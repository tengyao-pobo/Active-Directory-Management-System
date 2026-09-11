using ItManagement.Core;
using ItManagement.DirectoryConnector;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.ConnectorHost;

public sealed class DirectorySynchronizer(ConsoleDbContext db, TimeProvider time)
{
    public async Task<bool> RunAsync(Guid environment, Guid principal, IDirectoryReader reader, CancellationToken ct)
    {
        if (environment == Guid.Empty || principal == Guid.Empty) throw new ArgumentException("Connector identity required.");
        var attemptedAt = time.GetUtcNow();
        try
        {
            // Validate identity before network access, then release the transaction for LDAP I/O.
            await using (var check = await db.BeginEnvironment(environment, principal, ct))
            {
                if (!await db.Database.SqlQuery<bool>($"SELECT public.directory_database_access({environment},{principal}) AS \"Value\"").SingleAsync(ct))
                    throw new InvalidOperationException("ConnectorMembershipRequired");
            }
            var snapshot = await reader.ReadSnapshotAsync(ct);
            var now = time.GetUtcNow();
            if (snapshot.CapturedAt > now.AddSeconds(5) || snapshot.CapturedAt < now.AddMinutes(-10)) throw new InvalidOperationException("SnapshotTimeInvalid");
            var generation = Guid.NewGuid();
            var rows = Project(environment, generation, snapshot);
            await using var tx = await db.BeginEnvironment(environment, principal, ct);
            // Transaction-owned lock is released on commit, failure or connection loss.
            var locked = await db.Database.SqlQuery<bool>($"SELECT pg_try_advisory_xact_lock(hashtextextended({environment.ToString()}, 4)) AS \"Value\"").SingleAsync(ct);
            if (!locked) throw new InvalidOperationException("SyncAlreadyRunning");
            if (!await db.Database.SqlQuery<bool>($"SELECT public.directory_database_access({environment},{principal}) AS \"Value\"").SingleAsync(ct))
                throw new InvalidOperationException("ConnectorMembershipRequired");
            var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environment, ct);
            if (state?.AttemptedAt > attemptedAt) return false;
            // Readers observe the previous generation until this complete replacement commits.
            await db.DirectoryObjects.Where(x => x.EnvironmentId == environment).ExecuteDeleteAsync(ct);
            db.DirectoryObjects.AddRange(rows);
            if (state is null) { state = new DirectorySyncState { EnvironmentId = environment, Id = environment }; db.DirectorySync.Add(state); }
            state.Generation = generation; state.Status = "Ready"; state.CompletedAt = snapshot.CapturedAt;
            state.AttemptedAt = attemptedAt; state.ErrorCode = null; state.SourceServer = snapshot.SourceServer; state.NamingContext = snapshot.NamingContext;
            db.Audit.Add(new AuditRecord { EnvironmentId = environment, Id = Guid.NewGuid(), ActorId = principal,
                Action = "Directory.Sync", Result = "Success", OccurredAt = now, CorrelationId = generation.ToString(), SourceIp = "connector-host" });
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return true;
        }
        catch (Exception error) when (error is DirectoryReadException or InvalidOperationException or ArgumentException or FormatException or OperationCanceledException)
        {
            // Preserve the projection but invalidate its availability; never log raw LDAP errors.
            db.ChangeTracker.Clear();
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            ct = cleanup.Token;
            await using var tx = await db.BeginEnvironment(environment, principal, ct);
            // A competing run owns status; do not overwrite it with our lock contention.
            if (error is InvalidOperationException { Message: "SyncAlreadyRunning" }) return false;
            var locked = await db.Database.SqlQuery<bool>($"SELECT pg_try_advisory_xact_lock(hashtextextended({environment.ToString()}, 4)) AS \"Value\"").SingleAsync(ct);
            if (!locked) return false;
            if (!await db.Database.SqlQuery<bool>($"SELECT public.directory_database_access({environment},{principal}) AS \"Value\"").SingleAsync(ct)) return false;
            var state = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environment, ct);
            if (state?.AttemptedAt > attemptedAt) return false;
            if (state is null) { state = new DirectorySyncState { EnvironmentId = environment, Id = environment }; db.DirectorySync.Add(state); }
            state.Status = "Failed"; state.AttemptedAt = attemptedAt; state.ErrorCode = error is DirectoryReadException read ? read.Code.ToString() : error is OperationCanceledException ? "Cancelled" : "SnapshotRejected";
            db.Audit.Add(new AuditRecord { EnvironmentId = environment, Id = Guid.NewGuid(), ActorId = principal,
                Action = "Directory.Sync", Result = "Failed", OccurredAt = state.AttemptedAt, CorrelationId = Guid.NewGuid().ToString(), SourceIp = "connector-host" });
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return false;
        }
    }

    public static IReadOnlyList<DirectoryObjectRecord> Project(Guid environment, Guid generation, DirectorySnapshot snapshot)
    {
        if (snapshot.Entries.Count > 100000) throw new InvalidOperationException("SnapshotLimit");
        var ids = new HashSet<Guid>();
        var entries = new Dictionary<string, DirectoryEntrySnapshot>(StringComparer.Ordinal);
        foreach (var item in snapshot.Entries)
        {
            if (item.ObjectId == Guid.Empty || !ids.Add(item.ObjectId) || !Enum.IsDefined(item.Kind) || item.UsnChanged < 0 ||
                item.Name.Length is < 1 or > 256 || item.SamAccountName?.Length > 256 || item.Department?.Length > 256 || item.ObjectSid?.Length > 256 ||
                !DistinguishedName.IsDescendantOf(item.DistinguishedName, snapshot.NamingContext, true) ||
                !entries.TryAdd(DistinguishedName.GetComparisonKey(item.DistinguishedName), item)) throw new InvalidOperationException("SnapshotInvalid");
        }
        var result = new List<DirectoryObjectRecord>(entries.Count);
        foreach (var item in entries.Values)
        {
            var ancestry = new List<Guid>();
            var parent = DistinguishedName.GetParent(item.DistinguishedName);
            Guid? immediateOu = null;
            var seen = new HashSet<string>();
            for (var depth = 0; parent is not null && !DistinguishedName.AreEqual(parent, snapshot.NamingContext); depth++)
            {
                var key = DistinguishedName.GetComparisonKey(parent);
                if (depth > 128 || !seen.Add(key)) throw new InvalidOperationException("InvalidDirectoryHierarchy");
                if (entries.TryGetValue(key, out var ancestor) && ancestor.Kind == DirectoryObjectKind.OrganizationalUnit)
                {
                    if (depth == 0) immediateOu = ancestor.ObjectId;
                    ancestry.Add(ancestor.ObjectId);
                }
                else if (parent.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("MissingOrganizationalUnit");
                // Unprojected CN containers grant no OU scope by themselves.
                parent = DistinguishedName.GetParent(parent);
            }
            result.Add(new DirectoryObjectRecord { EnvironmentId = environment, Id = item.ObjectId, Generation = generation,
                Kind = item.Kind.ToString(), DistinguishedName = item.DistinguishedName, Name = item.Name, SamAccountName = item.SamAccountName,
                Department = item.Department, ObjectSid = item.ObjectSid, UsnChanged = item.UsnChanged, IsProtected = item.IsProtected,
                ProtectionKnown = item.ProtectionKnown, ParentOuId = immediateOu, OuAncestry = ancestry.ToArray() });
        }
        return result;
    }
}
