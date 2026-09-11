using ItManagement.AgentProjection;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class DeviceInventoryApi
{
    public static void MapDeviceInventory(this WebApplication app)
    {
        app.MapGet("/api/v1/environments/{environmentId:guid}/devices/{id:guid}/inventory", async (
            Guid environmentId, Guid id, HttpContext http, ConsoleDbContext db,
            IAgentInventoryProjectionReader reader, TimeProvider time, CancellationToken ct) =>
        {
            var actor = AuthEndpoints.Actor(http);
            await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
            if (!await db.Memberships.AnyAsync(x => x.EnvironmentId == environmentId && x.PrincipalId == actor && x.Active, ct)) return Results.NotFound();
            var directory = await db.DirectorySync.SingleOrDefaultAsync(x => x.EnvironmentId == environmentId, ct);
            var now = time.GetUtcNow();
            if (directory?.Status != "Ready" || directory.CompletedAt is null || directory.CompletedAt < now.AddMinutes(-15)) return Unavailable();
            foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.ComputerInventory })
            {
                var scoped = await DirectoryApi.Scoped(db, environmentId, actor, permission, directory.Generation, ct);
                if (!await scoped.AnyAsync(x => x.Id == id && x.Kind == "Computer", ct)) return Results.NotFound();
            }
            var projection = await reader.ReadInventoryAsync(environmentId, id, ct);
            now = time.GetUtcNow();
            if (projection.EnvironmentId != environmentId || projection.DirectoryObjectId != id) return Unavailable();
            if (projection.State == ProjectionReadState.Missing)
                return Results.Ok(new { queriedAt = now, collectedAt = (DateTimeOffset?)null, receivedAt = (DateTimeOffset?)null, lastSeenAt = (DateTimeOffset?)null,
                    basic = Basic(BasicDeviceProjection.Missing(), now, false), hardware = Hardware(HardwareProjection.Missing(), now, false),
                    software = Software(InstalledSoftwareProjection.Missing(), now, false) });
            if (projection.State != ProjectionReadState.Observed || projection.CollectedAt is null || projection.ReceivedAt is null ||
                Future(projection.CollectedAt.Value, now) || Future(projection.ReceivedAt.Value, now)) return Unavailable();
            var stale = Old(projection.CollectedAt.Value, now) || Old(projection.ReceivedAt.Value, now);
            return Results.Ok(new { queriedAt = now, projection.CollectedAt, projection.ReceivedAt, projection.LastSeenAt,
                basic = Basic(projection.BasicDevice, now, stale), hardware = Hardware(projection.Hardware, now, stale),
                software = Software(projection.InstalledSoftware, now, stale) });
        });
    }

    private static bool Future(DateTimeOffset value, DateTimeOffset now) => value > now + DeviceBitLockerApi.MaximumFutureSkew;
    private static bool Old(DateTimeOffset value, DateTimeOffset now) => value < now - DeviceBitLockerApi.MaximumObservationAge;
    private sealed record SourceMetadata(string Availability, string? Freshness, DateTimeOffset? SourceObservedAt, bool IsTruncated);
    private static SourceMetadata Describe(ProjectionAvailability availability, DateTimeOffset? observed, bool truncated, DateTimeOffset now, bool stale)
    {
        if (availability == ProjectionAvailability.Missing) return new("Missing", null, null, false);
        if (availability is not (ProjectionAvailability.Observed or ProjectionAvailability.NotApplicable) || observed is null || Future(observed.Value, now))
            return new("Unavailable", null, null, false);
        return new(availability.ToString(), stale || Old(observed.Value, now) ? "Stale" : "Current", observed, truncated);
    }
    private static SourceMetadata Invalid() => new("Unavailable", null, null, false);
    private static object Basic(BasicDeviceProjection value, DateTimeOffset now, bool stale)
    {
        var meta = Describe(value.Availability, value.SourceObservedAt, value.IsTruncated, now, stale);
        if (meta.Availability == "NotApplicable" || meta.Availability == "Observed" && (value.OperatingSystem is null || value.HostName is null)) meta = Invalid();
        return new { meta.Availability, meta.Freshness, meta.SourceObservedAt, meta.IsTruncated,
            data = meta.Availability != "Observed" ? null : new { value.HostName,
                operatingSystem = new { value.OperatingSystem!.Description, value.OperatingSystem.Version, value.OperatingSystem.Architecture },
                networkInterfaces = value.NetworkInterfaces.Select(item => new { item.Name, item.InterfaceType, item.Addresses, item.Gateways, item.DnsServers, item.MacAddress }) } };
    }
    private static object Software(InstalledSoftwareProjection value, DateTimeOffset now, bool stale)
    {
        var meta = Describe(value.Availability, value.SourceObservedAt, value.IsTruncated, now, stale);
        if (meta.Availability == "NotApplicable") meta = Invalid();
        return new { meta.Availability, meta.Freshness, meta.SourceObservedAt, meta.IsTruncated,
            applications = meta.Availability != "Observed" ? [] : value.Applications.Select(item => new { item.Name, item.Version, item.Publisher, item.InstallDate, item.Architecture }).ToArray() };
    }
    private static object Hardware(HardwareProjection value, DateTimeOffset now, bool stale)
    {
        var meta = Describe(value.Availability, value.SourceObservedAt, value.IsTruncated, now, stale);
        if (meta.Availability == "NotApplicable" || value.Sections.GroupBy(x => x.Kind).Any(group => group.Count() > 1)) meta = Invalid();
        return new { meta.Availability, meta.Freshness, meta.SourceObservedAt, meta.IsTruncated,
            sections = meta.Availability != "Observed" ? [] : value.Sections.Select(section => Section(section, now, meta.Freshness == "Stale")).ToArray() };
    }
    private static object Section(HardwareProjectionSection value, DateTimeOffset now, bool stale)
    {
        var meta = Describe(value.Availability, value.SourceObservedAt, value.IsTruncated, now, stale);
        if (!Enum.IsDefined(value.Kind) || meta.Availability == "NotApplicable" && value.Kind is not (ProjectedHardwareKind.Video or ProjectedHardwareKind.Battery)) meta = Invalid();
        var rows = new List<Dictionary<string, string?>>();
        if (meta.Availability == "Observed") foreach (var row in value.Rows)
        {
            var projected = Row(value.Kind, row);
            if (projected is null) { meta = Invalid(); rows.Clear(); break; }
            rows.Add(projected);
        }
        return new { kind = Enum.IsDefined(value.Kind) ? value.Kind.ToString() : "Unknown", meta.Availability, meta.Freshness, meta.SourceObservedAt, meta.IsTruncated, rows };
    }
    private static Dictionary<string, string?>? Row(ProjectedHardwareKind kind, ProjectedHardwareRow row) => (kind, row) switch
    {
        (ProjectedHardwareKind.System, ProjectedSystemHardwareRow x) => new() { ["Manufacturer"] = x.Manufacturer, ["Model"] = x.Model, ["TotalPhysicalMemory"] = x.TotalPhysicalMemory },
        (ProjectedHardwareKind.Product, ProjectedProductHardwareRow x) => new() { ["UUID"] = x.UUID },
        (ProjectedHardwareKind.Bios, ProjectedBiosHardwareRow x) => new() { ["Manufacturer"] = x.Manufacturer, ["SerialNumber"] = x.SerialNumber, ["SMBIOSBIOSVersion"] = x.SMBIOSBIOSVersion, ["ReleaseDate"] = x.ReleaseDate },
        (ProjectedHardwareKind.OperatingSystem, ProjectedOperatingSystemHardwareRow x) => new() { ["Caption"] = x.Caption, ["Version"] = x.Version, ["BuildNumber"] = x.BuildNumber, ["InstallDate"] = x.InstallDate, ["LastBootUpTime"] = x.LastBootUpTime },
        (ProjectedHardwareKind.Processor, ProjectedProcessorHardwareRow x) => new() { ["Name"] = x.Name, ["Manufacturer"] = x.Manufacturer, ["NumberOfCores"] = x.NumberOfCores, ["NumberOfLogicalProcessors"] = x.NumberOfLogicalProcessors },
        (ProjectedHardwareKind.Memory, ProjectedMemoryHardwareRow x) => new() { ["BankLabel"] = x.BankLabel, ["DeviceLocator"] = x.DeviceLocator, ["Capacity"] = x.Capacity, ["Speed"] = x.Speed },
        (ProjectedHardwareKind.Video, ProjectedVideoHardwareRow x) => new() { ["Name"] = x.Name, ["AdapterRAM"] = x.AdapterRAM },
        (ProjectedHardwareKind.Disk, ProjectedDiskHardwareRow x) => new() { ["Model"] = x.Model, ["SerialNumber"] = x.SerialNumber, ["Size"] = x.Size, ["MediaType"] = x.MediaType },
        (ProjectedHardwareKind.Battery, ProjectedBatteryHardwareRow x) => new() { ["Name"] = x.Name, ["EstimatedChargeRemaining"] = x.EstimatedChargeRemaining, ["DesignCapacity"] = x.DesignCapacity, ["FullChargeCapacity"] = x.FullChargeCapacity },
        _ => null
    };
    private static IResult Unavailable() => Results.Problem(statusCode: 503, title: "InventoryUnavailable");
}
