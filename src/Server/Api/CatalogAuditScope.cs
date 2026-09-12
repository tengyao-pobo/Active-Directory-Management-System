using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.Api;

internal enum CatalogAuditPath { Legacy, Profile4 }

// A catalog query's deparsed expressions depend on search_path. Keep that setting
// local to the audit, including when an endpoint already owns a transaction.
internal static class CatalogAuditScope
{
    // The callback must use only the supplied context and catalog-only SQL.
    internal static async Task<bool> RunAsync(ConsoleDbContext db, CatalogAuditPath path,
        Func<ConsoleDbContext, CancellationToken, Task<bool>> audit, CancellationToken cancellationToken)
    {
        var searchPath = path switch { CatalogAuditPath.Legacy => "pg_catalog,public,pg_temp", CatalogAuditPath.Profile4 => "pg_catalog,pg_temp", _ => null };
        if (searchPath is null) return false;
        var transaction = db.Database.CurrentTransaction;
        if (transaction is not null && !transaction.SupportsSavepoints) return false;
        IDbContextTransaction? owned = null;
        var savepoint = "catalog_audit_" + Guid.NewGuid().ToString("N");
        var savepointAttempted = false;
        var valid = false;
        var restored = true;
        try
        {
            if (transaction is null)
            {
                owned = await db.Database.BeginTransactionAsync(cancellationToken);
                transaction = owned;
                await db.Database.ExecuteSqlRawAsync("SET TRANSACTION READ ONLY", cancellationToken);
            }
            else
            {
                savepointAttempted = true;
                await transaction.CreateSavepointAsync(savepoint, cancellationToken);
            }
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_catalog.set_config('search_path',{searchPath},true)", cancellationToken);
            valid = await audit(db, cancellationToken);
        }
        catch (Exception error) when (error is NpgsqlException or InvalidOperationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Catalog errors and malformed result cardinality are unavailable, not
            // permission to use a less strict contract or a cached positive result.
            valid = false;
        }
        finally
        {
            // Bound database rollback operations independently of the request.
            // Mandatory provider disposal follows and has no cancellation-token API.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                if (owned is not null)
                    await owned.RollbackAsync(cleanup.Token);
                else if (savepointAttempted && transaction is not null)
                {
                    await transaction.RollbackToSavepointAsync(savepoint, cleanup.Token);
                    await transaction.ReleaseSavepointAsync(savepoint, cleanup.Token);
                }
            }
            catch (Exception error) when (error is NpgsqlException or InvalidOperationException or OperationCanceledException)
            {
                restored = false;
            }
            finally
            {
                if (owned is not null)
                {
                    try { await owned.DisposeAsync(); }
                    catch (Exception error) when (error is NpgsqlException or InvalidOperationException) { restored = false; }
                }
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return restored && valid;
    }
}
