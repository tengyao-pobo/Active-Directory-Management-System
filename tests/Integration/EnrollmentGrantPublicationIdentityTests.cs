using Npgsql;
using System.Security.Cryptography;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyPublicationRejectsUnboundLoginAsync(NpgsqlConnection owner, NpgsqlConnection admin,
        string connectionString, Guid environment, CancellationToken cancellationToken)
    {
        var name = "cdp_unbound_" + Guid.NewGuid().ToString("N")[..12];
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        using var quote = new NpgsqlCommandBuilder();
        var role = quote.QuoteIdentifier(name);
        var database = quote.QuoteIdentifier(admin.Database);
        var created = false;
        // A physical owner has implicit INSERT/helper rights, but is not the API.
        // A valid profile must not create an owner bypass in the publication guard.
        await using (var baseline = new NpgsqlCommand("SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)", owner))
        {
            baseline.Parameters.AddWithValue("environment", environment);
            Assert.Equal(true, await baseline.ExecuteScalarAsync(cancellationToken));
        }
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await using var insert = new NpgsqlCommand("INSERT INTO public.\"EnrollmentGrantOperations\"(\"EnvironmentId\") VALUES(@environment)", owner);
            insert.Parameters.AddWithValue("environment", environment);
            var denied = await Assert.ThrowsAsync<PostgresException>(async () => { await insert.ExecuteNonQueryAsync(cancellationToken); });
            Assert.Equal("55000", denied.SqlState);
            Assert.Equal("Enrollment grant publication is unavailable.", denied.MessageText);
            await transaction.RollbackAsync(cancellationToken);
        }
        try
        {
            await using (var create = new NpgsqlCommand($"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 1 PASSWORD '{password}'", admin))
                await create.ExecuteNonQueryAsync(cancellationToken);
            created = true;
            await using (var grants = new NpgsqlCommand($"GRANT CONNECT ON DATABASE {database} TO {role}; GRANT USAGE ON SCHEMA public TO {role}; GRANT INSERT ON public.\"EnrollmentGrantOperations\" TO {role}; GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) TO {role}", admin))
                await grants.ExecuteNonQueryAsync(cancellationToken);
            await using (var baseline = new NpgsqlCommand("SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)", owner))
            {
                baseline.Parameters.AddWithValue("environment", environment);
                Assert.Equal(false, await baseline.ExecuteScalarAsync(cancellationToken));
            }
            var info = new NpgsqlConnectionStringBuilder(connectionString) { Username = name, Password = password, Pooling = false };
            await using var unbound = new NpgsqlConnection(info.ConnectionString);
            await unbound.OpenAsync(cancellationToken);
            await using (var privilege = new NpgsqlCommand("SELECT CURRENT_USER=SESSION_USER AND pg_catalog.has_table_privilege('public.\"EnrollmentGrantOperations\"','INSERT')", unbound))
                Assert.Equal(true, await privilege.ExecuteScalarAsync(cancellationToken));
            await using var transaction = await unbound.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
            await using var insert = new NpgsqlCommand("INSERT INTO public.\"EnrollmentGrantOperations\"(\"EnvironmentId\") VALUES(@environment)", unbound) { CommandTimeout = 3 };
            insert.Parameters.AddWithValue("environment", environment);
            var failure = await Assert.ThrowsAsync<PostgresException>(async () => { await insert.ExecuteNonQueryAsync(cancellationToken); });
            Assert.True(failure.SqlState == "55000", $"{failure.SqlState}: {failure.MessageText}");
            Assert.Equal("Enrollment grant publication is unavailable.", failure.MessageText);
            await transaction.RollbackAsync(cancellationToken);
        }
        finally
        {
            if (created)
            {
                await using var cleanup = new NpgsqlCommand($"REVOKE EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) FROM {role}; REVOKE INSERT ON public.\"EnrollmentGrantOperations\" FROM {role}; REVOKE USAGE ON SCHEMA public FROM {role}; REVOKE CONNECT ON DATABASE {database} FROM {role}; DROP ROLE {role}", admin) { CommandTimeout = 10 };
                await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
                await using var verify = new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=@role)", admin);
                verify.Parameters.AddWithValue("role", name);
                Assert.Equal(false, await verify.ExecuteScalarAsync(CancellationToken.None));
            }
        }
    }
}
