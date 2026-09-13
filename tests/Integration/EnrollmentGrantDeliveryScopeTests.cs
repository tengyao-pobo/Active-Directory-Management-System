using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("EnrollmentGrantStatusRefresh")]
    [InlineData("EnrollmentGrantDelivery")]
    public async Task DeliveryScopePreservesSessionIdentityAcrossDefinerHops(string purpose)
    {
        var seed = await _fixture.SeedAsync();
        await using var scope = await DeliveryScopeFixture.CreateAsync(seed.Environment.Id);
        await scope.AsRuntimeAsync(purpose);
        Assert.Equal(false, await scope.ScalarAsync(
            "SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER"));
        Assert.Equal(scope.Runtime(purpose), await scope.ScalarAsync("SELECT SESSION_USER::text"));
        Assert.True(await scope.CheckAsync(seed.Environment.Id, purpose));
        Assert.False(await scope.CheckAsync(Guid.NewGuid(), purpose));
        Assert.False(await scope.CheckAsync(Guid.Empty, purpose));
        Assert.False(await scope.CheckAsync(seed.Environment.Id,
            purpose == "EnrollmentGrantDelivery" ? "EnrollmentGrantStatusRefresh" : "EnrollmentGrantDelivery"));
        Assert.False(await scope.CheckAsync(seed.Environment.Id, "Api"));
        Assert.False(await scope.CheckAsync(null, purpose));
        Assert.False(await scope.CheckAsync(seed.Environment.Id, null));
    }

    [Theory]
    [InlineData("EnrollmentGrantStatusRefresh", "SELECT * FROM enrollment_execution.role_reservations")]
    [InlineData("EnrollmentGrantDelivery", "SELECT * FROM enrollment_execution.role_reservations")]
    [InlineData("EnrollmentGrantStatusRefresh", "SELECT * FROM public.\"DirectoryDatabaseBindings\"")]
    [InlineData("EnrollmentGrantDelivery", "SELECT * FROM public.\"DirectoryDatabaseBindings\"")]
    [InlineData("EnrollmentGrantStatusRefresh", "SELECT enrollment_execution.delivery_worker_scope(NULL::uuid,NULL::text)")]
    [InlineData("EnrollmentGrantDelivery", "SELECT enrollment_execution.delivery_worker_scope(NULL::uuid,NULL::text)")]
    public async Task DeliveryScopeDoesNotGiveRuntimeProtectedTableOrAttestorAccess(string purpose, string sql)
    {
        var seed = await _fixture.SeedAsync();
        await using var scope = await DeliveryScopeFixture.CreateAsync(seed.Environment.Id);
        await scope.AsRuntimeAsync(purpose);
        var error = await Assert.ThrowsAsync<PostgresException>(() => scope.ScalarAsync(sql));
        Assert.Equal("42501", error.SqlState);
    }

    [Theory]
    [InlineData("SELECT * FROM enrollment_execution.role_reservations")]
    [InlineData("SELECT * FROM public.\"DirectoryDatabaseBindings\"")]
    public async Task DeliveryDefinerCannotReadProtectedIdentityTables(string sql)
    {
        var seed = await _fixture.SeedAsync();
        await using var scope = await DeliveryScopeFixture.CreateAsync(seed.Environment.Id);
        await scope.AsDefinerAsync();
        Assert.Equal(false, await scope.ScalarAsync(
            "SELECT rolcanlogin OR rolsuper OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER"));
        var error = await Assert.ThrowsAsync<PostgresException>(() => scope.ScalarAsync(sql));
        Assert.Equal("42501", error.SqlState);
    }

    [Theory]
    [InlineData("runtime_inherit")]
    [InlineData("runtime_createdb")]
    [InlineData("runtime_membership_member")]
    [InlineData("runtime_membership_role")]
    [InlineData("definer_login")]
    [InlineData("definer_membership")]
    [InlineData("runtime_reservation_kind")]
    [InlineData("runtime_reservation_oid")]
    [InlineData("runtime_reservation_capability")]
    [InlineData("definer_reservation_oid")]
    public async Task DeliveryScopeRejectsIdentityAndReservationDrift(string drift)
    {
        var seed = await _fixture.SeedAsync();
        await using var scope = await DeliveryScopeFixture.CreateAsync(seed.Environment.Id);
        await scope.DriftAsync(drift);
        await scope.AsRuntimeAsync("EnrollmentGrantStatusRefresh");
        Assert.False(await scope.CheckAsync(seed.Environment.Id, "EnrollmentGrantStatusRefresh"));
    }

    private sealed class DeliveryScopeFixture(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string status, string delivery, string definer, string auxiliary) : IAsyncDisposable
    {
        public string Runtime(string purpose) => purpose == "EnrollmentGrantStatusRefresh" ? status : delivery;

        public static async Task<DeliveryScopeFixture> CreateAsync(Guid environment)
        {
            // A rollback-only harness for the exact source attestor, NOT a complete profile4 installer.
            // No runtime is given SET ROLE, table rights, or EXECUTE on the attestor itself.
            var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
            await connection.OpenAsync();
            var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
            var suffix = Guid.NewGuid().ToString("N");
            var scope = new DeliveryScopeFixture(connection, transaction, $"scope_status_{suffix}",
                $"scope_delivery_{suffix}", $"scope_definer_{suffix}", $"scope_aux_{suffix}");
            try
            {
                await scope.InstallAsync(environment);
                return scope;
            }
            catch
            {
                await scope.DisposeAsync();
                throw;
            }
        }

        private async Task InstallAsync(Guid environment)
        {
            await ExecuteAsync($"""
                CREATE ROLE "{status}" LOGIN NOINHERIT;
                CREATE ROLE "{delivery}" LOGIN NOINHERIT;
                CREATE ROLE "{definer}" NOLOGIN NOINHERIT;
                CREATE ROLE "{auxiliary}" NOLOGIN NOINHERIT;
                """);
            var owner = (string)(await ScalarAsync("SELECT CURRENT_USER::text"))!;
            var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"));
            var start = upgrade.IndexOf("ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT", StringComparison.Ordinal);
            var end = upgrade.IndexOf("DROP FUNCTION enrollment_execution.reject_worker_update()", StringComparison.Ordinal);
            Assert.True(start >= 0 && end > start);
            await ExecuteAsync(upgrade[start..end].Replace(":'delivery_definer_role'", $"'{definer}'", StringComparison.Ordinal));
            await ExecuteAsync($"""
                INSERT INTO enrollment_execution.role_reservations
                    (role_name,role_oid,capability,role_kind,reservation_schema_version)
                SELECT rolname,oid,'EnrollmentGrantDelivery',
                    CASE rolname WHEN '{status}' THEN 'StatusRuntime' ELSE 'DeliveryRuntime' END,1
                FROM pg_catalog.pg_roles WHERE rolname IN ('{status}','{delivery}');
                INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId")
                VALUES ('{status}','EnrollmentGrantStatusRefresh',1,'{environment}',NULL),
                       ('{delivery}','EnrollmentGrantDelivery',1,'{environment}',NULL);
                GRANT USAGE ON SCHEMA enrollment_execution TO "{status}","{delivery}","{definer}";
                """);
            var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"));
            var boundary = profile.IndexOf("CREATE FUNCTION enrollment_execution.read_grant_status_receipt", StringComparison.Ordinal);
            Assert.True(boundary > 0);
            await ExecuteAsync(profile[..boundary]
                .Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal)
                .Replace(":\"delivery_definer_role\"", QuoteIdentifier(definer), StringComparison.Ordinal));
            await ExecuteAsync($"""
                CREATE FUNCTION enrollment_execution.test_delivery_scope(p_environment uuid,p_purpose text)
                RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
                SET search_path=pg_catalog,pg_temp SET row_security=on
                AS 'SELECT enrollment_execution.delivery_worker_scope(p_environment,p_purpose)';
                REVOKE ALL ON FUNCTION enrollment_execution.test_delivery_scope(uuid,text) FROM PUBLIC;
                ALTER FUNCTION enrollment_execution.test_delivery_scope(uuid,text) OWNER TO "{definer}";
                GRANT EXECUTE ON FUNCTION enrollment_execution.test_delivery_scope(uuid,text) TO "{status}","{delivery}";
                """);
            Assert.Equal(true, await ScalarAsync("""
                SELECT function_row.proowner=CURRENT_USER::regrole::oid AND function_row.prosecdef
                  AND function_row.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                  AND role_table.relrowsecurity AND role_table.relforcerowsecurity
                FROM pg_catalog.pg_proc function_row CROSS JOIN pg_catalog.pg_class role_table
                WHERE function_row.oid='enrollment_execution.delivery_worker_scope(uuid,text)'::regprocedure
                  AND role_table.oid='enrollment_execution.role_reservations'::regclass
                """));
        }

        public Task AsRuntimeAsync(string purpose) => ExecuteAsync($"SET LOCAL SESSION AUTHORIZATION {QuoteIdentifier(Runtime(purpose))}");

        public async Task AsDefinerAsync()
        {
            await ExecuteAsync($"SET LOCAL SESSION AUTHORIZATION {QuoteIdentifier(definer)}");
            Assert.Equal(definer, await ScalarAsync("SELECT CURRENT_USER::text"));
            Assert.Equal(definer, await ScalarAsync("SELECT SESSION_USER::text"));
        }

        public async Task<bool> CheckAsync(Guid? environment, string? purpose)
        {
            await using var command = new NpgsqlCommand(
                "SELECT enrollment_execution.test_delivery_scope(@environment,@purpose)", connection, transaction);
            command.Parameters.Add("environment", NpgsqlTypes.NpgsqlDbType.Uuid).Value = (object?)environment ?? DBNull.Value;
            command.Parameters.Add("purpose", NpgsqlTypes.NpgsqlDbType.Text).Value = (object?)purpose ?? DBNull.Value;
            return (bool)(await command.ExecuteScalarAsync())!;
        }

        public async Task DriftAsync(string drift)
        {
            // Synthetic catalog mutation stays inside the rollback-only test transaction.
            await ExecuteAsync("ALTER TABLE enrollment_execution.role_reservations DISABLE TRIGGER enrollment_execution_role_reservations_immutable");
            await ExecuteAsync(drift switch
            {
                "runtime_inherit" => $"ALTER ROLE \"{status}\" INHERIT",
                "runtime_createdb" => $"ALTER ROLE \"{status}\" CREATEDB",
                "runtime_membership_member" => $"GRANT \"{auxiliary}\" TO \"{status}\"",
                "runtime_membership_role" => $"GRANT \"{status}\" TO \"{auxiliary}\"",
                "definer_login" => $"ALTER ROLE \"{definer}\" LOGIN",
                "definer_membership" => $"GRANT \"{auxiliary}\" TO \"{definer}\"",
                "runtime_reservation_kind" => $"UPDATE enrollment_execution.role_reservations SET role_kind='DeliveryRuntime' WHERE role_name='{status}'",
                "runtime_reservation_oid" => $"UPDATE enrollment_execution.role_reservations SET role_oid='{auxiliary}'::regrole::oid WHERE role_name='{status}'",
                "runtime_reservation_capability" => $"UPDATE enrollment_execution.role_reservations SET capability='EnrollmentGrantExecution',role_kind='Runtime' WHERE role_name='{status}'",
                "definer_reservation_oid" => $"UPDATE enrollment_execution.role_reservations SET role_oid='{auxiliary}'::regrole::oid WHERE role_name='{definer}'",
                _ => throw new ArgumentOutOfRangeException(nameof(drift))
            });
        }

        public async Task<object?> ScalarAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            return await command.ExecuteScalarAsync();
        }

        private async Task ExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }

        public async ValueTask DisposeAsync()
        {
            try { await transaction.DisposeAsync(); }
            finally { await connection.DisposeAsync(); }
        }
    }
}
