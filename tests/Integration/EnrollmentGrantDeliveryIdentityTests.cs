using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task DeliveryIdentityOwnerPolicyWorksWithoutSuperuserOrBypassRls()
    {
        var seed = await _fixture.SeedAsync();
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var suffix = Guid.NewGuid().ToString("N");
        var owner = "identity_owner_" + suffix;
        var plan = "identity_plan_" + suffix;
        var execution = "identity_exec_" + suffix;
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        await Execute($"""
            CREATE ROLE "{owner}" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
            CREATE ROLE "{plan}" NOLOGIN NOINHERIT;
            CREATE ROLE "{execution}" NOLOGIN NOINHERIT;
            GRANT USAGE ON SCHEMA public TO "{owner}";
            GRANT SELECT ON public."DirectoryDatabaseBindings" TO "{owner}";
            ALTER TABLE public."Principals" OWNER TO "{owner}";
            ALTER TABLE public."Sessions" OWNER TO "{owner}";
            """);
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"));
        await Execute(source.Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal)
            .Replace(":\"enrollment_plan_lock_owner_role\"", QuoteIdentifier(plan), StringComparison.Ordinal)
            .Replace(":\"execution_definer_role\"", QuoteIdentifier(execution), StringComparison.Ordinal));
        await Execute($"SET LOCAL SESSION AUTHORIZATION {QuoteIdentifier(owner)}");
        await using (var flags = new NpgsqlCommand("SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER", connection, transaction))
            Assert.Equal(false, await flags.ExecuteScalarAsync());
        await using (var maintenance = new NpgsqlCommand($"""
            WITH changed AS (UPDATE public."Principals" SET "Enabled"=false
              WHERE "Id"='{seed.Requester.Id}' RETURNING 1) SELECT count(*) FROM changed
            """, connection, transaction))
            Assert.Equal(1L, await maintenance.ExecuteScalarAsync());
        await using (var sessions = new NpgsqlCommand($"""
            WITH changed AS (UPDATE public."Sessions" SET "RevokedAt"=now()
              WHERE "PrincipalId"='{seed.Requester.Id}' RETURNING 1) SELECT count(*) FROM changed
            """, connection, transaction))
            Assert.Equal(1L, await sessions.ExecuteScalarAsync());
        await transaction.RollbackAsync();
    }

    [Theory]
    [InlineData("unbound")]
    [InlineData("connector")]
    [InlineData("execution")]
    [InlineData("contract")]
    [InlineData("environment")]
    [InlineData("principal")]
    public async Task DeliveryIdentityAttestorRejectsNonApiBindingShape(string fault)
    {
        var seed = await _fixture.SeedAsync();
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var owner = new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username!;
        var api = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Username!;
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"));
        var end = source.IndexOf("CREATE POLICY enrollment_identity_principals_owner", StringComparison.Ordinal);
        Assert.True(end > 0);
        await using (var setup = new NpgsqlCommand(source[..end]
            .Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal), connection, transaction))
            await setup.ExecuteNonQueryAsync();
        // Deliberately remove the shape check only in this rollback fixture, proving that
        // the helper itself never treats a malformed API binding as authorization.
        var change = fault switch
        {
            "unbound" => "DELETE FROM public.\"DirectoryDatabaseBindings\" WHERE \"LoginRole\"=@api",
            "connector" => "UPDATE public.\"DirectoryDatabaseBindings\" SET \"Purpose\"='Connector' WHERE \"LoginRole\"=@api",
            "execution" => "UPDATE public.\"DirectoryDatabaseBindings\" SET \"Purpose\"='EnrollmentGrantExecution' WHERE \"LoginRole\"=@api",
            "contract" => "UPDATE public.\"DirectoryDatabaseBindings\" SET \"ContractVersion\"=2 WHERE \"LoginRole\"=@api",
            "environment" => "UPDATE public.\"DirectoryDatabaseBindings\" SET \"EnvironmentId\"=@environment WHERE \"LoginRole\"=@api",
            "principal" => "UPDATE public.\"DirectoryDatabaseBindings\" SET \"PrincipalId\"=@principal WHERE \"LoginRole\"=@api",
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };
        await using (var command = new NpgsqlCommand("ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT directory_database_binding_shape;" + change, connection, transaction))
        {
            command.Parameters.AddWithValue("api", api);
            command.Parameters.AddWithValue("environment", seed.Environment.Id);
            command.Parameters.AddWithValue("principal", seed.Requester.Id);
            await command.ExecuteNonQueryAsync();
        }
        await using (var identity = new NpgsqlCommand($"SET LOCAL SESSION AUTHORIZATION {QuoteIdentifier(api)}", connection, transaction))
            await identity.ExecuteNonQueryAsync();
        await using var query = new NpgsqlCommand("SELECT public.api_database_session()", connection, transaction);
        Assert.Equal(false, await query.ExecuteScalarAsync());
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task DeliveryIdentityRlsPreservesApiSessionsAndPlanLocksWithoutDefinerCrossover()
    {
        var operation = await QueuedJournalOperation();
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var owner = new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username!;
        var api = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Username!;
        var planLocker = _fixture.PlanLockOwner;
        var suffix = Guid.NewGuid().ToString("N");
        var executor = "identity_exec_" + suffix;
        var unrelated = "identity_other_" + suffix;
        var caller = "identity_caller_" + suffix;
        var probe = "identity_probe_" + suffix;
        async Task<object?> Scalar(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            return await command.ExecuteScalarAsync();
        }
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        async Task Denied(string sql)
        {
            await Execute("SAVEPOINT expected_denial");
            var error = await Assert.ThrowsAsync<PostgresException>(() => Scalar(sql));
            Assert.Equal("42501", error.SqlState);
            await Execute("ROLLBACK TO SAVEPOINT expected_denial");
        }
        await Execute($"""
            CREATE ROLE "{executor}" NOLOGIN NOINHERIT;
            CREATE ROLE "{unrelated}" NOLOGIN NOINHERIT;
            CREATE ROLE "{caller}" LOGIN NOINHERIT;
            GRANT USAGE ON SCHEMA public TO "{executor}","{unrelated}","{caller}";
            GRANT SELECT,UPDATE ON public."Principals" TO "{executor}","{unrelated}";
            GRANT SELECT ON public."Principals",public."Sessions" TO "{caller}";
            """);
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"));
        await Execute(source.Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal)
            .Replace(":\"enrollment_plan_lock_owner_role\"", QuoteIdentifier(planLocker), StringComparison.Ordinal)
            .Replace(":\"execution_definer_role\"", QuoteIdentifier(executor), StringComparison.Ordinal));
        await Execute($"""
            CREATE FUNCTION public."{probe}"() RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER
              SET search_path=pg_catalog,pg_temp SET row_security=on
              AS 'SELECT count(*) FROM (SELECT "Id" FROM public."Principals" FOR SHARE) locked';
            ALTER FUNCTION public."{probe}"() OWNER TO "{unrelated}";
            REVOKE ALL ON FUNCTION public."{probe}"() FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public."{probe}"() TO "{api}","{caller}";
            SET LOCAL SESSION AUTHORIZATION "{api}";
            """);
        Assert.Equal(true, await Scalar("SELECT public.api_database_session()"));
        Assert.Equal(false, await Scalar("SELECT has_table_privilege(CURRENT_USER,'public.\"Principals\"','UPDATE') OR has_any_column_privilege(CURRENT_USER,'public.\"Principals\"','UPDATE')"));
        Assert.Equal(1L, await Scalar($"SELECT count(*) FROM public.\"Principals\" WHERE \"Id\"='{operation.RequesterId}'"));
        // An API SESSION_USER does not expose global identity rows inside another definer.
        Assert.Equal(0L, await Scalar($"SELECT public.\"{probe}\"()"));
        await Denied($"UPDATE public.\"Principals\" SET \"Enabled\"=false WHERE \"Id\"='{operation.RequesterId}'");
        var session = suffix.ToUpperInvariant() + suffix.ToUpperInvariant();
        await Execute($"""
            INSERT INTO public."Sessions"("IdHash","PrincipalId","Method","CreatedAt","LastSeenAt","ExpiresAt","SourceIp","UserAgent")
            VALUES('{session}','{operation.RequesterId}','Synthetic',now(),now(),now()+interval '1 hour','127.0.0.1','test');
            UPDATE public."Sessions" SET "LastSeenAt"=now(),"StepUpAt"=now() WHERE "IdHash"='{session}';
            UPDATE public."Sessions" SET "RevokedAt"=now() WHERE "IdHash"='{session}';
            """);
        Assert.Equal(true, await Scalar($"SELECT \"StepUpAt\" IS NOT NULL AND \"RevokedAt\" IS NOT NULL FROM public.\"Sessions\" WHERE \"IdHash\"='{session}'"));
        Assert.Equal(1L, await Scalar($"WITH removed AS (DELETE FROM public.\"Sessions\" WHERE \"IdHash\"='{session}' RETURNING 1) SELECT count(*) FROM removed"));
        await Execute($"""
            SELECT set_config('app.environment_id','{operation.EnvironmentId}',true),
              set_config('app.principal_id','{operation.RequesterId}',true);
            SELECT public.lock_enrollment_grant_plan_context('{operation.EnvironmentId}','{operation.DirectoryObjectId}',ARRAY['{operation.RequesterId}'::uuid]);
            RESET SESSION AUTHORIZATION;
            ALTER FUNCTION public."{probe}"() OWNER TO {QuoteIdentifier(planLocker)};
            SET LOCAL SESSION AUTHORIZATION "{api}";
            """);
        Assert.True((long)(await Scalar($"SELECT public.\"{probe}\"()"))! > 0);
        // The lock owner's UPDATE USING permits row locks, but WITH CHECK false blocks changes.
        await Denied($"SET LOCAL ROLE {QuoteIdentifier(planLocker)}");
        await Execute($"""
            RESET SESSION AUTHORIZATION;
            CREATE FUNCTION public."{probe}"(p_id uuid) RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER
              SET search_path=pg_catalog,pg_temp SET row_security=on
              AS 'UPDATE public."Principals" SET "Enabled"=false WHERE "Id"=p_id';
            ALTER FUNCTION public."{probe}"(uuid) OWNER TO {QuoteIdentifier(planLocker)};
            REVOKE ALL ON FUNCTION public."{probe}"(uuid) FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public."{probe}"(uuid) TO "{api}";
            SET LOCAL SESSION AUTHORIZATION "{api}";
            """);
        await Denied($"SELECT public.\"{probe}\"('{operation.RequesterId}'::uuid)");
        Assert.Equal(true, await Scalar($"SELECT \"Enabled\" FROM public.\"Principals\" WHERE \"Id\"='{operation.RequesterId}'"));
        await Execute("RESET SESSION AUTHORIZATION");
        await Execute($"""
            ALTER FUNCTION public."{probe}"() OWNER TO "{executor}";
            SET LOCAL SESSION AUTHORIZATION "{caller}";
            SELECT set_config('app.execution_requester_id','{operation.RequesterId}',true),
              set_config('app.execution_approver_id','{operation.ApproverId}',true);
            """);
        Assert.Equal(false, await Scalar("SELECT public.api_database_session()"));
        Assert.Equal(0L, await Scalar("SELECT count(*) FROM public.\"Principals\""));
        Assert.Equal(0L, await Scalar("SELECT count(*) FROM public.\"Sessions\""));
        // This intentionally injected definer probe isolates row scoping, not caller
        // authorization. Full profile attestation must reject extra definer functions
        // and grants; real execution-wrapper compatibility remains an activation gate.
        Assert.Equal(2L, await Scalar($"SELECT public.\"{probe}\"()"));
        await Execute("SELECT set_config('app.execution_requester_id','',true),set_config('app.execution_approver_id','',true)");
        Assert.Equal(0L, await Scalar($"SELECT public.\"{probe}\"()"));
        await transaction.RollbackAsync();
    }
}
