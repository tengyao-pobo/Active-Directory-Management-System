using Npgsql;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task DeliveryGeneratedHistoryAuditMatchesSources()
    {
        var wrapper = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-history.sql"))).Replace("\r\n", "\n", StringComparison.Ordinal);
        var rows = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-history-rows.sql"));
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        var matches = Regex.Matches(profile, @"CREATE OR REPLACE FUNCTION enrollment_execution\.audit_execution_privileges\(p_environment uuid\).*?AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
        Assert.Single(matches.Cast<Match>());
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Regex.Replace(matches[0].Groups["body"].Value, @"\s+", " ").Trim()))).ToLowerInvariant();
        Verify("    ", "history audit hash", "    expected_audit_hash constant text := '" + hash + "';");
        Verify("      ", "history row rules", "      valid := (\n" + rows[rows.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';') + "\n      );");
        void Verify(string indent, string name, string content)
        {
            var begin = indent + "-- BEGIN generated " + name;
            var end = indent + "-- END generated " + name;
            Assert.Equal(1, wrapper.Split(begin, StringSplitOptions.None).Length - 1);
            Assert.Equal(1, wrapper.Split(end, StringSplitOptions.None).Length - 1);
            Assert.Equal(begin + "\n" + content.Replace("\r\n", "\n", StringComparison.Ordinal) + "\n" + end,
                wrapper[wrapper.IndexOf(begin, StringComparison.Ordinal)..(wrapper.IndexOf(end, StringComparison.Ordinal) + end.Length)]);
        }
    }

    private static async Task VerifyHistoryVisibilityAsync(NpgsqlConnection owner, NpgsqlConnection admin, string ownerRole, List<string> createdRoles, CancellationToken cancellationToken)
    {
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-history.sql"), cancellationToken);
        async Task Execute(NpgsqlConnection connection, string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        async Task<string> Snapshot()
        {
            await using var command = new NpgsqlCommand("SELECT coalesce(jsonb_agg(to_jsonb(policy) ORDER BY policy.oid)::text,'[]') FROM pg_catalog.pg_policy policy", owner);
            return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        async Task VerifyClean(string expectedPolicies, string expectedRowSecurity = "on", bool allowReserved = false)
        {
            Assert.Equal(expectedPolicies, await Snapshot());
            await using var command = new NpgsqlCommand("""
                SELECT current_setting('row_security')=@row_security
                  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'
                    AND classid=1162235478 AND objid=1 AND objsubid=2 AND mode='ExclusiveLock')
                  AND (@allow_reserved OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polname LIKE 'enrollment_history_check_%'))
                  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' AND mode='AccessExclusiveLock'
                    AND relation IN(SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','enrollment_execution')))
                """, owner);
            command.Parameters.AddWithValue("row_security", expectedRowSecurity);
            command.Parameters.AddWithValue("allow_reserved", allowReserved);
            Assert.Equal(true, await command.ExecuteScalarAsync(cancellationToken));
        }
        await Execute(owner, "SET search_path=pg_catalog,pg_temp; SET row_security=on");
        var policies = await Snapshot();
        await Execute(owner, source); // Autocommit success must not leave policies or the xact lock.
        await VerifyClean(policies);
        await Execute(admin, """
            BEGIN;
            SET LOCAL session_replication_role=replica;
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
              VALUES(gen_random_uuid(),'StoredDataInvalid',clock_timestamp());
            COMMIT;
            """);
        await using (var hidden = new NpgsqlCommand("SELECT count(*) FROM enrollment_execution.execution_stops", owner))
            Assert.Equal(0L, await hidden.ExecuteScalarAsync(cancellationToken));
        var invalidHistory = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("23514", invalidHistory.SqlState);
        Assert.Equal("Enrollment delivery history is inconsistent.", invalidHistory.MessageText);
        await VerifyClean(policies); // Failure after policy creation rolls back the full DO.
        await Execute(admin, "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM enrollment_execution.execution_stops; COMMIT;");
        await Execute(owner, source);
        await VerifyClean(policies);
        await Execute(owner, "CREATE POLICY history_public_hidden ON enrollment_execution.execution_stops AS RESTRICTIVE FOR SELECT TO PUBLIC USING(false)");
        var restrictedPolicies = await Snapshot();
        var restriction = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", restriction.SqlState);
        await VerifyClean(restrictedPolicies);
        await Execute(owner, "DROP POLICY history_public_hidden ON enrollment_execution.execution_stops");
        await Execute(owner, "CREATE POLICY history_public_permissive ON enrollment_execution.execution_stops AS PERMISSIVE FOR SELECT TO PUBLIC USING(true)");
        var permissivePolicies = await Snapshot();
        var permissive = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", permissive.SqlState);
        await VerifyClean(permissivePolicies);
        await Execute(owner, "DROP POLICY history_public_permissive ON enrollment_execution.execution_stops");
        await Execute(owner, "CREATE POLICY enrollment_history_check_execution_stops ON enrollment_execution.execution_stops FOR SELECT USING(false)");
        var occupiedPolicies = await Snapshot();
        var occupied = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", occupied.SqlState);
        await VerifyClean(occupiedPolicies, allowReserved: true);
        await Execute(owner, "DROP POLICY enrollment_history_check_execution_stops ON enrollment_execution.execution_stops");
        var inheritedRole = "cdh_policy_" + Guid.NewGuid().ToString("N")[..12];
        await Execute(admin, $"CREATE ROLE {inheritedRole} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION");
        createdRoles.Add(inheritedRole);
        await Execute(owner, $"CREATE POLICY history_inherited_hidden ON enrollment_execution.execution_stops AS RESTRICTIVE FOR SELECT TO {inheritedRole} USING(false)");
        var inheritedPolicies = await Snapshot();
        await Execute(admin, $"GRANT {inheritedRole} TO {ownerRole} WITH INHERIT FALSE, SET FALSE");
        await VerifyUsage(false);
        await Execute(owner, source);
        await VerifyClean(inheritedPolicies);
        await Execute(admin, $"GRANT {inheritedRole} TO {ownerRole} WITH INHERIT TRUE, SET FALSE");
        await VerifyUsage(true);
        var inherited = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", inherited.SqlState);
        await VerifyClean(inheritedPolicies);
        await Execute(owner, "DROP POLICY history_inherited_hidden ON enrollment_execution.execution_stops");
        await Execute(owner, $"CREATE POLICY history_inherited_permissive ON enrollment_execution.execution_stops AS PERMISSIVE FOR SELECT TO {inheritedRole} USING(true)");
        var inheritedPermissivePolicies = await Snapshot();
        var inheritedPermissive = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", inheritedPermissive.SqlState);
        await VerifyClean(inheritedPermissivePolicies);
        await Execute(admin, $"GRANT {inheritedRole} TO {ownerRole} WITH INHERIT FALSE, SET FALSE");
        await VerifyUsage(false);
        await Execute(owner, source);
        await VerifyClean(inheritedPermissivePolicies);
        await Execute(owner, "DROP POLICY history_inherited_permissive ON enrollment_execution.execution_stops");
        await Execute(admin, $"REVOKE {inheritedRole} FROM {ownerRole}");
        var wrongOwner = await Assert.ThrowsAsync<PostgresException>(() => Execute(admin, source));
        Assert.Equal("55000", wrongOwner.SqlState);
        await VerifyClean(policies);
        await Execute(admin, "CREATE TEMP TABLE history_execution_bindings AS SELECT * FROM public.\"DirectoryDatabaseBindings\" WHERE \"Purpose\"='EnrollmentGrantExecution'; BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM public.\"DirectoryDatabaseBindings\" WHERE \"Purpose\"='EnrollmentGrantExecution'; COMMIT;");
        var emptyBindings = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", emptyBindings.SqlState);
        Assert.Equal("History audit execution bindings are empty.", emptyBindings.MessageText);
        await VerifyClean(policies);
        await Execute(admin, "BEGIN; SET LOCAL session_replication_role=replica; INSERT INTO public.\"DirectoryDatabaseBindings\" SELECT * FROM history_execution_bindings; COMMIT; DROP TABLE history_execution_bindings;");
        async Task VerifyUsage(bool expected)
        {
            await using var command = new NpgsqlCommand("SELECT pg_catalog.pg_has_role(current_user,@role::name,'USAGE')", owner);
            command.Parameters.AddWithValue("role", inheritedRole);
            Assert.Equal(expected, await command.ExecuteScalarAsync(cancellationToken));
        }
        await Execute(owner, "ALTER TABLE enrollment_execution.execution_stops NO FORCE ROW LEVEL SECURITY");
        var forceDrift = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", forceDrift.SqlState);
        await VerifyClean(policies);
        await Execute(owner, "ALTER TABLE enrollment_execution.execution_stops FORCE ROW LEVEL SECURITY; SET row_security=off");
        var settingDrift = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
        Assert.Equal("55000", settingDrift.SqlState);
        await VerifyClean(policies, "off");
        await Execute(owner, "SET row_security=on");
        await using (var canonicalPolicyTransaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, "ALTER POLICY environment_enrollment_grant_operations ON public.\"EnrollmentGrantOperations\" USING(true) WITH CHECK(true)");
            var canonicalPolicy = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
            Assert.Equal("55000", canonicalPolicy.SqlState);
            Assert.Equal("History audit applicable policies are invalid.", canonicalPolicy.MessageText);
            await canonicalPolicyTransaction.RollbackAsync(cancellationToken);
        }
        await VerifyClean(policies);
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await Execute(owner, """
                CREATE OR REPLACE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid)
                RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
                LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on
                AS $stub$ BEGIN RETURN QUERY SELECT true,'None'::text,4::smallint; END $stub$;
                """);
            var stub = await Assert.ThrowsAsync<PostgresException>(() => Execute(owner, source));
            Assert.Equal("55000", stub.SqlState);
            Assert.Equal("History audit function contract is invalid.", stub.MessageText);
            await transaction.RollbackAsync(cancellationToken);
        }
        await VerifyClean(policies);
        await Execute(owner, source);
        await VerifyClean(policies);
    }
}
