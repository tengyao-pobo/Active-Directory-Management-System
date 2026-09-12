using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyReadinessAuditSplitAsync(NpgsqlConnection owner, NpgsqlConnection runtime,
        string statusConnection, string deliveryConnection, Guid environment, CancellationToken cancellationToken)
    {
        async Task Execute(NpgsqlConnection connection, string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        async Task<string> Identity()
        {
            await using var command = new NpgsqlCommand("SELECT jsonb_build_object('oid',oid,'owner',proowner,'acl',proacl)::text FROM pg_catalog.pg_proc WHERE oid='enrollment_execution.audit_execution_privileges(uuid)'::regprocedure", owner);
            return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        async Task Audit(NpgsqlConnection connection, string function, bool expected)
        {
            await using var command = new NpgsqlCommand($"SELECT is_valid,diagnostic_code,profile_version FROM enrollment_execution.{function}(@environment)", connection);
            command.Parameters.AddWithValue("environment", environment);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.True(expected == reader.GetBoolean(0), function);
            Assert.Equal(expected ? "None" : "ProfileDrift", reader.GetString(1));
            Assert.Equal((short)4, reader.GetInt16(2));
            Assert.False(await reader.ReadAsync(cancellationToken));
        }
        await using var status = new NpgsqlConnection(statusConnection);
        await using var delivery = new NpgsqlConnection(deliveryConnection);
        await status.OpenAsync(cancellationToken);
        await delivery.OpenAsync(cancellationToken);
        var original = await Identity();
        await Execute(owner, await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-structure-audit.sql"), cancellationToken));
        await Execute(owner, await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-runtime-audit.sql"), cancellationToken));
        Assert.Equal(original, await Identity());
        await Audit(owner, "audit_execution_profile_structure", true);
        await Audit(owner, "audit_execution_privileges", false);
        await Audit(runtime, "audit_execution_privileges", false);
        await Audit(status, "audit_delivery_privileges", false);
        await Audit(delivery, "audit_delivery_privileges", false);
        // Enumerate effective privileges, including PUBLIC and memberships, rather than
        // proving only that a handpicked wrapper list rejects Pending.
        foreach (var (connection, expectedNames) in new[] {
            (runtime, new[] { "audit_execution_privileges", "read_execution_record", "read_and_lock_plan_context",
                "authorize_and_store_candidate", "record_execution_result", "quarantine_execution", "claim_next", "defer_claim", "complete_claim" }),
            (status, new[] { "audit_delivery_privileges", "read_grant_status_receipt", "append_grant_status_observation" }),
            (delivery, new[] { "audit_delivery_privileges", "read_grant_delivery", "acknowledge_grant_delivery" }) })
        {
            await using var surface = new NpgsqlCommand("""
                SELECT p.proname::text
                FROM pg_catalog.pg_proc p
                WHERE p.pronamespace='enrollment_execution'::regnamespace
                  AND pg_catalog.has_schema_privilege(p.pronamespace,'USAGE')
                  AND pg_catalog.has_function_privilege(p.oid,'EXECUTE')
                ORDER BY p.proname COLLATE "C",p.oid
                """, connection);
            var actualNames = new List<string>();
            await using var reader = await surface.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) actualNames.Add(reader.GetString(0));
            Assert.Equal(expectedNames.Order(StringComparer.Ordinal), actualNames);
            await reader.DisposeAsync();
            await using var directData = new NpgsqlCommand("""
                SELECT c.relname::text
                FROM pg_catalog.pg_class c
                WHERE c.relnamespace='enrollment_execution'::regnamespace AND c.relkind IN ('r','p','v','m','f')
                  AND (pg_catalog.has_table_privilege(c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    OR pg_catalog.has_any_column_privilege(c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
                ORDER BY c.relname COLLATE "C"
                """, connection);
            await using var dataReader = await directData.ExecuteReaderAsync(cancellationToken);
            var directlyAccessible = new List<string>();
            while (await dataReader.ReadAsync(cancellationToken)) directlyAccessible.Add(dataReader.GetString(0));
            Assert.Empty(directlyAccessible);
            await dataReader.DisposeAsync();
            await using var sequences = new NpgsqlCommand("""
                SELECT c.relname::text FROM pg_catalog.pg_class c
                WHERE CASE WHEN c.relnamespace='enrollment_execution'::regnamespace AND c.relkind='S'
                  THEN pg_catalog.has_sequence_privilege(c.oid,'USAGE,SELECT,UPDATE') ELSE false END
                ORDER BY c.relname COLLATE "C"
                """, connection);
            await using var sequenceReader = await sequences.ExecuteReaderAsync(cancellationToken);
            var accessibleSequences = new List<string>();
            while (await sequenceReader.ReadAsync(cancellationToken)) accessibleSequences.Add(sequenceReader.GetString(0));
            Assert.Empty(accessibleSequences);
        }
        var denied = await Assert.ThrowsAsync<PostgresException>(() => Audit(runtime, "audit_execution_profile_structure", true));
        Assert.Equal("42501", denied.SqlState);
        foreach (var (connection, name) in new[] {
            (runtime, "read_execution_record"), (runtime, "read_and_lock_plan_context"), (runtime, "authorize_and_store_candidate"),
            (runtime, "record_execution_result"), (runtime, "quarantine_execution"), (runtime, "claim_next"), (runtime, "defer_claim"), (runtime, "complete_claim"),
            (status, "read_grant_status_receipt"), (status, "append_grant_status_observation"),
            (delivery, "read_grant_delivery"), (delivery, "acknowledge_grant_delivery") })
        {
            await using var lookup = new NpgsqlCommand("SELECT p.oid::regprocedure::text,(SELECT string_agg('NULL::'||pg_catalog.format_type(arg.type_oid,NULL),',' ORDER BY arg.position) FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY arg(type_oid,position) WHERE arg.position>1) FROM pg_catalog.pg_proc p WHERE p.pronamespace='enrollment_execution'::regnamespace AND p.proname=@name", owner);
            lookup.Parameters.AddWithValue("name", name);
            await using var lookupReader = await lookup.ExecuteReaderAsync(cancellationToken);
            Assert.True(await lookupReader.ReadAsync(cancellationToken));
            var signature = lookupReader.GetString(0);
            var arguments = lookupReader.GetString(1);
            Assert.False(await lookupReader.ReadAsync(cancellationToken));
            await lookupReader.DisposeAsync();
            await using var privilege = new NpgsqlCommand("SELECT pg_catalog.has_function_privilege(@signature,'EXECUTE')", connection);
            privilege.Parameters.AddWithValue("signature", signature);
            Assert.Equal(true, await privilege.ExecuteScalarAsync(cancellationToken));
            await using var pendingTransaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
            // Fixed wrapper inventory and trusted disposable-catalog type names; all are non-STRICT.
            await using var command = new NpgsqlCommand($"SELECT * FROM enrollment_execution.{name}(@environment,{arguments})", connection);
            command.Parameters.AddWithValue("environment", environment);
            var pending = await Assert.ThrowsAsync<PostgresException>(async () => { await command.ExecuteNonQueryAsync(cancellationToken); });
            Assert.True(pending.SqlState == "42501", name + ": " + pending.SqlState);
            var expectedMessage = name is "claim_next" or "defer_claim" or "complete_claim" ? "Execution queue capability is unavailable."
                : connection == runtime ? "Execution capability is unavailable." : "Enrollment delivery privilege audit failed.";
            Assert.Equal(expectedMessage, pending.MessageText);
            await pendingTransaction.RollbackAsync(cancellationToken);
        }
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            // Trusted-owner candidate proof only. The actual history transition remains uncomposed.
            await Execute(owner, "UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=session_user");
            await Audit(owner, "audit_execution_privileges", true);
            await transaction.CommitAsync(cancellationToken);
        }
        await Audit(runtime, "audit_execution_privileges", true);
        await Audit(status, "audit_delivery_privileges", true);
        await Audit(delivery, "audit_delivery_privileges", true);
        await using (var transaction = await runtime.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken))
        {
            await using var command = new NpgsqlCommand("SELECT outcome FROM enrollment_execution.claim_next(@environment,@token)", runtime);
            command.Parameters.AddWithValue("environment", environment);
            command.Parameters.AddWithValue("token", Guid.NewGuid());
            Assert.Equal("NoWork", await command.ExecuteScalarAsync(cancellationToken));
            await transaction.RollbackAsync(cancellationToken);
        }
        foreach (var mutation in new[] {
            "ALTER FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) RENAME TO missing_structure_audit",
            "ALTER FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) SECURITY DEFINER",
            "ALTER FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) VOLATILE",
            "ALTER FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) SET search_path=public,pg_temp",
            "GRANT EXECUTE ON FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) TO PUBLIC",
            "CREATE FUNCTION enrollment_execution.audit_execution_profile_structure(integer) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
            "CREATE OR REPLACE FUNCTION enrollment_execution.audit_execution_profile_structure(p_environment uuid) RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint) LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RAISE EXCEPTION 'Unpinned maintenance must never execute'; END $f$",
            "CREATE OR REPLACE FUNCTION enrollment_execution.profile4_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RAISE EXCEPTION 'Unpinned ready predicate must never execute'; END $f$",
            "ALTER TABLE enrollment_execution.profile4_readiness DISABLE TRIGGER profile4_readiness_transition"
        })
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await Execute(owner, mutation);
            await Audit(owner, "audit_execution_privileges", false);
            await transaction.RollbackAsync(cancellationToken);
            await Audit(owner, "audit_execution_privileges", true);
        }
        Assert.Equal(original, await Identity());
    }
}
