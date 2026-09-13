using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("membership-support")]
    [InlineData("access-support")]
    [InlineData("leakproof")]
    [InlineData("body")]
    [InlineData("missing")]
    [InlineData("config")]
    [InlineData("strict")]
    [InlineData("membership-reset")]
    [InlineData("access-reset")]
    [InlineData("unnamed-arguments")]
    public async Task DeliveryPolicyCalleeCatalogRejectsExecutableDrift(string fault)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        var start = profile.IndexOf("-- BEGIN delivery policy callee metadata", StringComparison.Ordinal);
        var end = profile.IndexOf("-- END delivery policy callee metadata", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute($"""
            CREATE FUNCTION pg_temp.test_delivery_policy_callees() RETURNS boolean LANGUAGE plpgsql AS $test$
            DECLARE table_owner oid := CURRENT_USER::regrole; ok boolean := true;
            BEGIN
            {profile[start..end]}
            RETURN COALESCE(ok,false);
            END $test$;
            """);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand("SELECT pg_temp.test_delivery_policy_callees()", connection, transaction);
            return (bool)(await command.ExecuteScalarAsync())!;
        }
        Assert.True(await Valid());
        await Execute(fault switch
        {
            "none" => "SELECT 1",
            "membership-support" => "ALTER FUNCTION public.has_environment_membership(uuid,uuid) SUPPORT pg_catalog.textlike_support",
            "access-support" => "ALTER FUNCTION public.directory_database_access(uuid,uuid) SUPPORT pg_catalog.textlike_support",
            "leakproof" => "ALTER FUNCTION public.directory_database_access(uuid,uuid) LEAKPROOF",
            "body" => "CREATE OR REPLACE FUNCTION public.directory_database_access(p_environment uuid,p_principal uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=off AS 'SELECT true'",
            "missing" => "DROP FUNCTION public.directory_database_access(uuid,uuid) CASCADE",
            "config" => "ALTER FUNCTION public.directory_database_access(uuid,uuid) SET row_security=on",
            "strict" => "ALTER FUNCTION public.has_environment_membership(uuid,uuid) CALLED ON NULL INPUT",
            "membership-reset" => "ALTER FUNCTION public.has_environment_membership(uuid,uuid) RESET ALL",
            "access-reset" => "ALTER FUNCTION public.directory_database_access(uuid,uuid) RESET ALL",
            "unnamed-arguments" => """
                DO $argument_names$
                DECLARE definition text; original text; previous_setting text:=current_setting('check_function_bodies');
                BEGIN
                  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
                    FROM pg_catalog.pg_proc p WHERE p.oid='public.directory_database_access(uuid,uuid)'::regprocedure;
                  IF strpos(definition,'p_environment uuid, p_principal uuid')=0 THEN RAISE EXCEPTION 'Missing expected argument names.'; END IF;
                  EXECUTE 'DROP FUNCTION public.directory_database_access(uuid,uuid) CASCADE';
                  PERFORM set_config('check_function_bodies','off',true);
                  EXECUTE replace(definition,'p_environment uuid, p_principal uuid','uuid, uuid');
                  PERFORM set_config('check_function_bodies',previous_setting,true);
                  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='public.directory_database_access(uuid,uuid)'::regprocedure
                    AND p.prosrc=original AND p.proargnames IS NULL) THEN RAISE EXCEPTION 'Argument probe changed the body or retained names.'; END IF;
                END $argument_names$;
                """,
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        });
        Assert.Equal(fault == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
