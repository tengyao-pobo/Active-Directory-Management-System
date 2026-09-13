using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeliveryOwnerGuardRejectsMissingOrInvisibleRole(bool hidden)
    {
        var data = await _fixture.SeedAsync();
        var runtime = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Username!;
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        await Execute(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "owner-mapping-guard-v1.sql")));
        await using var roleQuery = new NpgsqlCommand($"SELECT \"Id\" FROM public.\"Roles\" WHERE \"EnvironmentId\"='{data.Environment.Id}' AND \"Name\"='reviewer'", connection, transaction);
        var ordinaryRole = (Guid)(await roleQuery.ExecuteScalarAsync())!;
        await Execute($"SELECT set_config('app.environment_id','{data.Environment.Id}',true),set_config('app.principal_id','{data.Requester.Id}',true)");
        var login = "SET LOCAL SESSION AUTHORIZATION " + QuoteIdentifier(runtime);
        string Insert(Guid role) => $"INSERT INTO public.\"GroupMappings\" VALUES ('{data.Environment.Id}','{Guid.NewGuid()}','S-1-5-21-1-2-3-4','{role}','{data.AllScopeId}')";
        // Same caller and GroupMappings policies permit the visible non-Owner target.
        await Execute("SAVEPOINT visible_target; " + login);
        await Execute(Insert(ordinaryRole));
        await Execute("RESET SESSION AUTHORIZATION; ROLLBACK TO SAVEPOINT visible_target; RELEASE SAVEPOINT visible_target");
        if (hidden)
            await Execute($"CREATE POLICY test_hidden_owner_guard ON public.\"Roles\" AS RESTRICTIVE FOR SELECT TO {QuoteIdentifier(runtime)} USING (\"Id\"<>'{ordinaryRole}'::uuid)");
        await Execute(login);
        if (hidden)
        {
            await using var visibility = new NpgsqlCommand($"SELECT count(*) FROM public.\"Roles\" WHERE \"Id\"='{ordinaryRole}'", connection, transaction);
            Assert.Equal(0L, await visibility.ExecuteScalarAsync());
        }
        var error = await Assert.ThrowsAsync<PostgresException>(() => Execute(Insert(hidden ? ordinaryRole : Guid.NewGuid())));
        Assert.Equal("23514", error.SqlState);
        Assert.Equal("Directory group role target is not eligible", error.MessageText);
        await transaction.RollbackAsync();
    }

    [Theory]
    [InlineData("none")]
    [InlineData("settings")]
    [InlineData("body")]
    [InlineData("old-visibility")]
    [InlineData("owner")]
    [InlineData("definer")]
    [InlineData("public")]
    [InlineData("support")]
    [InlineData("strict")]
    [InlineData("disabled")]
    [InlineData("missing")]
    [InlineData("event")]
    [InlineData("statement")]
    [InlineData("argument")]
    [InlineData("condition")]
    [InlineData("overload")]
    public async Task DeliveryOwnerGuardCatalogRejectsDrift(string fault)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        await Execute(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "owner-mapping-guard-v1.sql")));
        var query = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-owner-mapping-guard.sql")))
            .Replace(":'expected_table_owner_role'", "current_user::text", StringComparison.Ordinal);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand(query, connection, transaction);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            var result = reader.GetBoolean(0);
            Assert.False(await reader.ReadAsync());
            return result;
        }
        Assert.True(await Valid());
        await Execute(fault switch
        {
            "none" => "SELECT 1",
            "settings" => "ALTER FUNCTION public.guard_owner_mapping() RESET ALL",
            "body" => "CREATE OR REPLACE FUNCTION public.guard_owner_mapping() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS 'BEGIN RETURN NEW; END'",
            "old-visibility" => "CREATE OR REPLACE FUNCTION public.guard_owner_mapping() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$BEGIN IF EXISTS(SELECT 1 FROM public.\"Roles\" WHERE \"EnvironmentId\"=NEW.\"EnvironmentId\" AND \"Id\"=NEW.\"RoleId\" AND \"BuiltInKind\"='Owner') THEN RAISE EXCEPTION 'Owner cannot be granted through directory groups' USING ERRCODE='23514'; END IF; RETURN NEW; END$$",
            "owner" => "ALTER FUNCTION public.guard_owner_mapping() OWNER TO " + QuoteIdentifier(_fixture.PlanLockOwner),
            "definer" => "ALTER FUNCTION public.guard_owner_mapping() SECURITY DEFINER",
            "public" => "GRANT EXECUTE ON FUNCTION public.guard_owner_mapping() TO PUBLIC",
            "support" => "ALTER FUNCTION public.guard_owner_mapping() SUPPORT pg_catalog.textlike_support",
            "strict" => "ALTER FUNCTION public.guard_owner_mapping() STRICT",
            "disabled" => "ALTER TABLE public.\"GroupMappings\" DISABLE TRIGGER no_owner_mapping",
            "missing" => "DROP TRIGGER no_owner_mapping ON public.\"GroupMappings\"",
            "event" => ReplaceTrigger("BEFORE INSERT", "ROW", ""),
            "statement" => ReplaceTrigger("BEFORE INSERT OR UPDATE", "STATEMENT", ""),
            "argument" => ReplaceTrigger("BEFORE INSERT OR UPDATE", "ROW", "", "'extra'"),
            "condition" => ReplaceTrigger("BEFORE INSERT OR UPDATE", "ROW", "WHEN (NEW.\"RoleId\" IS NOT NULL)"),
            "overload" => "CREATE FUNCTION public.guard_owner_mapping(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        });
        Assert.Equal(fault == "none", await Valid());
        await transaction.RollbackAsync();

        static string ReplaceTrigger(string events, string level, string condition, string arguments = "") =>
            $"DROP TRIGGER no_owner_mapping ON public.\"GroupMappings\"; CREATE TRIGGER no_owner_mapping {events} ON public.\"GroupMappings\" FOR EACH {level} {condition} EXECUTE FUNCTION public.guard_owner_mapping({arguments});";
    }
}
