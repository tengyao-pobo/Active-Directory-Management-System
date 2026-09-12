using System.Net;
using System.Security.Cryptography;
using ItManagement.Api;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task DeliveryIdentityHttpSessionTouchAndLogoutWorkInIsolatedDatabase()
    {
        // A separate disposable database lets real HTTP connections see committed RLS
        // without changing the shared integration fixture's identity tables or policies.
        var original = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        var suffix = Guid.NewGuid().ToString("N");
        var database = "identity_http_" + suffix;
        var runtime = "identity_api_" + suffix;
        var locker = "identity_lock_" + suffix;
        var execution = "identity_exec_" + suffix;
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var ownerConnection = new NpgsqlConnectionStringBuilder(original.ConnectionString) { Database = database };
        var runtimeConnection = new NpgsqlConnectionStringBuilder(ownerConnection.ConnectionString) { Username = runtime, Password = password };
        var environmentKeys = new[] { "CONSOLE_TEST_DB", "CONSOLE_TEST_RUNTIME_DB", "CONSOLE_TEST_PLAN_LOCK_OWNER", "ConnectionStrings__Console" };
        var previous = environmentKeys.ToDictionary(key => key, Environment.GetEnvironmentVariable);
        await using var admin = new NpgsqlConnection(original.ConnectionString);
        await admin.OpenAsync();
        async Task Admin(string sql)
        {
            await using var command = new NpgsqlCommand(sql, admin);
            await command.ExecuteNonQueryAsync();
        }
        PostgresApiFixture? isolated = null;
        var created = false;
        try
        {
            await Admin($"CREATE DATABASE {QuoteIdentifier(database)} OWNER {QuoteIdentifier(original.Username!)}");
            created = true;
            await Admin($"""
                CREATE ROLE "{runtime}" LOGIN NOINHERIT PASSWORD '{password}';
                CREATE ROLE "{locker}" NOLOGIN NOINHERIT;
                CREATE ROLE "{execution}" NOLOGIN NOINHERIT;
                """);
            Environment.SetEnvironmentVariable("CONSOLE_TEST_DB", ownerConnection.ConnectionString);
            Environment.SetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB", runtimeConnection.ConnectionString);
            Environment.SetEnvironmentVariable("CONSOLE_TEST_PLAN_LOCK_OWNER", locker);
            isolated = new PostgresApiFixture();
            await isolated.InitializeAsync();
            var seed = await isolated.SeedAsync();
            await using (var owner = new NpgsqlConnection(ownerConnection.ConnectionString))
            {
                await owner.OpenAsync();
                var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"));
                source = source.Replace(":\"expected_table_owner_role\"", QuoteIdentifier(original.Username!), StringComparison.Ordinal)
                    .Replace(":\"enrollment_plan_lock_owner_role\"", QuoteIdentifier(locker), StringComparison.Ordinal)
                    .Replace(":\"execution_definer_role\"", QuoteIdentifier(execution), StringComparison.Ordinal);
                await using var command = new NpgsqlCommand("BEGIN; SELECT pg_advisory_xact_lock(1162235478,1);" + source + "COMMIT;", owner);
                await command.ExecuteNonQueryAsync();
            }
            using var anonymous = isolated.Client();
            using var anonymousMe = await anonymous.GetAsync("/api/v1/session/me");
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousMe.StatusCode);
            using var client = isolated.Client(seed.RequesterToken);
            using var me = await client.GetAsync("/api/v1/session/me");
            Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            Assert.True(me.Headers.Contains("X-Session-Remaining-Ms"));
            using var logoutRequest = await client.MutationAsync(HttpMethod.Post, "/api/v1/session/logout", new { });
            using var logout = await client.SendAsync(logoutRequest);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
            using var revokedMe = await client.GetAsync("/api/v1/session/me");
            Assert.Equal(HttpStatusCode.Unauthorized, revokedMe.StatusCode);
            await using var verification = new NpgsqlConnection(ownerConnection.ConnectionString);
            await verification.OpenAsync();
            await using var verify = new NpgsqlCommand("SELECT \"RevokedAt\" IS NOT NULL AND \"LastSeenAt\">=\"CreatedAt\" FROM public.\"Sessions\" WHERE \"IdHash\"=@hash", verification);
            verify.Parameters.AddWithValue("hash", SessionTokens.Hash(seed.RequesterToken));
            Assert.Equal(true, await verify.ExecuteScalarAsync());
        }
        finally
        {
            try
            {
                if (isolated is not null) await isolated.DisposeAsync();
            }
            finally
            {
                foreach (var key in environmentKeys) Environment.SetEnvironmentVariable(key, previous[key]);
                if (created)
                {
                    // Names are generated once above, never supplied by a caller or discovered broadly.
                    await Admin($"DROP DATABASE {QuoteIdentifier(database)} WITH (FORCE)");
                    await Admin($"DROP ROLE IF EXISTS {QuoteIdentifier(runtime)}, {QuoteIdentifier(locker)}, {QuoteIdentifier(execution)}");
                }
            }
        }
    }
}
