using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4MembershipPinMatchesIndependentSource()
    {
        var source = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-profile4-membership.sql"))).Replace("\r\n", "\n", StringComparison.Ordinal);
        var bodies = Regex.Matches(source, @"AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
        var body = Assert.Single(bodies.Cast<Match>()).Groups["body"].Value;
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-membership.sql"));
        var pins = Regex.Matches(catalog, "'([0-9a-f]{64})' -- generated membership helper SHA-256");
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant(),
            Assert.Single(pins.Cast<Match>()).Groups[1].Value);
    }

    private static async Task VerifyProfile4MembershipCatalogAsync(NpgsqlConnection owner, Guid environment, CancellationToken cancellationToken)
    {
        var catalog = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-membership.sql"), cancellationToken))
            .Replace(":'expected_table_owner_role'", "CURRENT_USER", StringComparison.Ordinal);
        async Task Check(bool expected)
        {
            await using var direct = new NpgsqlCommand(catalog, owner);
            Assert.Equal(expected, await direct.ExecuteScalarAsync(cancellationToken));
            await using var structure = new NpgsqlCommand("SELECT is_valid FROM enrollment_execution.audit_execution_profile_structure(@environment)", owner);
            structure.Parameters.AddWithValue("environment", environment);
            Assert.Equal(expected, await structure.ExecuteScalarAsync(cancellationToken));
        }
        await Check(true);
        foreach (var mutation in new[]
        {
            "ALTER FUNCTION public.has_environment_membership(uuid,uuid) SET row_security=off",
            "ALTER FUNCTION public.has_environment_membership(uuid,uuid) SECURITY INVOKER",
            "ALTER FUNCTION public.has_environment_membership(uuid,uuid) RESET ALL",
            "GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) TO PUBLIC",
            "GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) FROM CURRENT_USER",
            "REVOKE EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid) FROM CURRENT_USER",
            "CREATE FUNCTION public.has_environment_membership(uuid) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
            "ALTER TABLE public.\"Memberships\" NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE public.\"Memberships\" DISABLE ROW LEVEL SECURITY",
            "DROP POLICY enrollment_profile4_membership_owner_select ON public.\"Memberships\"",
            "ALTER POLICY enrollment_profile4_membership_owner_select ON public.\"Memberships\" USING(false)",
            "ALTER POLICY enrollment_profile4_membership_owner_select ON public.\"Memberships\" TO PUBLIC",
            "CREATE POLICY extra_membership_owner_read ON public.\"Memberships\" FOR SELECT TO CURRENT_USER USING(true)",
            "CREATE POLICY extra_membership_owner_limit ON public.\"Memberships\" AS RESTRICTIVE FOR SELECT TO CURRENT_USER USING(false)",
            "ALTER POLICY member_read ON public.\"Memberships\" USING(true)",
            "ALTER POLICY member_insert ON public.\"Memberships\" WITH CHECK(true)",
            "ALTER POLICY member_update ON public.\"Memberships\" USING(true)",
            "ALTER POLICY member_update ON public.\"Memberships\" WITH CHECK(true)",
            "ALTER POLICY member_delete ON public.\"Memberships\" USING(true)",
            "DROP POLICY member_insert ON public.\"Memberships\""
        })
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(mutation, owner);
            await command.ExecuteNonQueryAsync(cancellationToken);
            await Check(false);
            await transaction.RollbackAsync(cancellationToken);
            await Check(true);
        }
    }
}
