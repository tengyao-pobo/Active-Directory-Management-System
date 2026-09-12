using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("EnrollmentGrantExecution", 1, true, false)]
    [InlineData("EnrollmentGrantExecution", 2, false, false)]
    [InlineData("EnrollmentGrantExecution", 2, true, true)]
    [InlineData("EnrollmentGrantExecution", 3, true, false)]
    [InlineData("Api", 2, false, false)]
    [InlineData("Connector", 2, true, true)]
    [InlineData("Other", 2, true, false)]
    public async Task ExecutionBindingRejectsUnrecognizedPurposeOrIdentityShape(
        string purpose, short version, bool hasEnvironment, bool hasPrincipal)
    {
        var seed = await _fixture.SeedAsync();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var role = $"execution_identity_{Guid.NewGuid():N}";
        Guid? environment = hasEnvironment ? seed.Environment.Id : null;
        Guid? principal = hasPrincipal ? seed.Requester.Id : null;
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId")
            VALUES ({role},{purpose},{version},{environment},{principal})
            """));
        Assert.Equal("23514", error.SqlState);
    }

    [Fact]
    public async Task ExecutionBindingIsUniquePerEnvironmentAndCannotUseEmptyEnvironment()
    {
        var seed = await _fixture.SeedAsync();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var first = $"execution_identity_{Guid.NewGuid():N}";
        var second = $"execution_identity_{Guid.NewGuid():N}";
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId")
            VALUES ({first},'EnrollmentGrantExecution',2,{seed.Environment.Id})
            """);
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId")
            VALUES ({second},'EnrollmentGrantExecution',2,{seed.Environment.Id})
            """));
        Assert.Equal("23505", error.SqlState);
        await tx.RollbackAsync();
        await using var emptyTx = await db.Database.BeginTransactionAsync();
        error = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId")
            VALUES ({first},'EnrollmentGrantExecution',2,{Guid.Empty})
            """));
        Assert.Equal("23514", error.SqlState);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutionRoleReservationCannotBeRewrittenOrDeleted(bool delete)
    {
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        var role = $"execution_reservation_{Guid.NewGuid():N}";
        // Synthetic metadata is rolled back; no database role or permanent reservation is provisioned.
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.role_reservations
                (role_name,role_oid,capability,role_kind,reservation_schema_version)
            VALUES ({role},current_user::regrole::oid,'EnrollmentGrantExecution','Runtime',1)
            """);
        var error = await Assert.ThrowsAsync<PostgresException>(() => delete
            ? db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM enrollment_execution.role_reservations WHERE role_name={role}")
            : db.Database.ExecuteSqlInterpolatedAsync($"UPDATE enrollment_execution.role_reservations SET role_kind='Definer' WHERE role_name={role}"));
        Assert.Equal("55000", error.SqlState);
    }

    [Fact]
    public async Task ExecutionIdentityMetadataDoesNotGrantApiRuntimeAccess()
    {
        await using var runtime = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB"));
        await runtime.OpenAsync();
        foreach (var sql in new[]
        {
            "SELECT * FROM enrollment_execution.role_reservations",
            "SELECT * FROM public.\"DirectoryDatabaseBindings\""
        })
        {
            await using var command = new NpgsqlCommand(sql, runtime);
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteReaderAsync());
            Assert.Equal("42501", error.SqlState);
        }
    }
}
