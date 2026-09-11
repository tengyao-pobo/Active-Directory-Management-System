using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed class SavedFilterConflictTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Serialization_failure_is_conflict_even_when_ef_wraps_it(bool wrapped)
    {
        Exception failure = new PostgresException("synthetic serialization failure", "ERROR", "ERROR", "40001");
        if (wrapped) failure = new DbUpdateException("synthetic save failure", failure);
        var result = await new SavedFilterApi.WriteConflictFilter().InvokeAsync(
            new DefaultEndpointFilterInvocationContext(new DefaultHttpContext()), _ => throw failure);
        var problem = Assert.IsType<ProblemHttpResult>(result);
        Assert.Equal(409, problem.StatusCode);
        Assert.Equal("SavedFilterWriteConflict", problem.ProblemDetails.Title);
    }

    [Theory]
    [InlineData("23505")]
    [InlineData("08006")]
    public async Task Unrelated_database_failures_are_not_reclassified(string state)
    {
        var failure = new DbUpdateException("synthetic failure", new PostgresException("synthetic", "ERROR", "ERROR", state));
        var actual = await Assert.ThrowsAsync<DbUpdateException>(async () =>
            await new SavedFilterApi.WriteConflictFilter().InvokeAsync(
                new DefaultEndpointFilterInvocationContext(new DefaultHttpContext()), _ => throw failure));
        Assert.Same(failure, actual);
    }
}
