using ItManagement.EnrollmentGrantExecution;
using ItManagement.EnrollmentWorker;
using Xunit;

namespace EnrollmentWorker.Tests;

public sealed class EnrollmentWorkerResourcesTests
{
    [Fact]
    public async Task ValidatesWholeListBeforeCreatingAnyResource()
    {
        var id = Guid.NewGuid();
        var called = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => EnrollmentWorkerResources.CreateAsync([id, id],
            (_, _) => { called = true; throw new Exception(); }, CancellationToken.None));
        Assert.False(called);
    }

    [Fact]
    public async Task StartupFailureDisposesPreviousEnvironmentsInReverseAndSanitizesProviderError()
    {
        var ids = Enumerable.Range(0, 3).Select(_ => Guid.NewGuid()).ToArray();
        var disposed = new List<Guid>();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => EnrollmentWorkerResources.CreateAsync(ids,
            (id, _) => id == ids[2] ? throw new Exception("provider secret")
                : Task.FromResult<IEnrollmentWorkerEnvironment>(new FakeEnvironment(id, disposed)), CancellationToken.None));
        Assert.Equal("EnrollmentWorkerStartupAuditFailed", error.Message);
        Assert.Null(error.InnerException);
        Assert.Equal(ids.Take(2).Reverse(), disposed);
    }

    [Fact]
    public async Task CancellationCleansUpAndNeverCreatesNextEnvironment()
    {
        using var cancellation = new CancellationTokenSource();
        var ids = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var disposed = new List<Guid>();
        var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EnrollmentWorkerResources.CreateAsync(ids, (id, _) =>
        {
            calls++;
            cancellation.Cancel();
            return Task.FromResult<IEnrollmentWorkerEnvironment>(new FakeEnvironment(id, disposed));
        }, cancellation.Token));
        Assert.Equal(1, calls);
        Assert.Equal([ids[0]], disposed);
    }

    [Fact]
    public async Task MismatchedEnvironmentIsAlsoDisposed()
    {
        var wrongId = Guid.NewGuid();
        var disposed = new List<Guid>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => EnrollmentWorkerResources.CreateAsync([Guid.NewGuid()],
            (_, _) => Task.FromResult<IEnrollmentWorkerEnvironment>(new FakeEnvironment(wrongId, disposed)), CancellationToken.None));
        Assert.Equal([wrongId], disposed);
    }

    [Fact]
    public async Task DisposalContinuesAfterFailureAndIsIdempotent()
    {
        var ids = new[] { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() };
        var disposed = new List<Guid>();
        var resources = await EnrollmentWorkerResources.CreateAsync(ids, (id, _) =>
            Task.FromResult<IEnrollmentWorkerEnvironment>(new FakeEnvironment(id, disposed, id == ids[1])), CancellationToken.None);
        var first = resources.DisposeAsync().AsTask();
        var second = resources.DisposeAsync().AsTask();
        Assert.Same(first, second);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => first);
        Assert.Equal("EnrollmentWorkerCleanupFailed", error.Message);
        Assert.Null(error.InnerException);
        Assert.Equal(ids.Reverse(), disposed);
    }

    private sealed class FakeEnvironment(Guid id, List<Guid> disposed, bool failDispose = false) : IEnrollmentWorkerEnvironment
    {
        public Guid EnvironmentId => id;
        public Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Startup must never process work");
        public ValueTask DisposeAsync()
        {
            disposed.Add(id);
            return failDispose ? ValueTask.FromException(new Exception("provider secret")) : ValueTask.CompletedTask;
        }
    }
}
