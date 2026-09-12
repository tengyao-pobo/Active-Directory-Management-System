using ItManagement.EnrollmentGrantExecution;

namespace ItManagement.EnrollmentWorker;

public interface IEnrollmentWorkerEnvironment : IAsyncDisposable
{
    Guid EnvironmentId { get; }
    Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken);
}
