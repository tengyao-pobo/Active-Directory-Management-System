namespace ItManagement.Api;

/// <summary>Availability is not authorization; execution always revalidates the approved operation.</summary>
public interface IEnrollmentGrantExecutionReadiness
{
    /// <summary>Reads initialized in-memory state only; implementations must not perform I/O.</summary>
    bool IsReady(Guid environmentId);
}

// Replaced only when an audited execution processor is composed into the host.
public sealed class UnavailableEnrollmentGrantExecution : IEnrollmentGrantExecutionReadiness
{
    public bool IsReady(Guid environmentId) => false;
}
