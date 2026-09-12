namespace ItManagement.EnrollmentWorker;

internal static class EnrollmentWorkerCommand
{
    internal static async Task<int> RunAsync(string[] args, Func<EnrollmentWorkerOptions> load,
        Func<ValidatedEnrollmentWorkerEnvironment, CancellationToken, Task<IEnrollmentWorkerEnvironment>> create,
        TextWriter output, CancellationToken cancellationToken)
    {
        if (args is ["--help"])
        {
            await output.WriteLineAsync("Use --verify to audit the configured public execution and private issuer databases. Work processing is not yet available.").ConfigureAwait(false);
            return 0;
        }
        // No flag, configuration value, or service startup can activate an incomplete delivery pipeline.
        if (args is not ["--verify"])
        {
            await output.WriteLineAsync("EnrollmentWorkerProcessingUnavailable: use --verify or --help.").ConfigureAwait(false);
            return 2;
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            deadline.Token.ThrowIfCancellationRequested();
            var options = load().ValidateAndSnapshot();
            var byId = options.Environments.ToDictionary(environment => environment.EnvironmentId);
            await using (var resources = await EnrollmentWorkerResources.CreateAsync(byId.Keys.ToArray(),
                (id, token) => create(byId[id], token), deadline.Token).ConfigureAwait(false))
            {
                // Deliberately never construct or run a loop here. Audits must not claim or issue grants.
                deadline.Token.ThrowIfCancellationRequested();
            }
            deadline.Token.ThrowIfCancellationRequested();
            await output.WriteLineAsync("EnrollmentWorkerVerificationSucceeded: database profiles verified; work processing remains unavailable.").ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await output.WriteLineAsync("EnrollmentWorkerVerificationCancelled").ConfigureAwait(false);
            return 130;
        }
        catch
        {
            await output.WriteLineAsync("EnrollmentWorkerVerificationFailed").ConfigureAwait(false);
            return 1;
        }
    }
}
