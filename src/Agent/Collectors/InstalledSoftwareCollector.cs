using System.Runtime.Versioning;
using Microsoft.Win32;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public enum RegistryArchitectureView
{
    Registry32,
    Registry64
}

public sealed record RegistrySoftwareEntry(
    string? DisplayName,
    string? Version,
    string? Publisher,
    string? InstallDate,
    RegistryArchitectureView Architecture);

public sealed record InstalledSoftware(
    string Name,
    string? Version,
    string? Publisher,
    string? InstallDate,
    string Architecture);

public sealed record InstalledSoftwareInventory(
    IReadOnlyList<InstalledSoftware> Applications,
    bool IsTruncated = false);

public sealed record InstalledSoftwareRegistryReadResult(
    IReadOnlyList<RegistrySoftwareEntry> Entries,
    bool IsTruncated);

public interface IInstalledSoftwareRegistry
{
    ValueTask<InstalledSoftwareRegistryReadResult> ReadUninstallEntriesAsync(
        RegistryArchitectureView view,
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsInstalledSoftwareRegistry : IInstalledSoftwareRegistry
{
    private const string UninstallPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    private readonly int _maxEntriesPerView;

    public WindowsInstalledSoftwareRegistry(int maxEntriesPerView = 10_000)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntriesPerView);
        _maxEntriesPerView = maxEntriesPerView;
    }

    public ValueTask<InstalledSoftwareRegistryReadResult> ReadUninstallEntriesAsync(
        RegistryArchitectureView view,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var registryView = view == RegistryArchitectureView.Registry64
            ? RegistryView.Registry64
            : RegistryView.Registry32;
        var entries = new List<RegistrySoftwareEntry>();

        using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView);
        using var uninstall = localMachine.OpenSubKey(UninstallPath, writable: false);
        if (uninstall is null)
        {
            return ValueTask.FromResult(new InstalledSoftwareRegistryReadResult(entries, false));
        }

        var isTruncated = false;
        foreach (var subkeyName in uninstall.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var application = uninstall.OpenSubKey(subkeyName, writable: false);
            if (application is null)
            {
                continue;
            }

            entries.Add(new RegistrySoftwareEntry(
                application.GetValue("DisplayName") as string,
                application.GetValue("DisplayVersion") as string,
                application.GetValue("Publisher") as string,
                application.GetValue("InstallDate") as string,
                view));
            if (entries.Count > _maxEntriesPerView)
            {
                entries.RemoveAt(entries.Count - 1);
                isTruncated = true;
                break;
            }
        }

        return ValueTask.FromResult(new InstalledSoftwareRegistryReadResult(entries, isTruncated));
    }
}

public sealed record InstalledSoftwareCollectorOptions(int MaxApplications, int MaxStringLength)
{
    private const int HardMaxApplications = 100_000;
    public static InstalledSoftwareCollectorOptions Default { get; } = new(10_000, 512);

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxApplications);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStringLength);
        if (MaxApplications > HardMaxApplications)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxApplications));
        }
    }
}

public sealed class InstalledSoftwareCollector : IInventoryCollector
{
    private readonly IInstalledSoftwareRegistry _registry;
    private readonly InstalledSoftwareCollectorOptions _options;
    private readonly TimeProvider _timeProvider;

    public InstalledSoftwareCollector(
        IInstalledSoftwareRegistry registry,
        InstalledSoftwareCollectorOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _options = options ?? InstalledSoftwareCollectorOptions.Default;
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Name => "installed-software";

    public async ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken)
    {
        try
        {
            var registry32 = await _registry
                .ReadUninstallEntriesAsync(RegistryArchitectureView.Registry32, cancellationToken)
                .ConfigureAwait(false);
            var registry64 = await _registry
                .ReadUninstallEntriesAsync(RegistryArchitectureView.Registry64, cancellationToken)
                .ConfigureAwait(false);

            var isTruncated =
                registry32.IsTruncated ||
                registry64.IsTruncated ||
                registry32.Entries.Count > _options.MaxApplications + 1 ||
                registry64.Entries.Count > _options.MaxApplications + 1;
            var uniqueApplications = new HashSet<InstalledSoftware>();
            foreach (var entry in registry32.Entries.Take(_options.MaxApplications + 1)
                         .Concat(registry64.Entries.Take(_options.MaxApplications + 1)))
            {
                if (string.IsNullOrWhiteSpace(entry.DisplayName))
                {
                    continue;
                }

                uniqueApplications.Add(ToInstalledSoftware(entry, ref isTruncated));
                if (uniqueApplications.Count > _options.MaxApplications)
                {
                    isTruncated = true;
                    break;
                }
            }

            var applications = uniqueApplications
                .OrderBy(static application => application.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static application => application.Version, StringComparer.OrdinalIgnoreCase)
                .Take(_options.MaxApplications)
                .ToArray();

            return CollectorPayload.Create(
                ObservationQuality.Observed,
                "HKLM uninstall registry (32-bit and 64-bit views)",
                _timeProvider.GetUtcNow(),
                new InstalledSoftwareInventory(applications, isTruncated),
                applications.Length);
        }
        catch (UnauthorizedAccessException)
        {
            return CollectorPayload.Create(
                ObservationQuality.AccessDenied,
                "HKLM uninstall registry (32-bit and 64-bit views)",
                _timeProvider.GetUtcNow(),
                new InstalledSoftwareInventory([]),
                0);
        }
    }

    private InstalledSoftware ToInstalledSoftware(RegistrySoftwareEntry entry, ref bool isTruncated) =>
        new(
            Bound(entry.DisplayName!, ref isTruncated),
            BoundNullable(entry.Version, ref isTruncated),
            BoundNullable(entry.Publisher, ref isTruncated),
            BoundNullable(entry.InstallDate, ref isTruncated),
            entry.Architecture == RegistryArchitectureView.Registry64 ? "x64" : "x86");

    private string? BoundNullable(string? value, ref bool isTruncated) =>
        value is null ? null : Bound(value, ref isTruncated);

    private string Bound(string value, ref bool isTruncated)
    {
        if (value.Length <= _options.MaxStringLength)
        {
            return value;
        }

        isTruncated = true;
        return value[.._options.MaxStringLength];
    }
}
