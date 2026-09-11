using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public interface IInventoryCollector
{
    string Name { get; }

    ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken);
}
