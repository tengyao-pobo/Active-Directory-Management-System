using System.Text.Json;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Tests;

public sealed class HardwareCollectorTests
{
    [Fact]
    public async Task Uses_fixed_catalog_and_drops_unrequested_data()
    {
        var reader = new Reader(kind => new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch,
            [JsonSerializer.SerializeToElement(new { Manufacturer = "Synthetic", Secret = "do-not-export", UserName = "private" })]));
        var payload = await new HardwareCollector(reader).CollectAsync(default);
        Assert.Equal(Enum.GetValues<HardwareQueryKind>(), reader.Seen);
        Assert.DoesNotContain("do-not-export", payload.Data.GetRawText());
        Assert.DoesNotContain("UserName", payload.Data.GetRawText());
        Assert.Contains("Synthetic", payload.Data.GetRawText());
    }

    [Fact]
    public async Task Per_query_errors_preserve_other_sections_without_details()
    {
        var reader = new Reader(kind => kind == HardwareQueryKind.Bios ? throw new UnauthorizedAccessException("private-path") :
            new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [JsonSerializer.SerializeToElement(new { Name = "Synthetic CPU" })]));
        var payload = await new HardwareCollector(reader).CollectAsync(default);
        var sections = payload.Data.GetProperty("Sections").EnumerateArray().ToArray();
        var bios = sections.Single(s => s.GetProperty("Kind").GetInt32() == (int)HardwareQueryKind.Bios);
        Assert.Equal((int)ObservationQuality.AccessDenied, bios.GetProperty("Quality").GetInt32());
        Assert.Equal(0, bios.GetProperty("Rows").GetArrayLength());
        Assert.DoesNotContain("private-path", payload.Data.GetRawText());
        Assert.Contains("Synthetic CPU", payload.Data.GetRawText());
    }

    [Fact]
    public async Task Bounds_rows_strings_and_reports_truncation()
    {
        var row = JsonSerializer.SerializeToElement(new { Name = new string('x', 600) });
        var payload = await new HardwareCollector(new Reader(_ => new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, Enumerable.Repeat(row, 129).ToArray()))).CollectAsync(default);
        var section = payload.Data.GetProperty("Sections").EnumerateArray().Single(s => s.GetProperty("Kind").GetInt32() == (int)HardwareQueryKind.Processor);
        Assert.True(section.GetProperty("IsTruncated").GetBoolean());
        Assert.Equal(128, section.GetProperty("Rows").GetArrayLength());
        Assert.Equal(512, section.GetProperty("Rows")[0].GetProperty("Name").GetString()!.Length);
    }

    [Fact]
    public async Task Empty_battery_is_not_applicable_but_empty_required_system_is_unknown()
    {
        var payload = await new HardwareCollector(new Reader(_ => new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, []))).CollectAsync(default);
        var sections = payload.Data.GetProperty("Sections").EnumerateArray().ToArray();
        Assert.Equal((int)ObservationQuality.NotApplicable, sections.Single(s => s.GetProperty("Kind").GetInt32() == (int)HardwareQueryKind.Battery).GetProperty("Quality").GetInt32());
        Assert.Equal((int)ObservationQuality.Unknown, sections.Single(s => s.GetProperty("Kind").GetInt32() == (int)HardwareQueryKind.System).GetProperty("Quality").GetInt32());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"Name\":null}")]
    [InlineData("{\"Name\":[]}")]
    [InlineData("{\"Name\":\"   \"}")]
    public async Task Unusable_rows_are_unknown_not_success_or_not_applicable(string json)
    {
        var row = JsonSerializer.Deserialize<JsonElement>(json);
        var payload = await new HardwareCollector(new Reader(_ => new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [row]))).CollectAsync(default);
        Assert.All(payload.Data.GetProperty("Sections").EnumerateArray(), section =>
        {
            Assert.Equal((int)ObservationQuality.Unknown, section.GetProperty("Quality").GetInt32());
            Assert.Empty(section.GetProperty("Rows").EnumerateArray());
        });
    }

    [Theory]
    [InlineData(unchecked((int)0x80041003), true)]
    [InlineData(unchecked((int)0x80070005), true)]
    [InlineData(unchecked((int)0x80041001), false)]
    public void Maps_native_permission_denied_without_windows_calls(int code, bool expected) =>
        Assert.Equal(expected, HardwareFailureClassifier.IsAccessDenied(code));

    [Fact]
    public async Task Cancellation_stops_without_collecting()
    {
        var reader = new Reader(_ => throw new InvalidOperationException());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await new HardwareCollector(reader).CollectAsync(cts.Token));
        Assert.Empty(reader.Seen);
    }

    [Fact]
    public void Catalog_does_not_contain_commands_or_sensitive_queries()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HardwareQueryCatalog.Get((HardwareQueryKind)999));
        foreach (var kind in Enum.GetValues<HardwareQueryKind>())
        {
            var definition = HardwareQueryCatalog.Get(kind);
            Assert.StartsWith("Win32_", definition.ClassName);
            Assert.DoesNotContain("Win32_Product", definition.ClassName);
            Assert.DoesNotContain("Password", string.Join(',', definition.Properties));
        }
    }

    private sealed class Reader(Func<HardwareQueryKind, HardwareQueryResult> read) : IHardwareQueryReader
    {
        public List<HardwareQueryKind> Seen { get; } = [];
        public ValueTask<HardwareQueryResult> ReadAsync(HardwareQueryKind kind, CancellationToken ct)
        {
            Seen.Add(kind);
            return ValueTask.FromResult(read(kind));
        }
    }
}
