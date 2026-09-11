using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace ItManagement.AgentProjection.Tests;

[Collection(AgentProjectionCollection.Name)]
public sealed class AgentInventoryProjectionTests(AgentProjectionFixture fixture):IAsyncLifetime
{
    public Task InitializeAsync()=>fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.inventory_projection; DELETE FROM agent_private.receipts; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.devices;");
    public Task DisposeAsync()=>Task.CompletedTask;

    [Fact]
    public async Task ReadsThreeTypedCollectorsAndExcludesUnrequestedPayload()
    {
        var seed=await fixture.Seed(AgentProjectionFixture.ValidInventoryPayload());
        var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.True(result.State==ProjectionReadState.Observed,$"{result.State}/{result.DiagnosticCode}");Assert.Equal(seed.DeviceId,result.DeviceId);Assert.Equal(seed.RegistrationId,result.RegistrationId);Assert.Equal(1,result.Sequence);
        Assert.True(result.BasicDevice.Availability==ProjectionAvailability.Observed,$"basic={result.BasicDevice.Availability}/{result.BasicDevice.DiagnosticCode};software={result.InstalledSoftware.Availability}/{result.InstalledSoftware.DiagnosticCode};hardware={result.Hardware.Availability}/{result.Hardware.DiagnosticCode}");Assert.Equal("synthetic-host",result.BasicDevice.HostName);Assert.Single(result.BasicDevice.NetworkInterfaces);
        Assert.Equal(ProjectionAvailability.Observed,result.InstalledSoftware.Availability);Assert.Equal("Synthetic App",Assert.Single(result.InstalledSoftware.Applications).Name);
        Assert.Equal(ProjectionAvailability.Observed,result.Hardware.Availability);Assert.Equal(9,result.Hardware.Sections.Count);
        var system=Assert.IsType<ProjectedSystemHardwareRow>(Assert.Single(result.Hardware.Sections.Single(section=>section.Kind==ProjectedHardwareKind.System).Rows));Assert.Equal(ulong.MaxValue.ToString(),system.TotalPhysicalMemory);
        Assert.DoesNotContain("secret-canary",JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task MissingAndRunnerFailureRemainIndependent()
    {
        var payload=Root();payload["Collectors"]!.AsArray().RemoveAt(0);var seed=await fixture.Seed(payload.ToJsonString());var missing=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Missing,missing.BasicDevice.Availability);Assert.Equal(ProjectionAvailability.Observed,missing.InstalledSoftware.Availability);Assert.Equal(ProjectionAvailability.Observed,missing.Hardware.Availability);
        await fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.inventory_projection; DELETE FROM agent_private.receipts; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.devices;");
        payload=Root();var basic=payload["Collectors"]![0]!.AsObject();basic["Status"]=1;basic["Quality"]=1;basic["Source"]="basic-device";basic["Data"]=null;basic["ItemCount"]=0;basic["ErrorCode"]="timeout";
        seed=await fixture.Seed(payload.ToJsonString());var failed=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Unavailable,failed.BasicDevice.Availability);Assert.Equal(ProjectionDiagnostic.SourceUnavailable,failed.BasicDevice.DiagnosticCode);Assert.Equal(ProjectionAvailability.Observed,failed.Hardware.Availability);
    }

    [Fact]
    public async Task HardwareKeepsUnknownAndNotApplicableSections()
    {
        var payload=Root();var sections=payload["Collectors"]![2]!["Data"]!["Sections"]!.AsArray();
        var video=sections[6]!.AsObject();video["Quality"]=2;video["Rows"]=new JsonArray();video["IsTruncated"]=false;video["ErrorCode"]=null;
        var battery=sections[8]!.AsObject();battery["Quality"]=1;battery["Rows"]=new JsonArray();battery["ErrorCode"]="query_timeout";payload["Collectors"]![2]!["ItemCount"]=7;
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Observed,result.Hardware.Availability);Assert.Equal(ProjectionAvailability.NotApplicable,result.Hardware.Sections[6].Availability);Assert.Equal(ProjectionAvailability.Unavailable,result.Hardware.Sections[8].Availability);
    }

    [Fact]
    public async Task DuplicateRequestedCollectorOnlyMakesThatCollectorUnavailable()
    {
        var payload=Root();var collectors=payload["Collectors"]!.AsArray();collectors.Add(collectors[0]!.DeepClone());
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Unavailable,result.BasicDevice.Availability);
        Assert.Equal(ProjectionAvailability.Observed,result.InstalledSoftware.Availability);
        Assert.Equal(ProjectionAvailability.Observed,result.Hardware.Availability);
    }

    [Fact]
    public async Task HardwareContainerRemainsObservedWhenNoSectionHasValues()
    {
        var payload=Root();var sections=payload["Collectors"]![2]!["Data"]!["Sections"]!.AsArray();
        for(var index=0;index<sections.Count;index++){var section=sections[index]!.AsObject();section["Rows"]=new JsonArray();section["Quality"]=index is 6 or 8?2:1;section["ErrorCode"]=null;section["IsTruncated"]=false;}
        payload["Collectors"]![2]!["Quality"]=1;payload["Collectors"]![2]!["ItemCount"]=0;
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Observed,result.Hardware.Availability);Assert.Equal(9,result.Hardware.Sections.Count);Assert.All(result.Hardware.Sections,section=>Assert.NotEqual(ProjectionAvailability.Observed,section.Availability));
    }

    [Fact]
    public async Task SoftwareAccessDeniedIsUnavailableWithoutData()
    {
        var payload=Root();var software=payload["Collectors"]![1]!.AsObject();software["Quality"]=3;software["Data"]=JsonSerializer.SerializeToNode(new{Applications=Array.Empty<object>(),IsTruncated=false});software["ItemCount"]=0;
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionAvailability.Unavailable,result.InstalledSoftware.Availability);Assert.Empty(result.InstalledSoftware.Applications);
    }

    [Theory]
    [InlineData("basic-count")]
    [InlineData("basic-future")]
    [InlineData("software-architecture")]
    [InlineData("hardware-source")]
    [InlineData("hardware-number")]
    [InlineData("hardware-duplicate-kind")]
    [InlineData("hardware-future")]
    public async Task MalformedCollectorIsUnavailableWithoutAffectingOthers(string variant)
    {
        var payload=Root();switch(variant)
        {
            case "basic-count":payload["Collectors"]![0]!["ItemCount"]=1;break;
            case "basic-future":payload["Collectors"]![0]!["ObservedAt"]=DateTimeOffset.UtcNow.AddMinutes(10).ToString("O");break;
            case "software-architecture":payload["Collectors"]![1]!["Data"]!["Applications"]![0]!["Architecture"]="arm64";break;
            case "hardware-source":payload["Collectors"]![2]!["Data"]!["Sections"]![0]!["Source"]="arbitrary";break;
            case "hardware-number":payload["Collectors"]![2]!["Data"]!["Sections"]![0]!["Rows"]![0]!["TotalPhysicalMemory"]=-1;break;
            case "hardware-duplicate-kind":payload["Collectors"]![2]!["Data"]!["Sections"]![8]!["Kind"]=7;break;
            case "hardware-future":payload["Collectors"]![2]!["Data"]!["Sections"]![0]!["ObservedAt"]=DateTimeOffset.UtcNow.AddMinutes(10).ToString("O");break;
        }
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        var affected=variant.StartsWith("basic",StringComparison.Ordinal)?result.BasicDevice:variant.StartsWith("software",StringComparison.Ordinal)?(object)result.InstalledSoftware:result.Hardware;
        Assert.Equal(ProjectionAvailability.Unavailable,affected switch{BasicDeviceProjection item=>item.Availability,InstalledSoftwareProjection item=>item.Availability,HardwareProjection item=>item.Availability,_=>throw new InvalidOperationException()});
    }

    [Fact]
    public async Task RawDatabaseCallRejectsCrossEnvironment()
    {
        await using var command=fixture.Projection.CreateCommand("SELECT diagnostic_code FROM agent_private.read_current_inventory_projection(@environment,@directory)");command.Parameters.AddWithValue("environment",Guid.NewGuid());command.Parameters.AddWithValue("directory",Guid.NewGuid());Assert.Equal("AuthenticationFailed",(string)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task FutureSharedTimestampRejectsWholeProjectionWhileOldSnapshotRemainsReadable()
    {
        var payload=Root();payload["CollectedAt"]=DateTimeOffset.UtcNow.AddMinutes(10).ToString("O");var seed=await fixture.Seed(payload.ToJsonString());var future=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);Assert.Equal(ProjectionReadState.Unavailable,future.State);
        await fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.inventory_projection; DELETE FROM agent_private.receipts; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.devices;");
        seed=await fixture.Seed(AgentProjectionFixture.ValidInventoryPayload());var old=await (await Create()).ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);Assert.Equal(ProjectionReadState.Observed,old.State);
    }

    private static JsonObject Root()=>JsonNode.Parse(AgentProjectionFixture.ValidInventoryPayload())!.AsObject();
    private Task<IAgentInventoryProjectionReader> Create()=>PostgresAgentInventoryProjectionReader.CreateAuditedAsync(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole);
}
