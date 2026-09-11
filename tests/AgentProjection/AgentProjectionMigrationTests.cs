namespace ItManagement.AgentProjection.Tests;

[Collection(AgentProjectionCollection.Name)]
public sealed class AgentProjectionMigrationTests(AgentProjectionFixture fixture):IAsyncLifetime
{
    public Task InitializeAsync()=>fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.inventory_projection; DELETE FROM agent_private.receipts; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.devices;");
    public async Task DisposeAsync(){if(!await fixture.Scalar<bool>("SELECT pg_catalog.to_regprocedure('agent_private.read_current_inventory_projection(uuid,uuid)') IS NOT NULL"))await fixture.UpgradeProjection();}

    [Fact]
    public async Task V2DowngradesToExactV1AndUpgradesWithExistingData()
    {
        var seed=await fixture.Seed();await fixture.DowngradeProjection();
        Assert.True(await fixture.Scalar<bool>("SELECT pg_catalog.to_regprocedure('agent_private.read_current_inventory_projection(uuid,uuid)') IS NULL"));
        Assert.Equal("ReadBitLocker",await fixture.Scalar<string>("SELECT purpose FROM agent_private.agent_projection_database_bindings"));
        await using(var audit=fixture.Projection.CreateCommand("SELECT is_valid,diagnostic_code FROM agent_private.audit_projection_privileges(@environment,@table_owner::name,@function_owner::name)")){audit.Parameters.AddWithValue("environment",fixture.EnvironmentId);audit.Parameters.AddWithValue("table_owner",fixture.TableOwnerRole);audit.Parameters.AddWithValue("function_owner",fixture.ProjectionDefinerRole);await using var row=await audit.ExecuteReaderAsync();Assert.True(await row.ReadAsync());Assert.True(row.GetBoolean(0));Assert.Equal("None",row.GetString(1));}
        await using(var read=fixture.Projection.CreateCommand("SELECT outcome FROM agent_private.read_current_bitlocker_projection(@environment,@directory)")){read.Parameters.AddWithValue("environment",seed.EnvironmentId);read.Parameters.AddWithValue("directory",seed.DirectoryObjectId);Assert.Equal("Observed",(string)(await read.ExecuteScalarAsync())!);}
        await Assert.ThrowsAsync<InvalidOperationException>(()=>PostgresAgentInventoryProjectionReader.CreateAuditedAsync(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole));
        await fixture.UpgradeProjection();Assert.Equal("ReadDeviceProjection",await fixture.Scalar<string>("SELECT purpose FROM agent_private.agent_projection_database_bindings"));
        var reader=await PostgresAgentInventoryProjectionReader.CreateAuditedAsync(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole);var result=await reader.ReadInventoryAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);Assert.Equal(ProjectionReadState.Observed,result.State);Assert.Equal(ProjectionAvailability.Missing,result.BasicDevice.Availability);
    }

    [Fact]
    public async Task LateDowngradeFailureRollsBackAllMutations()
    {
        await fixture.VerifyFailedLateDowngradeRollsBack();
        Assert.True(await fixture.Scalar<bool>("SELECT pg_catalog.to_regprocedure('agent_private.read_current_inventory_projection(uuid,uuid)') IS NOT NULL"));Assert.Equal("ReadDeviceProjection",await fixture.Scalar<string>("SELECT purpose FROM agent_private.agent_projection_database_bindings"));
        Assert.Equal(2,await fixture.Scalar<short>("SELECT profile_version FROM agent_private.audit_projection_privileges(@env,@owner::name,@function_owner::name)",new("env",fixture.EnvironmentId),new("owner",fixture.TableOwnerRole),new("function_owner",fixture.ProjectionDefinerRole)));
    }

    [Fact]
    public async Task TargetAclDriftFailsPostflightAndRollsBackDowngrade()
    {
        await fixture.VerifyPostflightAclDriftRollsBack();
        Assert.Equal("ReadDeviceProjection",await fixture.Scalar<string>("SELECT purpose FROM agent_private.agent_projection_database_bindings"));
        Assert.True(await fixture.Scalar<bool>("SELECT pg_catalog.to_regprocedure('agent_private.read_current_inventory_projection(uuid,uuid)') IS NOT NULL"));
        Assert.False(await fixture.Scalar<bool>("SELECT pg_catalog.has_table_privilege(@role,'agent_private.devices','SELECT')",new Npgsql.NpgsqlParameter("role",fixture.ProjectionRole)));
    }

    [Fact]
    public async Task MigrationPreflightRejectsFunctionDriftBeforeMutation()
    {
        await fixture.Execute("ALTER FUNCTION agent_private.read_current_inventory_projection(uuid,uuid) SET search_path=pg_catalog,pg_temp");
        try{await Assert.ThrowsAnyAsync<Exception>(fixture.DowngradeProjection);Assert.Equal("ReadDeviceProjection",await fixture.Scalar<string>("SELECT purpose FROM agent_private.agent_projection_database_bindings"));}
        finally{await fixture.Execute("ALTER FUNCTION agent_private.read_current_inventory_projection(uuid,uuid) SET search_path=pg_catalog,agent_private,pg_temp");}
    }
}
