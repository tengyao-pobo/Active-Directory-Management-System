using System.Text.Json.Nodes;
using ItManagement.AgentEnrollment;
using ItManagement.AgentIngestion;
using Npgsql;

namespace ItManagement.AgentProjection.Tests;

[Collection(AgentProjectionCollection.Name)]
public sealed class AgentProjectionRepositoryTests(AgentProjectionFixture fixture):IAsyncLifetime
{
    public Task InitializeAsync()=>fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings; DELETE FROM agent_private.inventory_projection; DELETE FROM agent_private.receipts; DELETE FROM agent_private.certificate_bindings; DELETE FROM agent_private.registrations; DELETE FROM agent_private.devices;");
    public Task DisposeAsync()=>Task.CompletedTask;

    [Fact]
    public void UnsafeStoreOwnerIsRejectedWithoutPartialState()=>Assert.True(fixture.UnsafeStoreRollbackVerified);

    [Fact]
    public async Task DatabaseFunctionRejectsWrongEnvironmentBelowReaderGuard()
    {
        await using var command=fixture.Projection.CreateCommand("SELECT diagnostic_code FROM agent_private.read_current_bitlocker_projection(@environment,@directory)");
        command.Parameters.AddWithValue("environment",Guid.NewGuid());command.Parameters.AddWithValue("directory",Guid.NewGuid());
        Assert.Equal("AuthenticationFailed",(string)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task AuditedFactoryReadsOnlyTypedCurrentBitLockerProjection()
    {
        var seed=await fixture.Seed();var reader=await Create();var result=await reader.ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.True(result.State==ProjectionReadState.Observed,$"Expected Observed, received {result.State}/{result.DiagnosticCode}.");Assert.Equal(ProjectionDiagnostic.None,result.DiagnosticCode);
        Assert.Equal(seed.DeviceId,result.DeviceId);Assert.Equal(seed.RegistrationId,result.RegistrationId);Assert.Equal(seed.Epoch,result.RegistrationEpoch);
        Assert.Equal(1,result.Sequence);Assert.Equal(seed.ReceiptId,result.ReceiptId);Assert.NotNull(result.CollectedAt);Assert.NotNull(result.SourceObservedAt);Assert.NotNull(result.ReceivedAt);Assert.NotNull(result.LastSeenAt);
        var volume=Assert.Single(result.Volumes);Assert.Equal("synthetic-volume",volume.DeviceId);Assert.Equal(uint.MaxValue,volume.ProtectionStatus);Assert.Equal(string.Empty,volume.PersistentVolumeId);
    }

    [Fact]
    public async Task MissingMappingCrossEnvironmentAndInactiveDeviceFailClosed()
    {
        var reader=await Create();var missing=await reader.ReadAsync(fixture.EnvironmentId,Guid.NewGuid(),default);
        Assert.Equal(ProjectionReadState.Missing,missing.State);Assert.Equal(ProjectionDiagnostic.MappingMissing,missing.DiagnosticCode);
        var cross=await reader.ReadAsync(Guid.NewGuid(),Guid.NewGuid(),default);Assert.Equal(ProjectionDiagnostic.AuthenticationFailed,cross.DiagnosticCode);
        var seed=await fixture.Seed(deviceState:"Disabled");var inactive=await reader.ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Missing,inactive.State);Assert.Equal(ProjectionDiagnostic.DeviceUnavailable,inactive.DiagnosticCode);Assert.Empty(inactive.Volumes);
    }

    [Fact]
    public async Task CurrentActiveRegistrationMustExactlyMatchProjectionEpoch()
    {
        var seed=await fixture.Seed();await fixture.Execute("UPDATE agent_private.registrations SET state='Replaced' WHERE registration_id=@registration; INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state) VALUES(@env,@new_registration,@device,2,@guid,'Active')",new("registration",seed.RegistrationId),new("env",seed.EnvironmentId),new("new_registration",Guid.NewGuid()),new("device",seed.DeviceId),new("guid",Guid.NewGuid()));
        var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Missing,result.State);Assert.Equal(ProjectionDiagnostic.ProjectionMissing,result.DiagnosticCode);Assert.Equal(2,result.RegistrationEpoch);
    }

    [Theory]
    [InlineData("Revoked")]
    [InlineData("Replaced")]
    public async Task NonActiveRegistrationCannotExposeProjection(string registrationState)
    {
        var seed=await fixture.Seed(registrationState:registrationState);var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Missing,result.State);Assert.Equal(ProjectionDiagnostic.RegistrationUnavailable,result.DiagnosticCode);
        Assert.Equal(seed.DeviceId,result.DeviceId);Assert.Null(result.RegistrationId);Assert.Empty(result.Volumes);
    }

    [Fact]
    public async Task ZeroVolumesTruncationAndFutureCodesRemainObserved()
    {
        var zero=JsonNode.Parse(AgentProjectionFixture.ValidPayload())!.AsObject();var data=zero["Collectors"]![0]!["Data"]!.AsObject();data["Volumes"]=new JsonArray();data["IsTruncated"]=true;zero["Collectors"]![0]!["ItemCount"]=0;
        var seed=await fixture.Seed(zero.ToJsonString());var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Observed,result.State);Assert.Empty(result.Volumes);Assert.True(result.IsTruncated);
    }

    [Fact]
    public async Task MissingBitLockerCollectorDoesNotExposeOtherCollectorPayload()
    {
        var payload=JsonNode.Parse(AgentProjectionFixture.ValidPayload())!.AsObject();payload["Collectors"]=new JsonArray(JsonNode.Parse("""{"Collector":"hardware","RecoveryPassword":"secret-canary"}"""));
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Missing,result.State);Assert.Equal(ProjectionDiagnostic.ProjectionMissing,result.DiagnosticCode);
        Assert.DoesNotContain("secret-canary",System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task OtherCollectorsAreIgnoredAndNeverCopiedToObservedOutput()
    {
        var payload=JsonNode.Parse(AgentProjectionFixture.ValidPayload())!.AsObject();payload["Collectors"]!.AsArray().Add(JsonNode.Parse("""{"Collector":"hardware","RecoveryPassword":"secret-canary"}"""));
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Observed,result.State);Assert.DoesNotContain("secret-canary",System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Theory]
    [InlineData("timestamp")]
    [InlineData("oversize")]
    public async Task NonCanonicalOrOversizedStoredPayloadFailsClosed(string variant)
    {
        var payload=JsonNode.Parse(AgentProjectionFixture.ValidPayload())!.AsObject();
        if(variant=="timestamp")payload["CollectedAt"]="today";
        else payload["Collectors"]!.AsArray().Add(JsonNode.Parse($$"""{"Collector":"hardware","Padding":"{{new string('x',525000)}}"}"""));
        var seed=await fixture.Seed(payload.ToJsonString());var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Unavailable,result.State);Assert.Equal(ProjectionDiagnostic.ProjectionMalformed,result.DiagnosticCode);Assert.Empty(result.Volumes);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("malformed")]
    [InlineData("secret")]
    [InlineData("null-source")]
    [InlineData("missing-source")]
    [InlineData("numeric-source")]
    [InlineData("scalar-volume")]
    public async Task UnavailableAndMalformedSnapshotsNeverExposeStoredPayload(string variant)
    {
        var root=JsonNode.Parse(AgentProjectionFixture.ValidPayload())!.AsObject();var collectors=root["Collectors"]!.AsArray();var collector=collectors[0]!.AsObject();var data=collector["Data"]!.AsObject();
        switch(variant)
        {
            case "unknown":collector["Quality"]=1;data["Volumes"]=new JsonArray();data["ErrorCode"]="query_unavailable";collector["ItemCount"]=0;break;
            case "duplicate":collectors.Add(collector.DeepClone());break;
            case "malformed":data["Volumes"]![0]!["ProtectionStatus"]="1";break;
            case "secret":data["SecretKey"]="secret-canary";break;
            case "null-source":collector["Source"]=null;break;
            case "missing-source":collector.Remove("Source");break;
            case "numeric-source":collector["Source"]=1;break;
            case "scalar-volume":data["Volumes"]=new JsonArray(1);break;
        }
        var seed=await fixture.Seed(root.ToJsonString());var result=await (await Create()).ReadAsync(seed.EnvironmentId,seed.DirectoryObjectId,default);
        Assert.Equal(ProjectionReadState.Unavailable,result.State);Assert.Empty(result.Volumes);Assert.Null(result.Source);
        Assert.DoesNotContain("secret-canary",System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task ExactPrivilegesAndLegacyAuditorsRemainValidAndDetectDrift()
    {
        var audit=await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default);
        Assert.True(audit.IsValid);Assert.Equal(ProjectionDiagnostic.None,audit.DiagnosticCode);
        Assert.True((await new AgentStorePrivilegeAuditor(fixture.Ingest,fixture.TableOwnerRole).AuditAsync(default)).IsValid);
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.Enroll,fixture.TableOwnerRole,fixture.EnrollmentDefinerRole,"Enroll").AuditAsync(default)).IsValid);
        await fixture.Execute($"GRANT SELECT ON agent_private.devices TO \"{fixture.ProjectionRole}\"");
        try{Assert.False((await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid);}
        finally{await fixture.Execute($"REVOKE SELECT ON agent_private.devices FROM \"{fixture.ProjectionRole}\"");}
        await fixture.Execute($"GRANT UPDATE(device_id) ON agent_private.devices TO \"{fixture.ProjectionDefinerRole}\"");
        try{Assert.False((await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid);}
        finally{await fixture.Execute($"REVOKE UPDATE(device_id) ON agent_private.devices FROM \"{fixture.ProjectionDefinerRole}\"");}
        await fixture.Execute($"GRANT CREATE ON SCHEMA agent_private TO \"{fixture.ProjectionDefinerRole}\"");
        try{Assert.False((await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid);}
        finally{await fixture.Execute($"REVOKE CREATE ON SCHEMA agent_private FROM \"{fixture.ProjectionDefinerRole}\"");}
    }

    [Fact]
    public async Task PrivilegeAuditDetectsColumnPublicExtraExecuteAndWrongBinding()
    {
        async Task<bool> Valid()=> (await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid;
        Assert.True(await Valid());
        await fixture.Execute($"GRANT SELECT(environment_id) ON agent_private.devices TO \"{fixture.ProjectionRole}\"");
        try{Assert.False(await Valid());}finally{await fixture.Execute($"REVOKE SELECT(environment_id) ON agent_private.devices FROM \"{fixture.ProjectionRole}\"");}
        await fixture.Execute("GRANT SELECT(environment_id) ON agent_private.devices TO PUBLIC");
        try{Assert.False(await Valid());}finally{await fixture.Execute("REVOKE SELECT(environment_id) ON agent_private.devices FROM PUBLIC");}
        await fixture.Execute("GRANT EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) TO PUBLIC");
        try{Assert.False(await Valid());}finally{await fixture.Execute("REVOKE EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) FROM PUBLIC");}
        await fixture.Execute($"GRANT EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) TO \"{fixture.EnrollRole}\"");
        try{Assert.False(await Valid());}finally{await fixture.Execute($"REVOKE EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) FROM \"{fixture.EnrollRole}\"");}
        await fixture.Execute($"CREATE FUNCTION agent_private.projection_test_extra() RETURNS integer LANGUAGE sql AS 'SELECT 1'; REVOKE ALL ON FUNCTION agent_private.projection_test_extra() FROM PUBLIC; GRANT EXECUTE ON FUNCTION agent_private.projection_test_extra() TO \"{fixture.ProjectionRole}\"");
        try{Assert.False(await Valid());}finally{await fixture.Execute("DROP FUNCTION agent_private.projection_test_extra()") ;}
        Assert.False((await new AgentProjectionPrivilegeAuditor(fixture.Projection,Guid.NewGuid(),fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid);
    }

    [Fact]
    public async Task ProvisioningRejectsRoleAliasesBeforeChangingPrivileges()
    {
        await Assert.ThrowsAsync<PostgresException>(fixture.ReprovisionWithTableOwnerAsLogin);
        Assert.False(await fixture.Scalar<bool>("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=@role",new NpgsqlParameter("role",fixture.TableOwnerRole)));
        await Assert.ThrowsAsync<PostgresException>(fixture.ReprovisionWithEnrollmentDefinerAlias);
        Assert.False(await fixture.Scalar<bool>("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=@role",new NpgsqlParameter("role",fixture.EnrollmentDefinerRole)));
    }

    [Fact]
    public async Task PrivilegeAuditRejectsFunctionOwnershipAndRuntimeBindingAliases()
    {
        async Task<bool> Valid()=> (await new AgentProjectionPrivilegeAuditor(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole).AuditAsync(default)).IsValid;
        await fixture.Execute($"CREATE FUNCTION agent_private.projection_owner_drift() RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION agent_private.projection_owner_drift() OWNER TO \"{fixture.ProjectionDefinerRole}\"; REVOKE ALL ON FUNCTION agent_private.projection_owner_drift() FROM PUBLIC");
        try{Assert.False(await Valid());}finally{await fixture.Execute("DROP FUNCTION agent_private.projection_owner_drift()") ;}
        await fixture.Execute("INSERT INTO agent_private.agent_database_bindings(login_role,environment_id,purpose) VALUES(@role,@env,'Ingest')",new NpgsqlParameter("role",fixture.ProjectionDefinerRole),new NpgsqlParameter("env",Guid.NewGuid()));
        try{Assert.False(await Valid());}finally{await fixture.Execute("DELETE FROM agent_private.agent_database_bindings WHERE login_role=@role",new NpgsqlParameter("role",fixture.ProjectionDefinerRole));}
        await fixture.Execute("INSERT INTO agent_private.agent_database_bindings(login_role,environment_id,purpose) VALUES(@role,@env,'Ingest')",new NpgsqlParameter("role",fixture.ProjectionRole),new NpgsqlParameter("env",Guid.NewGuid()));
        try{Assert.False(await Valid());}finally{await fixture.Execute("DELETE FROM agent_private.agent_database_bindings WHERE login_role=@role",new NpgsqlParameter("role",fixture.ProjectionRole));}
    }

    [Fact]
    public async Task LateWrongEnvironmentProvisioningFailureRollsBackEarlierGrant()
    {
        await fixture.Execute($"REVOKE EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) FROM \"{fixture.ProjectionRole}\"");
        try
        {
            await Assert.ThrowsAsync<PostgresException>(()=>fixture.ReprovisionSeparately(Guid.NewGuid()));
            Assert.False(await fixture.Scalar<bool>("SELECT has_function_privilege(@role::name,'agent_private.read_current_bitlocker_projection(uuid,uuid)','EXECUTE')",new NpgsqlParameter("role",fixture.ProjectionRole)));
        }
        finally{await fixture.Execute($"GRANT EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) TO \"{fixture.ProjectionRole}\"");}
    }

    private Task<IAgentBitLockerProjectionReader> Create()=>PostgresAgentBitLockerProjectionReader.CreateAuditedAsync(fixture.Projection,fixture.EnvironmentId,fixture.TableOwnerRole,fixture.ProjectionDefinerRole);
}
