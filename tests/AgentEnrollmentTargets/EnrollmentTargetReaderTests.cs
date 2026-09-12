using ItManagement.AgentEnrollmentTargets;
using ItManagement.AgentEnrollment;
using ItManagement.AgentIngestion;
using ItManagement.AgentPlatformGrants;
using ItManagement.AgentProjection;
using Npgsql;

namespace ItManagement.AgentEnrollmentTargets.Tests;

[Collection(EnrollmentTargetCollection.Name)]
public sealed class EnrollmentTargetReaderTests(AgentEnrollmentTargetFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.Reset();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AuditBaselineIsValid()
    {
        await using var command = fixture.Target.CreateCommand("SELECT is_valid,diagnostic_code,profile_version FROM agent_private.audit_enrollment_target_read_privileges(@env,@owner::name,@definer::name)");
        command.Parameters.AddWithValue("env", fixture.EnvironmentId); command.Parameters.AddWithValue("owner", fixture.TableOwnerRole); command.Parameters.AddWithValue("definer", fixture.TargetDefinerRole);
        await using var reader = await command.ExecuteReaderAsync(); Assert.True(await reader.ReadAsync());
        Assert.True(reader.GetBoolean(0)); Assert.Equal("None", reader.GetString(1)); Assert.Equal(1, reader.GetInt16(2)); Assert.False(await reader.ReadAsync());
    }

    [Fact]
    public async Task ReadsActiveMapping()
    {
        var mapping = await fixture.SeedMapping();
        var reader = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.TargetDefinerRole, default);

        var result = await reader.ReadAsync(mapping.EnvironmentId, mapping.DirectoryObjectId, default);

        Assert.Equal(EnrollmentTargetState.Resolved, result.State);
        Assert.Equal(EnrollmentTargetDiagnostic.None, result.Diagnostic);
        Assert.Equal(mapping.DeviceId, result.DeviceId);
        Assert.Equal(mapping.MappingCreatedAt, result.MappingCreatedAt);
    }

    [Fact]
    public async Task MissingAndInactiveMappingsRequireMapping()
    {
        var reader = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
        var missing = await reader.ReadAsync(fixture.EnvironmentId, Guid.NewGuid(), default);
        var inactiveMapping = await fixture.SeedMapping("Disabled");
        var inactive = await reader.ReadAsync(fixture.EnvironmentId, inactiveMapping.DirectoryObjectId, default);

        Assert.Equal((EnrollmentTargetState.MappingRequired, EnrollmentTargetDiagnostic.MappingMissing), (missing.State, missing.Diagnostic));
        Assert.Equal((EnrollmentTargetState.MappingRequired, EnrollmentTargetDiagnostic.DeviceInactive), (inactive.State, inactive.Diagnostic));
        Assert.Null(missing.DeviceId); Assert.Null(missing.MappingCreatedAt);
        Assert.Null(inactive.DeviceId); Assert.Null(inactive.MappingCreatedAt);
    }

    [Fact]
    public async Task WrongEnvironmentFailsClosedInReaderAndSql()
    {
        var other = Guid.NewGuid();
        var reader = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
        var result = await reader.ReadAsync(other, Guid.NewGuid(), default);
        Assert.Equal(EnrollmentTargetDiagnostic.PrivilegeAuditFailed, result.Diagnostic);

        await using var command = fixture.Target.CreateCommand("SELECT outcome,diagnostic_code,environment_id,directory_object_id,device_id,mapping_created_at FROM agent_private.resolve_enrollment_target(@env,@directory)");
        command.Parameters.AddWithValue("env", other); command.Parameters.AddWithValue("directory", Guid.NewGuid());
        await using var db = await command.ExecuteReaderAsync(); Assert.True(await db.ReadAsync());
        Assert.Equal("Unauthorized", db.GetString(0)); Assert.Equal("PrivilegeAuditFailed", db.GetString(1));
        for (var index = 2; index < 6; index++) Assert.True(db.IsDBNull(index));
        Assert.False(await db.ReadAsync());
    }

    [Fact]
    public async Task RuntimeHasNoDirectTableAccess()
    {
        await using var command = fixture.Target.CreateCommand("SELECT count(*) FROM agent_private.devices");
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Fact]
    public void StrictMatrixRejectsMalformedRows()
    {
        var env = Guid.NewGuid(); var directory = Guid.NewGuid(); var device = Guid.NewGuid();
        var malformed = new EnrollmentTargetDatabaseResult("Resolved", "None", env, directory, null, DateTimeOffset.UtcNow);
        var result = PostgresEnrollmentTargetReader.Normalize(malformed, env, directory);
        Assert.Equal(EnrollmentTargetState.Unavailable, result.State);
        Assert.Equal(EnrollmentTargetDiagnostic.ResponseUnavailable, result.Diagnostic);

        var unauthorizedWithData = new EnrollmentTargetDatabaseResult("Unauthorized", "PrivilegeAuditFailed", env, null, device, null);
        Assert.Equal(EnrollmentTargetDiagnostic.ResponseUnavailable,
            PostgresEnrollmentTargetReader.Normalize(unauthorizedWithData, env, directory).Diagnostic);
    }

    [Fact]
    public async Task InvalidIdentifiersReturnClosedResult()
    {
        var reader = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
        var result = await reader.ReadAsync(fixture.EnvironmentId, Guid.Empty, default);
        Assert.Equal(EnrollmentTargetDiagnostic.InvalidDirectoryObject, result.Diagnostic);
        Assert.Equal(EnrollmentTargetState.Unavailable, result.State);
    }

    [Fact]
    public async Task EveryInstalledRuntimeAuditPassesAfterCapabilityUpgrade()
    {
        Assert.True((await new AgentStorePrivilegeAuditor(fixture.Ingest, fixture.TableOwnerRole).AuditAsync(default)).IsValid);
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.Enroll, fixture.TableOwnerRole, fixture.EnrollmentDefinerRole, "Enroll").AuditAsync(default)).IsValid);
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.Issue, fixture.TableOwnerRole, fixture.EnrollmentDefinerRole, "Issue").AuditAsync(default)).IsValid);
        _ = await PostgresAgentInventoryProjectionReader.CreateAuditedAsync(fixture.Projection, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.ProjectionDefinerRole);
        _ = await PostgresPlatformGrantRepository.CreateAuditedAsync(fixture.Platform, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, default);
        _ = await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(fixture.Revoker, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, default);
        _ = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
    }

    [Fact]
    public async Task MissingRuntimeReservationFailsAuditAndCanBeRepaired()
    {
        await fixture.Execute("DELETE FROM agent_private.agent_capability_roles WHERE role_name=@role::name", new NpgsqlParameter("role", fixture.TargetRole));
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresEnrollmentTargetReader.CreateAuditedAsync(
                fixture.Target, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.TargetDefinerRole, default));
        }
        finally
        {
            await fixture.Execute("INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES(@role::name,'EnrollmentTargetRead','Runtime')", new NpgsqlParameter("role", fixture.TargetRole));
        }
    }

    [Fact]
    public async Task MultipleEnvironmentLoginsShareOnlyTheExactFunctions()
    {
        var additional = await fixture.AddTargetEnvironment();
        _ = await PostgresEnrollmentTargetReader.CreateAuditedAsync(fixture.Target, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
        var reader = await PostgresEnrollmentTargetReader.CreateAuditedAsync(additional.DataSource, additional.EnvironmentId, fixture.TableOwnerRole, fixture.TargetDefinerRole, default);
        var missing = await reader.ReadAsync(additional.EnvironmentId, Guid.NewGuid(), default);
        Assert.Equal(EnrollmentTargetDiagnostic.MappingMissing, missing.Diagnostic);
        await using var direct = additional.DataSource.CreateCommand("SELECT count(*) FROM agent_private.enrollment_target_read_database_bindings");
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, (await Assert.ThrowsAsync<PostgresException>(() => direct.ExecuteScalarAsync())).SqlState);
    }

    [Fact]
    public async Task ConnectionFailureUsesDedicatedDiagnostic()
    {
        await using var unavailable = NpgsqlDataSource.Create("Host=127.0.0.1;Port=1;Database=console_test;Username=none;Password=none;Timeout=1;Pooling=false");
        var reader = new PostgresEnrollmentTargetReader(unavailable, fixture.EnvironmentId);
        var result = await reader.ReadAsync(fixture.EnvironmentId, Guid.NewGuid(), default);
        Assert.Equal(EnrollmentTargetDiagnostic.ConnectionUnavailable, result.Diagnostic);
    }

    [Fact]
    public async Task RegistryPrimaryKeyAndDuplicateCapabilityDriftFailsClosed()
    {
        await fixture.Execute("ALTER TABLE agent_private.agent_capability_roles DROP CONSTRAINT agent_capability_roles_pkey; INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES(@role::name,'Projection','Runtime')", new NpgsqlParameter("role", fixture.TargetRole));
        try { Assert.False(await TargetAudit()); }
        finally
        {
            await fixture.Execute("DELETE FROM agent_private.agent_capability_roles WHERE role_name=@role::name AND capability='Projection'; ALTER TABLE agent_private.agent_capability_roles ADD PRIMARY KEY(role_name)", new NpgsqlParameter("role", fixture.TargetRole));
        }
    }

    [Fact]
    public async Task RegistryExtraPolicyFailsClosed()
    {
        await fixture.Execute($"CREATE POLICY unexpected_registry_policy ON agent_private.agent_capability_roles FOR SELECT TO {Quote(fixture.TableOwnerRole)} USING(true)");
        try { Assert.False(await TargetAudit()); }
        finally { await fixture.Execute("DROP POLICY unexpected_registry_policy ON agent_private.agent_capability_roles"); }
    }

    [Fact]
    public async Task RegistryCannotReserveSharedOwnerAsDefiner()
    {
        await fixture.Execute("INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES(@owner::name,'EnrollmentTargetRead','Definer')", new NpgsqlParameter("owner", fixture.TableOwnerRole));
        try { Assert.False(await TargetAudit()); }
        finally { await fixture.Execute("DELETE FROM agent_private.agent_capability_roles WHERE role_name=@owner::name", new NpgsqlParameter("owner", fixture.TableOwnerRole)); }
    }

    [Fact]
    public async Task TargetBindingPrimaryKeyAndDuplicateLoginDriftFailsClosed()
    {
        await fixture.Execute("ALTER TABLE agent_private.enrollment_target_read_database_bindings DROP CONSTRAINT enrollment_target_read_database_bindings_pkey; INSERT INTO agent_private.enrollment_target_read_database_bindings(login_role,environment_id,purpose) VALUES(@role::name,@env,'ResolveEnrollmentTarget')", new NpgsqlParameter("role", fixture.TargetRole), new NpgsqlParameter("env", Guid.NewGuid()));
        try { Assert.False(await TargetAudit()); }
        finally
        {
            await fixture.Execute("DELETE FROM agent_private.enrollment_target_read_database_bindings WHERE login_role=@role::name AND environment_id<>@env; ALTER TABLE agent_private.enrollment_target_read_database_bindings ADD PRIMARY KEY(login_role)", new NpgsqlParameter("role", fixture.TargetRole), new NpgsqlParameter("env", fixture.EnvironmentId));
        }
    }

    [Fact]
    public async Task DefinerGrantOptionDriftFailsClosed()
    {
        await fixture.Execute($"GRANT SELECT(environment_id) ON agent_private.enrollment_target_read_database_bindings TO {Quote(fixture.TargetDefinerRole)} WITH GRANT OPTION");
        try { Assert.False(await TargetAudit()); }
        finally
        {
            await fixture.Execute($"REVOKE SELECT(environment_id) ON agent_private.enrollment_target_read_database_bindings FROM {Quote(fixture.TargetDefinerRole)}; GRANT SELECT(environment_id) ON agent_private.enrollment_target_read_database_bindings TO {Quote(fixture.TargetDefinerRole)}");
        }
    }

    [Fact]
    public async Task ExtraTargetPolicyDriftFailsClosed()
    {
        await fixture.Execute($"CREATE POLICY unexpected_target_policy ON agent_private.enrollment_target_read_database_bindings FOR SELECT TO {Quote(fixture.TargetDefinerRole)} USING(true)");
        try { Assert.False(await TargetAudit()); }
        finally { await fixture.Execute("DROP POLICY unexpected_target_policy ON agent_private.enrollment_target_read_database_bindings"); }
    }

    private async Task<bool> TargetAudit()
    {
        await using var command = fixture.Target.CreateCommand("SELECT is_valid FROM agent_private.audit_enrollment_target_read_privileges(@env,@owner::name,@definer::name)");
        command.Parameters.AddWithValue("env", fixture.EnvironmentId); command.Parameters.AddWithValue("owner", fixture.TableOwnerRole); command.Parameters.AddWithValue("definer", fixture.TargetDefinerRole);
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    private static string Quote(string role) => $"\"{role.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
}
