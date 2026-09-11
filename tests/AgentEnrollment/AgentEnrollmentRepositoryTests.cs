using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentIngestion;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.AgentEnrollment.Tests;

[Collection(AgentEnrollmentCollection.Name)]
public sealed class AgentEnrollmentRepositoryTests(AgentEnrollmentFixture fixture):IAsyncLifetime
{
    public Task InitializeAsync()=>fixture.ResetStateAsync();
    public Task DisposeAsync()=>Task.CompletedTask;
    [Fact]
    public async Task RolesExposeOnlyPurposeFunctionsAndOriginalIngestionAuditStillPasses()
    {
        var enrollAudit=await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default);
        var issueAudit=await new EnrollmentStorePrivilegeAuditor(fixture.IssueDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Issue").AuditAsync(default);
        Assert.True(enrollAudit.IsValid);Assert.True(issueAudit.IsValid);
        var ingestionAudit=await new AgentStorePrivilegeAuditor(fixture.IngestDataSource,fixture.TableOwnerRole).AuditAsync(default);
        Assert.True(ingestionAudit.IsValid,string.Join(',',ingestionAudit.Issues));
        await using var direct=fixture.EnrollDataSource.CreateCommand("SELECT count(*) FROM agent_private.enrollment_requests");
        Assert.Equal("42501",(await Assert.ThrowsAsync<PostgresException>(()=>direct.ExecuteScalarAsync())).SqlState);
        await fixture.ExecuteAsync($"GRANT EXECUTE ON FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) TO \"{fixture.IngestRole}\"");
        try{Assert.False((await new AgentStorePrivilegeAuditor(fixture.IngestDataSource,fixture.TableOwnerRole).AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync($"REVOKE EXECUTE ON FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) FROM \"{fixture.IngestRole}\"");}
        await fixture.ExecuteAsync($"GRANT EXECUTE ON FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) TO \"{fixture.EnrollRole}\"");
        try{var audit=await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default);Assert.False(audit.IsValid);Assert.Equal(EnrollmentDiagnosticCode.PrivilegeAuditFailed,audit.DiagnosticCode);}
        finally{await fixture.ExecuteAsync($"REVOKE EXECUTE ON FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) FROM \"{fixture.EnrollRole}\"");}
        await fixture.ExecuteAsync($"REVOKE EXECUTE ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) FROM \"{fixture.IssueRole}\"");
        try{Assert.False((await new EnrollmentStorePrivilegeAuditor(fixture.IssueDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Issue").AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync($"GRANT EXECUTE ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) TO \"{fixture.IssueRole}\"");}
        await fixture.ExecuteAsync($"REVOKE EXECUTE ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) FROM \"{fixture.IssueRole}\"");
        try
        {
            await Assert.ThrowsAsync<PostgresException>(()=>fixture.ProvisionForEnvironmentAsSeparateCommandsAsync(Guid.NewGuid()));
            Assert.False(await fixture.ScalarAsync<bool>("SELECT has_function_privilege(@role::name,'agent_private.defer_enrollment_issuance(uuid,uuid,integer)','EXECUTE')",new NpgsqlParameter("role",fixture.IssueRole)));
        }
        finally{await fixture.ExecuteAsync($"GRANT EXECUTE ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) TO \"{fixture.IssueRole}\"");}
        await fixture.ExecuteAsync($"GRANT CREATE ON SCHEMA agent_private TO \"{fixture.FunctionOwnerRole}\"");
        try{Assert.False((await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync($"REVOKE CREATE ON SCHEMA agent_private FROM \"{fixture.FunctionOwnerRole}\"");}
        await fixture.ExecuteAsync($"GRANT DELETE ON agent_private.enrollment_grants TO \"{fixture.FunctionOwnerRole}\"");
        try{Assert.False((await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync($"REVOKE DELETE ON agent_private.enrollment_grants FROM \"{fixture.FunctionOwnerRole}\"");}
        await fixture.ExecuteAsync($"GRANT UPDATE (device_id) ON agent_private.devices TO \"{fixture.FunctionOwnerRole}\"");
        try{Assert.False((await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync($"REVOKE UPDATE (device_id) ON agent_private.devices FROM \"{fixture.FunctionOwnerRole}\"");}
        await fixture.ExecuteAsync($"CREATE SEQUENCE agent_private.enrollment_audit_probe; GRANT USAGE ON SEQUENCE agent_private.enrollment_audit_probe TO \"{fixture.EnrollRole}\"");
        try{Assert.False((await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default)).IsValid);}
        finally{await fixture.ExecuteAsync("DROP SEQUENCE agent_private.enrollment_audit_probe");}
        await Assert.ThrowsAsync<PostgresException>(()=>fixture.ProvisionWithTableOwnerAsEnrollAsync());
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.EnrollDataSource,fixture.TableOwnerRole,fixture.FunctionOwnerRole,"Enroll").AuditAsync(default)).IsValid);
    }

    [Fact]
    public async Task SubmitConsumesGrantOnceAndExactRetrySurvivesExpiryWhileChangedTupleConflicts()
    {
        var grant=await fixture.SeedGrantAsync();var csr=CreateCsr();var request=Guid.NewGuid();var guid=Guid.NewGuid();var repository=Submitter();
        var first=await repository.SubmitOrRecoverAsync(Token(grant),request,guid,csr,default);
        await fixture.ExecuteAsync("UPDATE agent_private.enrollment_grants SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE grant_id=@grant",new NpgsqlParameter("grant",grant.GrantId));
        var retry=await repository.SubmitOrRecoverAsync(Token(grant),request,guid,csr,default);
        var conflict=await repository.SubmitOrRecoverAsync(Token(grant),Guid.NewGuid(),guid,csr,default);
        Assert.Equal(EnrollmentSubmissionOutcome.Pending,first.Outcome);Assert.Equal(first.Identity,retry.Identity);
        Assert.Equal(EnrollmentSubmissionOutcome.IdentityConflict,conflict.Outcome);
        Assert.Equal(1,await Count("enrollment_requests"));Assert.Equal(2,await DeviceNextEpoch(grant));
    }

    [Fact]
    public async Task InvalidTokenAndConcurrentExactSubmissionDoNotCreateExtraState()
    {
        var grant=await fixture.SeedGrantAsync();var csr=CreateCsr();var request=Guid.NewGuid();var guid=Guid.NewGuid();
        var invalid=await Submitter().SubmitOrRecoverAsync(EnrollmentBearerToken.FromBytes(RandomNumberGenerator.GetBytes(32)),request,guid,csr,default);
        Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected,invalid.Outcome);Assert.Equal(0,await Count("enrollment_requests"));
        var results=await Task.WhenAll(Submitter().SubmitOrRecoverAsync(Token(grant),request,guid,csr,default),
            Submitter().SubmitOrRecoverAsync(Token(grant),request,guid,csr,default));
        Assert.All(results,x=>Assert.Equal(EnrollmentSubmissionOutcome.Pending,x.Outcome));
        Assert.Equal(results[0].Identity,results[1].Identity);Assert.Equal(1,await Count("enrollment_requests"));
    }

    [Fact]
    public async Task ClaimReclaimsStableIssuanceAndUnknownNeverRequeues()
    {
        var context=await Pending();var issuer=Issuer();var worker=Guid.NewGuid();
        var first=await issuer.ClaimAsync(fixture.EnvironmentId,worker,default);Assert.Equal(IssuanceClaimOutcome.Claimed,first.Outcome);
        await fixture.ExecuteAsync("UPDATE agent_private.enrollment_requests SET lease_until=clock_timestamp()-interval '1 second' WHERE issuance_id=@issuance",new NpgsqlParameter("issuance",first.Claim!.IssuanceId));
        var reclaimed=await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default);
        Assert.Equal(first.Claim.IssuanceId,reclaimed.Claim!.IssuanceId);Assert.NotEqual(first.Claim.LeaseToken,reclaimed.Claim.LeaseToken);
        Assert.Equal(IssuanceMutationOutcome.OutcomeUnknown,(await issuer.MarkOutcomeUnknownAsync(reclaimed.Claim.IssuanceId,reclaimed.Claim.LeaseToken,default)).Outcome);
        Assert.Equal(IssuanceClaimOutcome.None,(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Outcome);
        Assert.Equal(EnrollmentSubmissionOutcome.RecoveryRequired,(await Submitter().SubmitOrRecoverAsync(Token(context.Grant),context.RequestId,context.DeviceGuid,context.Csr,default)).Outcome);
    }

    [Fact]
    public async Task DeferCapsRetryAndReclaimsTheSameIssuanceOnlyAfterDeadline()
    {
        var context=await Pending();var issuer=Issuer();var first=(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        Assert.Equal(IssuanceMutationOutcome.Deferred,(await issuer.DeferAsync(first.IssuanceId,first.LeaseToken,TimeSpan.FromDays(1),default)).Outcome);
        Assert.Equal(IssuanceMutationOutcome.RecoveryRequired,(await issuer.CompleteAsync(first.IssuanceId,first.LeaseToken,
            Certificate(context,first,RandomNumberGenerator.GetBytes(256)),default)).Outcome);
        Assert.Equal(IssuanceClaimOutcome.None,(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Outcome);
        var delay=await fixture.ScalarAsync<decimal>("SELECT extract(epoch FROM (next_attempt_at-clock_timestamp())) FROM agent_private.enrollment_requests WHERE issuance_id=@issuance",new NpgsqlParameter("issuance",first.IssuanceId));
        Assert.InRange(delay,3500m,3600m);
        await fixture.ExecuteAsync("UPDATE agent_private.enrollment_requests SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE issuance_id=@issuance",new NpgsqlParameter("issuance",first.IssuanceId));
        var reclaimed=(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        Assert.Equal(context.Identity.IssuanceId,reclaimed.IssuanceId);Assert.NotEqual(first.LeaseToken,reclaimed.LeaseToken);
    }

    [Fact]
    public async Task ExpiredLeaseCannotMarkUnknownOrDefinitivelyFail()
    {
        await Pending();var issuer=Issuer();var claim=(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        await fixture.ExecuteAsync("UPDATE agent_private.enrollment_requests SET lease_until=clock_timestamp()-interval '1 second' WHERE issuance_id=@issuance",new NpgsqlParameter("issuance",claim.IssuanceId));
        var unknown=await issuer.MarkOutcomeUnknownAsync(claim.IssuanceId,claim.LeaseToken,default);
        var failed=await issuer.FailDefinitivelyAsync(claim.IssuanceId,claim.LeaseToken,DefinitiveIssuanceFailure.FromValidatedAdapterResult(),default);
        Assert.Equal(IssuanceMutationOutcome.RecoveryRequired,unknown.Outcome);Assert.Equal(EnrollmentDiagnosticCode.LeaseUnavailable,unknown.DiagnosticCode);
        Assert.Equal(IssuanceMutationOutcome.RecoveryRequired,failed.Outcome);Assert.Equal(EnrollmentDiagnosticCode.LeaseUnavailable,failed.DiagnosticCode);
        Assert.Equal(IssuanceClaimOutcome.Claimed,(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Outcome);
    }

    [Fact]
    public async Task NullCompletionEpochOrProfileIsRejectedBeforeWrites()
    {
        var context=await Pending();var claim=(await Issuer().ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        var certificate=Certificate(context,claim,RandomNumberGenerator.GetBytes(256));
        Assert.Equal("PermanentRejected",await RawCompleteOutcome(claim,certificate,null,1));
        Assert.Equal("PermanentRejected",await RawCompleteOutcome(claim,certificate,claim.RegistrationEpoch,null));
        Assert.Equal(0,await Count("registrations"));Assert.Equal(0,await Count("certificate_bindings"));Assert.Equal(0,await Count("enrollment_results"));
    }

    [Fact]
    public async Task NullSubmissionProfileIsRejectedBeforeWrites()
    {
        var grant=await fixture.SeedGrantAsync();var csr=CreateCsr();
        await using var command=fixture.EnrollDataSource.CreateCommand("SELECT outcome FROM agent_private.submit_or_recover_enrollment(@token,@request,@device_guid,@csr,@csr_hash,@spki_hash,@profile)");
        command.Parameters.AddWithValue("token",grant.Token);command.Parameters.AddWithValue("request",Guid.NewGuid());command.Parameters.AddWithValue("device_guid",Guid.NewGuid());
        command.Parameters.AddWithValue("csr",csr.GetDer());command.Parameters.AddWithValue("csr_hash",csr.GetCsrSha256());command.Parameters.AddWithValue("spki_hash",csr.GetSubjectPublicKeyInfoSha256());
        command.Parameters.Add(new NpgsqlParameter("profile",NpgsqlDbType.Integer){Value=DBNull.Value});
        Assert.Equal("PermanentRejected",(string)(await command.ExecuteScalarAsync())!);Assert.Equal(0,await Count("enrollment_requests"));Assert.Equal(1,await DeviceNextEpoch(grant));
    }

    [Fact]
    public async Task CompletionIsAtomicAndExactReplayReturnsStoredCertificate()
    {
        var context=await Pending();var issuer=Issuer();var claim=(await issuer.ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        var certificate=Certificate(context,claim,RandomNumberGenerator.GetBytes(256));
        var wrongIdentityCertificate=Certificate(context,claim,RandomNumberGenerator.GetBytes(256),Guid.NewGuid());
        Assert.Equal(IssuanceMutationOutcome.IdentityConflict,(await issuer.CompleteAsync(claim.IssuanceId,claim.LeaseToken,wrongIdentityCertificate,default)).Outcome);
        Assert.Equal(0,await Count("registrations"));Assert.Equal(0,await Count("certificate_bindings"));Assert.Equal(0,await Count("enrollment_results"));
        var completed=await issuer.CompleteAsync(claim.IssuanceId,claim.LeaseToken,certificate,default);
        var replay=await issuer.CompleteAsync(claim.IssuanceId,Guid.NewGuid(),certificate,default);
        var mismatch=await issuer.CompleteAsync(claim.IssuanceId,Guid.NewGuid(),Certificate(context,claim,RandomNumberGenerator.GetBytes(256)),default);
        Assert.Equal(IssuanceMutationOutcome.Completed,completed.Outcome);Assert.Equal(IssuanceMutationOutcome.AlreadyCompleted,replay.Outcome);
        Assert.Equal(completed.Identity,replay.Identity);Assert.Equal(completed.Certificate!.BindingId,replay.Certificate!.BindingId);
        Assert.Equal(IssuanceMutationOutcome.IdentityConflict,mismatch.Outcome);
        Assert.Equal(1,await Count("registrations"));Assert.Equal(1,await Count("certificate_bindings"));Assert.Equal(1,await Count("enrollment_results"));
        Assert.Equal(EnrollmentSubmissionOutcome.Issued,(await Submitter().SubmitOrRecoverAsync(Token(context.Grant),context.RequestId,context.DeviceGuid,context.Csr,default)).Outcome);
    }

    [Fact]
    public async Task FailedEnrollmentBurnsEpochAndNextGrantReservesNextEpoch()
    {
        var grant=await fixture.SeedGrantAsync();var deviceGuid=Guid.NewGuid();
        await fixture.ExecuteAsync("INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state,revoked_at) VALUES(@environment,@registration,@device,5,@guid,'Revoked',clock_timestamp())",
            new NpgsqlParameter("environment",grant.EnvironmentId),new NpgsqlParameter("registration",Guid.NewGuid()),new NpgsqlParameter("device",grant.DeviceId),new NpgsqlParameter("guid",Guid.NewGuid()));
        var csr=CreateCsr();var request=Guid.NewGuid();var submitted=await Submitter().SubmitOrRecoverAsync(Token(grant),request,deviceGuid,csr,default);
        Assert.Equal(6,submitted.Identity!.RegistrationEpoch);
        var first=new PendingContext(grant,csr,request,deviceGuid,submitted.Identity);var claim=(await Issuer().ClaimAsync(fixture.EnvironmentId,Guid.NewGuid(),default)).Claim!;
        var proof=DefinitiveIssuanceFailure.FromValidatedAdapterResult();
        Assert.Equal(IssuanceMutationOutcome.PermanentFailed,(await Issuer().FailDefinitivelyAsync(claim.IssuanceId,claim.LeaseToken,proof,default)).Outcome);
        var nextGrant=await fixture.SeedGrantAsync(first.Grant.DeviceId);var nextCsr=CreateCsr();
        var next=await Submitter().SubmitOrRecoverAsync(Token(nextGrant),Guid.NewGuid(),first.DeviceGuid,nextCsr,default);
        Assert.Equal(7,next.Identity!.RegistrationEpoch);Assert.Equal(8,await DeviceNextEpoch(nextGrant));
    }

    [Fact]
    public async Task EnvironmentBindingsCannotBeSpoofedAcrossEnrollmentOrIssuance()
    {
        var otherEnvironment=Guid.NewGuid();var grant=await fixture.SeedGrantAsync(environmentId:otherEnvironment);var csr=CreateCsr();
        var submission=await Submitter().SubmitOrRecoverAsync(Token(grant),Guid.NewGuid(),Guid.NewGuid(),csr,default);
        Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected,submission.Outcome);Assert.Equal(EnrollmentDiagnosticCode.AuthenticationFailed,submission.DiagnosticCode);
        Assert.Equal(IssuanceClaimOutcome.Unauthorized,(await Issuer().ClaimAsync(otherEnvironment,Guid.NewGuid(),default)).Outcome);
        Assert.Equal(0,await Count("enrollment_requests"));Assert.Equal(1,await DeviceNextEpoch(grant));
    }

    [Fact]
    public async Task ConcurrentDifferentRequestForOneGrantHasOneWinnerAndNoExtraState()
    {
        var grant=await fixture.SeedGrantAsync();var csr=CreateCsr();var guid=Guid.NewGuid();
        var results=await Task.WhenAll(Submitter().SubmitOrRecoverAsync(Token(grant),Guid.NewGuid(),guid,csr,default),
            Submitter().SubmitOrRecoverAsync(Token(grant),Guid.NewGuid(),guid,csr,default));
        Assert.Single(results,x=>x.Outcome==EnrollmentSubmissionOutcome.Pending);
        Assert.Single(results,x=>x.Outcome==EnrollmentSubmissionOutcome.IdentityConflict);
        Assert.Equal(1,await Count("enrollment_requests"));Assert.Equal(2,await DeviceNextEpoch(grant));
    }

    [Fact]
    public async Task ExpiredOrRevokedGrantAndActiveRegistrationRejectWithoutWrites()
    {
        var csr=CreateCsr();
        var expired=await fixture.SeedGrantAsync(expires:DateTimeOffset.UtcNow.AddMinutes(-1));
        Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected,(await Submitter().SubmitOrRecoverAsync(Token(expired),Guid.NewGuid(),Guid.NewGuid(),csr,default)).Outcome);
        var revoked=await fixture.SeedGrantAsync();
        await fixture.ExecuteAsync("UPDATE agent_private.enrollment_grants SET state='Revoked',revoked_at=clock_timestamp() WHERE grant_id=@grant",new NpgsqlParameter("grant",revoked.GrantId));
        Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected,(await Submitter().SubmitOrRecoverAsync(Token(revoked),Guid.NewGuid(),Guid.NewGuid(),csr,default)).Outcome);
        var active=await fixture.SeedGrantAsync();
        await fixture.ExecuteAsync("INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state) VALUES(@environment,@registration,@device,1,@guid,'Active')",
            new NpgsqlParameter("environment",active.EnvironmentId),new NpgsqlParameter("registration",Guid.NewGuid()),new NpgsqlParameter("device",active.DeviceId),new NpgsqlParameter("guid",Guid.NewGuid()));
        Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected,(await Submitter().SubmitOrRecoverAsync(Token(active),Guid.NewGuid(),Guid.NewGuid(),csr,default)).Outcome);
        Assert.Equal(0,await Count("enrollment_requests"));
    }

    private EnrollmentSubmissionRepository Submitter()=>new(fixture.EnrollDataSource);private EnrollmentIssuanceRepository Issuer()=>new(fixture.IssueDataSource);
    private static EnrollmentBearerToken Token(TestGrant grant)=>EnrollmentBearerToken.FromBytes(grant.Token);
    private async Task<PendingContext> Pending(){var grant=await fixture.SeedGrantAsync();var csr=CreateCsr();var request=Guid.NewGuid();var guid=Guid.NewGuid();
      var result=await Submitter().SubmitOrRecoverAsync(Token(grant),request,guid,csr,default);Assert.Equal(EnrollmentSubmissionOutcome.Pending,result.Outcome);return new(grant,csr,request,guid,result.Identity!);}
    private static ValidatedEnrollmentCsr CreateCsr(){using var rsa=RSA.Create(3072);var request=new CertificateRequest("CN=Ignored",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);return EnrollmentCsrValidator.Validate(request.CreateSigningRequest());}
    private static ValidatedIssuedEnrollmentCertificate Certificate(PendingContext context,IssuanceClaim claim,byte[] leaf,Guid? registrationId=null)=>new(
      leaf,[],context.Csr.GetSubjectPublicKeyInfoSha256(),[1],RandomNumberGenerator.GetBytes(32),DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(30),
      new EnrollmentCertificateIdentity(context.Grant.EnvironmentId,context.Grant.DeviceId,registrationId??claim.RegistrationId,context.DeviceGuid,claim.RegistrationEpoch));
    private Task<long> Count(string table)=>fixture.ScalarAsync<long>($"SELECT count(*) FROM agent_private.{table}");
    private Task<long> DeviceNextEpoch(TestGrant grant)=>fixture.ScalarAsync<long>("SELECT next_registration_epoch FROM agent_private.devices WHERE environment_id=@environment AND device_id=@device",new NpgsqlParameter("environment",grant.EnvironmentId),new NpgsqlParameter("device",grant.DeviceId));
    private async Task<string> RawCompleteOutcome(IssuanceClaim claim,ValidatedIssuedEnrollmentCertificate certificate,long? epoch,int? profile)
    {
        await using var command=fixture.IssueDataSource.CreateCommand("""
          SELECT outcome FROM agent_private.complete_enrollment_issuance(@issuance,@lease,@environment,@device,@registration,
            @device_guid,@epoch,@profile,@leaf,@intermediates,@leaf_hash,@spki_hash,@serial,@not_before,@not_after)
          """);
        command.Parameters.AddWithValue("issuance",claim.IssuanceId);command.Parameters.AddWithValue("lease",claim.LeaseToken);
        command.Parameters.AddWithValue("environment",fixture.EnvironmentId);command.Parameters.AddWithValue("device",claim.DeviceId);
        command.Parameters.AddWithValue("registration",claim.RegistrationId);command.Parameters.AddWithValue("device_guid",claim.DeviceGuid);
        command.Parameters.Add(new NpgsqlParameter("epoch",NpgsqlDbType.Bigint){Value=epoch.HasValue?epoch.Value:DBNull.Value});
        command.Parameters.Add(new NpgsqlParameter("profile",NpgsqlDbType.Integer){Value=profile.HasValue?profile.Value:DBNull.Value});
        command.Parameters.AddWithValue("leaf",certificate.GetLeafDer());command.Parameters.AddWithValue("intermediates",NpgsqlDbType.Array|NpgsqlDbType.Bytea,certificate.GetIntermediateDer());
        command.Parameters.AddWithValue("leaf_hash",certificate.GetLeafSha256());command.Parameters.AddWithValue("spki_hash",certificate.GetSubjectPublicKeyInfoSha256());
        command.Parameters.AddWithValue("serial",certificate.GetSerialNumber());command.Parameters.AddWithValue("not_before",certificate.NotBefore);command.Parameters.AddWithValue("not_after",certificate.NotAfter);
        return (string)(await command.ExecuteScalarAsync())!;
    }
    private sealed record PendingContext(TestGrant Grant,ValidatedEnrollmentCsr Csr,Guid RequestId,Guid DeviceGuid,EnrollmentIdentity Identity);
}
