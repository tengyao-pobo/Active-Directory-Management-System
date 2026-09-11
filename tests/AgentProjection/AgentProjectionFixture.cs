using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;

namespace ItManagement.AgentProjection.Tests;

[CollectionDefinition(Name,DisableParallelization=true)]
public sealed class AgentProjectionCollection:ICollectionFixture<AgentProjectionFixture>{public const string Name="Agent projection database";}

public sealed partial class AgentProjectionFixture:IAsyncLifetime
{
    private const long LockKey=7912040301;
    private readonly string _connectionString=Environment.GetEnvironmentVariable("AGENT_PROJECTION_TEST_DB")??Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")??
        throw new InvalidOperationException("AGENT_PROJECTION_TEST_DB or CONSOLE_TEST_DB is required.");
    private readonly string _suffix=Guid.NewGuid().ToString("N")[..12];private NpgsqlConnection? _lease;private bool _rolesCreated,_disposed;
    private string _ingestPassword=null!,_enrollPassword=null!,_issuePassword=null!,_projectionPassword=null!;
    public string TableOwnerRole=>$"ap_tbl_{_suffix}";public string IngestRole=>$"ap_ing_{_suffix}";public string EnrollmentDefinerRole=>$"ap_enf_{_suffix}";public string UnsafeDefinerRole=>$"ap_bad_{_suffix}";
    public string EnrollRole=>$"ap_enr_{_suffix}";public string IssueRole=>$"ap_iss_{_suffix}";public string ProjectionDefinerRole=>$"ap_prf_{_suffix}";public string ProjectionRole=>$"ap_pro_{_suffix}";
    public Guid EnvironmentId{get;}=Guid.NewGuid();public bool UnsafeStoreRollbackVerified{get;private set;}public NpgsqlDataSource Owner{get;private set;}=null!;public NpgsqlDataSource Projection{get;private set;}=null!;
    public NpgsqlDataSource Ingest{get;private set;}=null!;public NpgsqlDataSource Enroll{get;private set;}=null!;public NpgsqlDataSource Issue{get;private set;}=null!;
    public async Task InitializeAsync()
    {
        var builder=new NpgsqlConnectionStringBuilder(_connectionString);Validate(builder);
        try
        {
            Owner=NpgsqlDataSource.Create(builder.ConnectionString);_lease=new NpgsqlConnection(new NpgsqlConnectionStringBuilder(builder.ConnectionString){Pooling=false}.ConnectionString);
            await _lease.OpenAsync();await using(var command=new NpgsqlCommand("SELECT pg_catalog.pg_advisory_lock(@key)",_lease){CommandTimeout=120})
            {command.Parameters.AddWithValue("key",LockKey);await command.ExecuteNonQueryAsync();}
            if(await Scalar<long>("SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='agent_private'")!=0)throw new InvalidOperationException("agent_private already exists; refusing to overwrite state.");
            _ingestPassword=Secret();_enrollPassword=Secret();_issuePassword=Secret();_projectionPassword=Secret();
            await Execute($"""
              BEGIN;
              CREATE ROLE {Id(TableOwnerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(IngestRole)} LOGIN PASSWORD {Lit(_ingestPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(EnrollmentDefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(EnrollRole)} LOGIN PASSWORD {Lit(_enrollPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(IssueRole)} LOGIN PASSWORD {Lit(_issuePassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(ProjectionDefinerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(ProjectionRole)} LOGIN PASSWORD {Lit(_projectionPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(UnsafeDefinerRole)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              COMMIT;
              """);_rolesCreated=true;var database=builder.Database!;
            await Script("agent-store.sql",new(){[":\"agent_definer_role\""]=Id(TableOwnerRole)});
            await Script("provision-agent-store.sql",new(){[":\"agent_definer_role\""]=Id(TableOwnerRole),[":\"agent_ingest_role\""]=Id(IngestRole),[":'agent_definer_role'"]=Lit(TableOwnerRole),[":'agent_ingest_role'"]=Lit(IngestRole),[":'environment_id'"]=Lit(EnvironmentId.ToString()),[":DBNAME"]=Id(database)});
            await Script("agent-enrollment-store.sql",new(){[":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(EnrollmentDefinerRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),[":'agent_enrollment_definer_role'"]=Lit(EnrollmentDefinerRole)});
            await Script("provision-agent-enrollment.sql",new(){[":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(EnrollmentDefinerRole),[":\"agent_enroll_role\""]=Id(EnrollRole),[":\"agent_issue_role\""]=Id(IssueRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),[":'agent_enrollment_definer_role'"]=Lit(EnrollmentDefinerRole),[":'agent_enroll_role'"]=Lit(EnrollRole),[":'agent_issue_role'"]=Lit(IssueRole),[":'environment_id'"]=Lit(EnvironmentId.ToString()),[":DBNAME"]=Id(database)});
            await VerifyUnsafeStoreRollback();
            await Script("agent-projection-store.sql",ProjectionStoreReplacements());await Script("provision-agent-projection.sql",ProjectionProvisionReplacements(EnvironmentId));
            Projection=DataSource(builder,ProjectionRole,_projectionPassword);Ingest=DataSource(builder,IngestRole,_ingestPassword);Enroll=DataSource(builder,EnrollRole,_enrollPassword);Issue=DataSource(builder,IssueRole,_issuePassword);
        }
        catch{await DisposeAsync();throw;}
    }
    public async Task<TestProjectionSeed> Seed(string? payload=null,string deviceState="Active",string registrationState="Active",long epoch=1)
    {
        var seed=new TestProjectionSeed(EnvironmentId,Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),epoch);
        payload??=ValidPayload();await Execute("""
          INSERT INTO agent_private.devices(environment_id,device_id,state,last_seen_at) VALUES(@env,@device,@device_state,clock_timestamp()-interval '2 minutes');
          INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state) VALUES(@env,@registration,@device,@epoch,@device_guid,@registration_state);
          INSERT INTO agent_private.certificate_bindings(environment_id,binding_id,registration_id,leaf_der_sha256,state,not_before,not_after) VALUES(@env,@binding,@registration,@fingerprint,'Active',clock_timestamp()-interval '1 day',clock_timestamp()+interval '1 day');
          INSERT INTO agent_private.receipts(environment_id,registration_id,registration_epoch,sequence,receipt_id,device_id,binding_id,hash_version,protocol_version,device_guid,request_id,observed_utc_ticks,received_at,payload_hash,envelope_hash,kind,schema_version)
          VALUES(@env,@registration,@epoch,1,@receipt,@device,@binding,2,1,@device_guid,@request,0,clock_timestamp()-interval '1 minute',repeat('a',64),repeat('b',64),1,1);
          INSERT INTO agent_private.inventory_projection(environment_id,device_id,registration_id,registration_epoch,sequence,receipt_id,normalized_payload) VALUES(@env,@device,@registration,@epoch,1,@receipt,@payload::jsonb);
          INSERT INTO agent_private.agent_device_directory_bindings(environment_id,directory_object_id,device_id,creation_source) VALUES(@env,@directory,@device,'OwnerProvisioning');
          """,P("env",seed.EnvironmentId),P("device",seed.DeviceId),P("device_state",deviceState),P("registration",seed.RegistrationId),P("epoch",epoch),P("device_guid",Guid.NewGuid()),P("registration_state",registrationState),P("binding",Guid.NewGuid()),P("fingerprint",RandomNumberGenerator.GetBytes(32)),P("receipt",seed.ReceiptId),P("request",Guid.NewGuid()),P("payload",payload),P("directory",seed.DirectoryObjectId));return seed;
    }
    public static string ValidPayload(bool truncated=false,uint protection=uint.MaxValue)=>JsonSerializer.Serialize(new{SchemaVersion=1,CollectedAt=DateTimeOffset.Parse("2026-01-02T03:04:05Z"),Collectors=new[]{new{Collector="bitlocker",Status=0,Quality=0,Source=@"root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume",ObservedAt=DateTimeOffset.Parse("2026-01-02T03:03:05Z"),Data=new{SchemaVersion=1,Volumes=new[]{new{DeviceId="synthetic-volume",PersistentVolumeId="",DriveLetter="C:",VolumeType=(uint?)0,ProtectionStatus=(uint?)protection,ConversionStatus=(uint?)1,EncryptionMethod=(uint?)6,IsVolumeInitializedForProtection=(bool?)true}},IsTruncated=truncated,ErrorCode=(string?)null},ItemCount=1,ErrorCode=(string?)null}}});
    public async Task Execute(string sql,params NpgsqlParameter[] parameters){await using var command=Owner.CreateCommand(sql);command.Parameters.AddRange(parameters);await command.ExecuteNonQueryAsync();}
    public async Task<T> Scalar<T>(string sql,params NpgsqlParameter[] parameters){await using var command=Owner.CreateCommand(sql);command.Parameters.AddRange(parameters);return (T)(await command.ExecuteScalarAsync())!;}
    public async Task ReprovisionSeparately(Guid environment)
    {var script=await Render("provision-agent-projection.sql",ProjectionProvisionReplacements(environment));await using var connection=await Owner.OpenConnectionAsync();try{foreach(var statement in script.Split(';',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)){await using var command=new NpgsqlCommand(statement,connection);await command.ExecuteNonQueryAsync();}}catch{await using var rollback=new NpgsqlCommand("ROLLBACK",connection);await rollback.ExecuteNonQueryAsync();throw;}}
    public async Task ReprovisionWithTableOwnerAsLogin()
    {var replacements=ProjectionProvisionReplacements(EnvironmentId);replacements[":\"agent_projection_role\""]=Id(TableOwnerRole);replacements[":'agent_projection_role'"]=Lit(TableOwnerRole);await Execute(await Render("provision-agent-projection.sql",replacements));}
    public async Task ReprovisionWithEnrollmentDefinerAlias()
    {var replacements=ProjectionProvisionReplacements(EnvironmentId);replacements[":\"agent_projection_definer_role\""]=Id(EnrollmentDefinerRole);replacements[":'agent_projection_definer_role'"]=Lit(EnrollmentDefinerRole);await Execute(await Render("provision-agent-projection.sql",replacements));}
    private async Task VerifyUnsafeStoreRollback()
    {
        var replacements=ProjectionStoreReplacements();replacements[":\"agent_projection_definer_role\""]=Id(UnsafeDefinerRole);replacements[":'agent_projection_definer_role'"]=Lit(UnsafeDefinerRole);
        var script=await Render("agent-projection-store.sql",replacements);await using var connection=await Owner.OpenConnectionAsync();var rejected=false;
        try{await using var command=new NpgsqlCommand(script,connection);await command.ExecuteNonQueryAsync();}
        catch(PostgresException){rejected=true;await using var rollback=new NpgsqlCommand("ROLLBACK",connection);await rollback.ExecuteNonQueryAsync();}
        if(!rejected)throw new InvalidOperationException("Unsafe projection definer was accepted.");
        await using var verify=new NpgsqlCommand("SELECT (SELECT count(*) FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname IN('agent_projection_database_bindings','agent_device_directory_bindings'))=0 AND NOT pg_catalog.has_column_privilege(@role,'agent_private.devices','device_id','SELECT')",connection);
        verify.Parameters.AddWithValue("role",UnsafeDefinerRole);UnsafeStoreRollbackVerified=(bool)(await verify.ExecuteScalarAsync())!;
        if(!UnsafeStoreRollbackVerified)throw new InvalidOperationException("Rejected projection store left partial state.");
    }
    public Task DisposeAsync()=>Cleanup();
    private async Task Cleanup(){if(_disposed)return;_disposed=true;try{try{if(Projection is not null)await Projection.DisposeAsync();}finally{try{if(Ingest is not null)await Ingest.DisposeAsync();}finally{try{if(Enroll is not null)await Enroll.DisposeAsync();}finally{if(Issue is not null)await Issue.DisposeAsync();}}}if(Owner is not null&&_rolesCreated){if(await Scalar<long>("SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE nspname='agent_private' AND rolname=@owner",P("owner",TableOwnerRole))==1)await Execute("DROP SCHEMA agent_private CASCADE");var database=new NpgsqlConnectionStringBuilder(_connectionString).Database!;await Execute($"REVOKE CONNECT ON DATABASE {Id(database)} FROM {Id(IngestRole)},{Id(EnrollRole)},{Id(IssueRole)},{Id(ProjectionRole)}; DROP ROLE IF EXISTS {Id(UnsafeDefinerRole)},{Id(ProjectionRole)},{Id(ProjectionDefinerRole)},{Id(IssueRole)},{Id(EnrollRole)},{Id(EnrollmentDefinerRole)},{Id(IngestRole)},{Id(TableOwnerRole)};");}}finally{try{if(_lease is not null)await _lease.DisposeAsync();}finally{if(Owner is not null)await Owner.DisposeAsync();}}}
    private Dictionary<string,string> ProjectionStoreReplacements()=>new(){[":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_projection_definer_role\""]=Id(ProjectionDefinerRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),[":'agent_projection_definer_role'"]=Lit(ProjectionDefinerRole)};
    private Dictionary<string,string> ProjectionProvisionReplacements(Guid environment){var database=new NpgsqlConnectionStringBuilder(_connectionString).Database!;return new(){[":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_projection_definer_role\""]=Id(ProjectionDefinerRole),[":\"agent_projection_role\""]=Id(ProjectionRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),[":'agent_projection_definer_role'"]=Lit(ProjectionDefinerRole),[":'agent_projection_role'"]=Lit(ProjectionRole),[":'environment_id'"]=Lit(environment.ToString()),[":DBNAME"]=Id(database)};}
    private async Task Script(string file,Dictionary<string,string> replacements)=>await Execute(await Render(file,replacements));
    private static async Task<string> Render(string file,Dictionary<string,string> replacements){var lines=await File.ReadAllLinesAsync(Path.Combine(AppContext.BaseDirectory,file));var sql=string.Join('\n',lines.Where(x=>!x.StartsWith('\\')));foreach(var pair in replacements.OrderByDescending(x=>x.Key.Length))sql=sql.Replace(pair.Key,pair.Value,StringComparison.Ordinal);return sql;}
    private static NpgsqlDataSource DataSource(NpgsqlConnectionStringBuilder source,string role,string password)=>NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(source.ConnectionString){Username=role,Password=password,Pooling=false}.ConnectionString);
    private static NpgsqlParameter P(string name,object value)=>new(name,value);private static string Secret()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(24));private static string Lit(string value)=>$"'{value.Replace("'","''",StringComparison.Ordinal)}'";
    private static string Id(string value){if(!Safe().IsMatch(value))throw new ArgumentException("Unsafe identifier");return $"\"{value}\"";}private static void Validate(NpgsqlConnectionStringBuilder value){if(value.Host is not("127.0.0.1" or "localhost" or "::1")||value.Database is not("console_test" or "console_ci"))throw new InvalidOperationException("Projection tests require loopback console_test or console_ci.");}
    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$")]private static partial Regex Safe();
}
public sealed record TestProjectionSeed(Guid EnvironmentId,Guid DirectoryObjectId,Guid DeviceId,Guid RegistrationId,Guid ReceiptId,Guid Unused,long Epoch);
