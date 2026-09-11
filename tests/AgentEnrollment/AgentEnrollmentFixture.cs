using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Npgsql;

namespace ItManagement.AgentEnrollment.Tests;

[CollectionDefinition(Name,DisableParallelization=true)]
public sealed class AgentEnrollmentCollection:ICollectionFixture<AgentEnrollmentFixture>{public const string Name="Agent enrollment database";}

public sealed partial class AgentEnrollmentFixture:IAsyncLifetime
{
    private const long AdvisoryLockKey=7912040301;
    private readonly string _ownerConnectionString=Environment.GetEnvironmentVariable("AGENT_ENROLLMENT_TEST_DB")??
      Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")??throw new InvalidOperationException("AGENT_ENROLLMENT_TEST_DB or CONSOLE_TEST_DB is required.");
    private readonly string _suffix=Guid.NewGuid().ToString("N")[..12];
    private NpgsqlConnection? _lockConnection; private bool _rolesCreated; private bool _cleanupStarted;
    private string _enrollPassword=null!,_issuePassword=null!,_ingestPassword=null!;
    public string TableOwnerRole=>$"ae_tbl_{_suffix}"; public string FunctionOwnerRole=>$"ae_fun_{_suffix}";
    public string EnrollRole=>$"ae_enr_{_suffix}"; public string IssueRole=>$"ae_iss_{_suffix}"; public string IngestRole=>$"ae_ing_{_suffix}";
    public Guid EnvironmentId{get;}=Guid.NewGuid();
    public NpgsqlDataSource OwnerDataSource{get;private set;}=null!; public NpgsqlDataSource EnrollDataSource{get;private set;}=null!;
    public NpgsqlDataSource IssueDataSource{get;private set;}=null!; public NpgsqlDataSource IngestDataSource{get;private set;}=null!;
    public async Task InitializeAsync()
    {
        var builder=new NpgsqlConnectionStringBuilder(_ownerConnectionString);ValidateTarget(builder);
        try
        {
            OwnerDataSource=NpgsqlDataSource.Create(builder.ConnectionString);
            var lockBuilder=new NpgsqlConnectionStringBuilder(builder.ConnectionString){Pooling=false};
            _lockConnection=new NpgsqlConnection(lockBuilder.ConnectionString);
            await _lockConnection.OpenAsync();
            await using(var command=new NpgsqlCommand("SELECT pg_catalog.pg_advisory_lock(@key)",_lockConnection){CommandTimeout=120})
            {command.Parameters.AddWithValue("key",AdvisoryLockKey);await command.ExecuteNonQueryAsync();}
            if(await ScalarAsync<long>("SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='agent_private'")!=0)
                throw new InvalidOperationException("agent_private already exists; refusing to overwrite existing state.");
            _enrollPassword=Secret();_issuePassword=Secret();_ingestPassword=Secret();
            await ExecuteAsync($"""
              CREATE ROLE {Id(TableOwnerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(FunctionOwnerRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(EnrollRole)} LOGIN PASSWORD {Lit(_enrollPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(IssueRole)} LOGIN PASSWORD {Lit(_issuePassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              CREATE ROLE {Id(IngestRole)} LOGIN PASSWORD {Lit(_ingestPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
              """);_rolesCreated=true;
            await ScriptAsync("agent-store.sql",new Dictionary<string,string> { [":\"agent_definer_role\""]=Id(TableOwnerRole) });
            var database=builder.Database!;
            await ScriptAsync("agent-enrollment-store.sql",new Dictionary<string,string> { [":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(FunctionOwnerRole) });
            await ScriptAsync("provision-agent-store.sql",new Dictionary<string,string> { [":\"agent_definer_role\""]=Id(TableOwnerRole),[":\"agent_ingest_role\""]=Id(IngestRole),
              [":'agent_definer_role'"]=Lit(TableOwnerRole),[":'agent_ingest_role'"]=Lit(IngestRole),[":'environment_id'"]=Lit(EnvironmentId.ToString()),[":DBNAME"]=Id(database) });
            await ScriptAsync("provision-agent-enrollment.sql",new Dictionary<string,string> { [":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(FunctionOwnerRole),
              [":\"agent_enroll_role\""]=Id(EnrollRole),[":\"agent_issue_role\""]=Id(IssueRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),
              [":'agent_enrollment_definer_role'"]=Lit(FunctionOwnerRole),[":'agent_enroll_role'"]=Lit(EnrollRole),[":'agent_issue_role'"]=Lit(IssueRole),
              [":'environment_id'"]=Lit(EnvironmentId.ToString()),[":DBNAME"]=Id(database) });
            EnrollDataSource=DataSource(builder,EnrollRole,_enrollPassword);IssueDataSource=DataSource(builder,IssueRole,_issuePassword);
            IngestDataSource=DataSource(builder,IngestRole,_ingestPassword);
        }
        catch{await CleanupAsync();throw;}
    }
    public async Task<TestGrant> SeedGrantAsync(Guid? deviceId=null,DateTimeOffset? expires=null,Guid? environmentId=null)
    {
        var value=new TestGrant(environmentId??EnvironmentId,deviceId??Guid.NewGuid(),Guid.NewGuid(),RandomNumberGenerator.GetBytes(32));
        var expiresAt=expires??DateTimeOffset.UtcNow.AddMinutes(10);var createdAt=expires.HasValue?expiresAt.AddMinutes(-1):DateTimeOffset.UtcNow;
        await ExecuteAsync("""
          INSERT INTO agent_private.devices(environment_id,device_id,state) VALUES(@environment,@device,'Active') ON CONFLICT DO NOTHING;
          INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at)
          VALUES(@environment,@grant,@device,sha256(@token),'Available',@created,@expires)
          """,new NpgsqlParameter("environment",value.EnvironmentId),new NpgsqlParameter("device",value.DeviceId),
          new NpgsqlParameter("grant",value.GrantId),new NpgsqlParameter("token",value.Token),
          new NpgsqlParameter("created",createdAt),new NpgsqlParameter("expires",expiresAt));return value;
    }
    public async Task ExecuteAsync(string sql,params NpgsqlParameter[] parameters){await using var command=OwnerDataSource.CreateCommand(sql);command.Parameters.AddRange(parameters);await command.ExecuteNonQueryAsync();}
    public Task ResetStateAsync()=>ExecuteAsync("""
      DELETE FROM agent_private.enrollment_results;
      DELETE FROM agent_private.enrollment_requests;
      DELETE FROM agent_private.enrollment_grants;
      DELETE FROM agent_private.certificate_bindings;
      DELETE FROM agent_private.registrations;
      DELETE FROM agent_private.devices;
      """);
    public Task ProvisionWithTableOwnerAsEnrollAsync()
    {
        var database=new NpgsqlConnectionStringBuilder(_ownerConnectionString).Database!;
        return ScriptAsync("provision-agent-enrollment.sql",new Dictionary<string,string> { [":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(FunctionOwnerRole),
          [":\"agent_enroll_role\""]=Id(TableOwnerRole),[":\"agent_issue_role\""]=Id(IssueRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),
          [":'agent_enrollment_definer_role'"]=Lit(FunctionOwnerRole),[":'agent_enroll_role'"]=Lit(TableOwnerRole),[":'agent_issue_role'"]=Lit(IssueRole),
          [":'environment_id'"]=Lit(EnvironmentId.ToString()),[":DBNAME"]=Id(database) });
    }
    public async Task ProvisionForEnvironmentAsSeparateCommandsAsync(Guid environmentId)
    {
        var database=new NpgsqlConnectionStringBuilder(_ownerConnectionString).Database!;
        var replacements=new Dictionary<string,string> { [":\"agent_table_owner_role\""]=Id(TableOwnerRole),[":\"agent_enrollment_definer_role\""]=Id(FunctionOwnerRole),
          [":\"agent_enroll_role\""]=Id(EnrollRole),[":\"agent_issue_role\""]=Id(IssueRole),[":'agent_table_owner_role'"]=Lit(TableOwnerRole),
          [":'agent_enrollment_definer_role'"]=Lit(FunctionOwnerRole),[":'agent_enroll_role'"]=Lit(EnrollRole),[":'agent_issue_role'"]=Lit(IssueRole),
          [":'environment_id'"]=Lit(environmentId.ToString()),[":DBNAME"]=Id(database) };
        var lines=await File.ReadAllLinesAsync(Path.Combine(AppContext.BaseDirectory,"provision-agent-enrollment.sql"));
        var sql=string.Join('\n',lines.Where(x=>!x.StartsWith('\\')));foreach(var pair in replacements.OrderByDescending(x=>x.Key.Length))sql=sql.Replace(pair.Key,pair.Value,StringComparison.Ordinal);
        await using var connection=await OwnerDataSource.OpenConnectionAsync();
        try
        {
            foreach(var statement in sql.Split(';',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries))
            {await using var command=new NpgsqlCommand(statement,connection);await command.ExecuteNonQueryAsync();}
        }
        catch
        {
            await using var rollback=new NpgsqlCommand("ROLLBACK",connection);await rollback.ExecuteNonQueryAsync();throw;
        }
    }
    public async Task<T> ScalarAsync<T>(string sql,params NpgsqlParameter[] parameters){await using var command=OwnerDataSource.CreateCommand(sql);command.Parameters.AddRange(parameters);return (T)(await command.ExecuteScalarAsync())!;}
    public Task DisposeAsync()=>CleanupAsync();
    private async Task CleanupAsync()
    {
        if(_cleanupStarted)return;
        _cleanupStarted=true;
        try
        {
            try{if(EnrollDataSource is not null)await EnrollDataSource.DisposeAsync();}
            finally{try{if(IssueDataSource is not null)await IssueDataSource.DisposeAsync();}finally{if(IngestDataSource is not null)await IngestDataSource.DisposeAsync();}}
            if(OwnerDataSource is not null&&_rolesCreated)
            {
                if(await ScalarAsync<long>("SELECT count(*) FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='agent_private' AND r.rolname=@owner",new NpgsqlParameter("owner",TableOwnerRole))==1)
                    await ExecuteAsync("DROP SCHEMA agent_private CASCADE");
                var database=new NpgsqlConnectionStringBuilder(_ownerConnectionString).Database!;
                await ExecuteAsync($"REVOKE CONNECT ON DATABASE {Id(database)} FROM {Id(EnrollRole)},{Id(IssueRole)},{Id(IngestRole)}; DROP ROLE IF EXISTS {Id(EnrollRole)},{Id(IssueRole)},{Id(IngestRole)},{Id(FunctionOwnerRole)},{Id(TableOwnerRole)};");
                _rolesCreated=false;
            }
        }
        finally
        {
            try{if(_lockConnection is not null){await _lockConnection.DisposeAsync();_lockConnection=null;}}
            finally{if(OwnerDataSource is not null)await OwnerDataSource.DisposeAsync();}
        }
    }
    private async Task ScriptAsync(string file,IReadOnlyDictionary<string,string> replacements){var lines=await File.ReadAllLinesAsync(Path.Combine(AppContext.BaseDirectory,file));var sql=string.Join('\n',lines.Where(x=>!x.StartsWith('\\')));foreach(var pair in replacements.OrderByDescending(x=>x.Key.Length))sql=sql.Replace(pair.Key,pair.Value,StringComparison.Ordinal);await ExecuteAsync(sql);}
    private static NpgsqlDataSource DataSource(NpgsqlConnectionStringBuilder source,string user,string password){var copy=new NpgsqlConnectionStringBuilder(source.ConnectionString){Username=user,Password=password,Pooling=false};return NpgsqlDataSource.Create(copy.ConnectionString);}
    private static void ValidateTarget(NpgsqlConnectionStringBuilder builder){if(builder.Host is not("127.0.0.1" or "localhost" or "::1")||builder.Database is not("console_test" or "console_ci"))throw new InvalidOperationException("Enrollment tests require loopback console_test or console_ci.");}
    private static string Secret()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(24));private static string Lit(string value)=>$"'{value.Replace("'","''",StringComparison.Ordinal)}'";
    private static string Id(string value){if(!SafeIdentifier().IsMatch(value))throw new ArgumentException("Unsafe identifier.");return $"\"{value}\"";}
    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$")]private static partial Regex SafeIdentifier();
}
public sealed record TestGrant(Guid EnvironmentId,Guid DeviceId,Guid GrantId,byte[] Token);
