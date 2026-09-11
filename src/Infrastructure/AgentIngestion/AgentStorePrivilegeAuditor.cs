using Npgsql;

namespace ItManagement.AgentIngestion;

public enum AgentStorePrivilegeIssue
{
    LoginMissing,
    LoginAttributesTooBroad,
    LoginHasRoleMembership,
    LoginBindingInvalid,
    DirectTableOrSequencePrivilege,
    FunctionExecuteMissing,
    FunctionOwnerMismatch,
    DefinerAttributesTooBroad,
    DefinerHasRoleMembership,
    FunctionNotSecurityDefiner,
    FunctionSearchPathInvalid,
    SchemaCreateGranted,
    LoginOwnsDatabaseOrSchema,
    UnexpectedFunctionExecuteGranted,
    TableSecurityInvalid
}

public sealed record AgentStorePrivilegeAudit(IReadOnlyList<AgentStorePrivilegeIssue> Issues)
{
    public bool IsValid => Issues.Count == 0;
}

public sealed class AgentStorePrivilegeAuditor
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly string _expectedDefinerRole;

    public AgentStorePrivilegeAuditor(NpgsqlDataSource dataSource, string expectedDefinerRole)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedDefinerRole);
        _expectedDefinerRole = expectedDefinerRole;
    }

    public async Task<AgentStorePrivilegeAudit> AuditAsync(CancellationToken cancellationToken)
    {
        var issues = new List<AgentStorePrivilegeIssue>();
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(
            """
            SELECT login_exists, attributes_too_broad, has_role_membership, binding_valid,
                   has_direct_object_privilege, function_execute_granted, function_owner_matches,
                   definer_attributes_too_broad, definer_has_membership, function_security_definer,
                   function_search_path_valid, schema_create_granted, login_owns_database_or_schema,
                   unexpected_function_execute, table_security_valid
            FROM agent_private.audit_ingest_privileges(@expected_definer::name)
            """,
            connection);
        command.Parameters.AddWithValue("expected_definer", _expectedDefinerRole);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return new AgentStorePrivilegeAudit([AgentStorePrivilegeIssue.LoginMissing]);
        }

        AddIfFalse(reader.GetBoolean(0), AgentStorePrivilegeIssue.LoginMissing);
        AddIfTrue(reader.GetBoolean(1), AgentStorePrivilegeIssue.LoginAttributesTooBroad);
        AddIfTrue(reader.GetBoolean(2), AgentStorePrivilegeIssue.LoginHasRoleMembership);
        AddIfFalse(reader.GetBoolean(3), AgentStorePrivilegeIssue.LoginBindingInvalid);
        AddIfTrue(reader.GetBoolean(4), AgentStorePrivilegeIssue.DirectTableOrSequencePrivilege);
        AddIfFalse(reader.GetBoolean(5), AgentStorePrivilegeIssue.FunctionExecuteMissing);
        if (!reader.GetBoolean(6))
        {
            issues.Add(AgentStorePrivilegeIssue.FunctionOwnerMismatch);
        }
        AddIfTrue(reader.GetBoolean(7), AgentStorePrivilegeIssue.DefinerAttributesTooBroad);
        AddIfTrue(reader.GetBoolean(8), AgentStorePrivilegeIssue.DefinerHasRoleMembership);
        AddIfFalse(reader.GetBoolean(9), AgentStorePrivilegeIssue.FunctionNotSecurityDefiner);
        AddIfFalse(reader.GetBoolean(10), AgentStorePrivilegeIssue.FunctionSearchPathInvalid);
        AddIfTrue(reader.GetBoolean(11), AgentStorePrivilegeIssue.SchemaCreateGranted);
        AddIfTrue(reader.GetBoolean(12), AgentStorePrivilegeIssue.LoginOwnsDatabaseOrSchema);
        AddIfTrue(reader.GetBoolean(13), AgentStorePrivilegeIssue.UnexpectedFunctionExecuteGranted);
        AddIfFalse(reader.GetBoolean(14), AgentStorePrivilegeIssue.TableSecurityInvalid);

        return new AgentStorePrivilegeAudit(issues);

        void AddIfTrue(bool condition, AgentStorePrivilegeIssue issue)
        {
            if (condition)
            {
                issues.Add(issue);
            }
        }

        void AddIfFalse(bool condition, AgentStorePrivilegeIssue issue) => AddIfTrue(!condition, issue);
    }
}
