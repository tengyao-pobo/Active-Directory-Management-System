# PostgreSQL 邏輯資料模型

Phase 1 設計；不是已套用的 DDL。Phase 2 產生 EF Core migrations、約束與 PostgreSQL integration tests。資料量、retention 與部署 SLO 需以實際環境容量測試校正。

## 共通規則

- 主鍵採平台產生的 UUID，不以 IP、hostname、DN、UPN、email 或 serial 為主鍵。
- 除明確列出的平台級資料外，每表有非空 `environment_id`。業務表 PK 可採 UUID，但一律有 UNIQUE `(environment_id,id)`，所有業務 FK 使用 `(environment_id,parent_id)` 複合參照。
- 可變資料有 `created_at, updated_at, version`；觀測資料另有 `observed_at, received_at, source, schema_version`。時間採 timestamptz/UTC。Row version 是樂觀併發 token，不用時間猜相等。
- 明確分開 Principal（平台登入者）與 DirectoryUser（被管理人員）；用不可變 SID/objectGUID/issuer-subject 建 identity mapping，不能依 email 自動合併。
- 一般業務資料禁止 cascade delete 到 audit、歷史與外部變更紀錄；刪 Environment 不是直接 DELETE cascade，而是獨立匯出/retention/停用/刪除工作流程。
- 機密僅存 opaque secret reference。無 recovery-key value 欄位。Password hash 限 emergency identity 使用，不能混入 directory cache。

## Identity / Environment

| 表 | 核心欄位、鍵與關係 |
|---|---|
| Environments | id、display_name、canonical_dns、status、default_locale、time_zone、policy_version |
| Principals（平台級） | id、issuer、subject、kind、display_name、status；UNIQUE issuer+subject；Windows subject 為 SID |
| EnvironmentMemberships | principal_id FK、environment_id FK、status；UNIQUE env+principal |
| PrincipalPreferences（平台級） | principal_id、locale、theme；只能由本人或明確管理流程修改 |
| LocalCredentials（平台級） | principal_id、password_hash、hash_version、lockout_until、failed_count；不對一般查詢 role 開放 |
| Authenticators（平台級） | principal_id、credential_id、public_key、counter、created_at、revoked_at；FIDO2 credential ownership |
| RecoveryCodes（平台級） | principal_id、code_hash、consumed_at；單次原子消耗 |
| Sessions（平台級） | id_hash、principal_id、auth_method、auth_time、step_up_at、expires_at、last_seen、revoked_at、source_ip、user_agent、authorization_version |
| Permissions（平台級唯讀 catalog） | code PK、resource_type、sensitivity；新增 permission 須版本化 migration |
| Roles | id、name、built_in_kind、is_system_protected；UNIQUE env+name |
| RolePermissions | role_id、permission_code；UNIQUE env+role+permission |
| Scopes | id、resource_type、rule_ast、version；只允許已定義 operator/欄位 |
| RoleAssignments | principal_id、role_id、scope_id、valid_from/until、grant_source；membership 必須存在 |
| AdGroupMappings | group_sid、role_id、scope_id；禁止指向 Owner；群組重新命名不改識別 |
| ResolvedGroupMemberships | principal_id、group_sid、observed_at、expires_at；僅快取，不取代敏感操作再驗證 |
| EnvironmentPolicies | type、version、schema_version、payload JSONB、effective_at；UNIQUE env+type+version |
| OwnerTransfers | from_principal、to_principal、requested/accepted_at、expires_at、state、reason；原子最後 Owner invariant |

平台級身份表只能由 Identity 模組查詢，不能經一般 Environment API 列舉所有人。平台 provisioning 權限是独立 bootstrap/operator capability，不預設賦予某個 Environment Owner。

## Directory / Connector

| 表 | 核心欄位、鍵與關係 |
|---|---|
| ConnectorConfigurations | id、kind、endpoint、external_tenant/domain_identifier、secret_ref、capabilities、enabled、version；不存 credential material |
| ConnectorRuns | connector_id、started/completed_at、cursor_ref、status、error_code、freshness；同步游標持久化 |
| DirectoryDomains | connector_id、domain_guid、dns_name、netbios_name、forest_id、site metadata |
| DirectoryObjects | id、connector_id、object_guid、sid、kind、dn、parent_ou_id、is_deleted、last_synced_at；UNIQUE env+connector+object_guid |
| DirectoryUsers | object_id FK/UNIQUE、UPN、display_name、department_id、manager_object_id、enabled、locked、password-expiry metadata；不存 password |
| DirectoryGroups | object_id、group_type、scope、description |
| DirectoryComputers | object_id、dns_name、os metadata、last_logon_timestamp、trust observation；lastLogonTimestamp 不宣稱精確最後登入 |
| DirectoryOus | object_id、parent_object_id、path projection；OU scope 用 GUID 與樹，不做不安全字尾字串比對 |
| GroupMemberships | group_object_id、member_object_id、observed_at；UNIQUE env+group+member；保留 direct edge，transitive 查詢有限深度/循環保護 |
| Departments | id、name、external_mapping；Environment 可管理其名稱映射 |
| UserTemplates | id、version、name、OU ref、department ref、group refs、naming_rule、UPN_rule；套用時再驗授權及保護 |
| ProtectedObjects | target_type、target_id、reason、source、policy_version；只能由受限安全流程變更 |
| DirectoryChangeHistory | object_id、changed_fields、sanitized_before/after、source、observed_at、operation_id |

DirectoryObjects 的 tombstone 不自動刪歷史。critical group monitoring 以 SID/RID-aware identity 與變更事件處理，不依英文群組名稱。

## Device / Inventory / Asset

| 表 | 核心欄位、鍵與關係 |
|---|---|
| Devices | id、display_hostname、canonical_dns、lifecycle_status、first_seen、last_received_heartbeat、current_snapshot_id、asset_owner_id、version |
| DeviceIdentifiers | device_id、kind、value、source、confidence、valid_from/to；只有受控內部 ID 唯一，serial/SMBIOS UUID 不假設全球唯一 |
| DeviceDirectoryLinks | device_id、directory_computer_id、confidence、verified_by/at；唯一性按有效 mapping 約束 |
| DeviceIdentityConflicts | candidate_device_ids、evidence、state、resolved_by/at；禁止靜默 merge |
| DeviceHardware | device_id、snapshot_id、component_id、type、vendor、model、serial、typed metrics / extra JSONB |
| DeviceNetwork | device_id、snapshot_id、interface_id、MAC、addresses inet[]、DNS/gateway、optional_ssid；IP 可重用，不 UNIQUE |
| SoftwareProducts | id、normalized_name、publisher、normalization_version；避免把不明產品粗暴合併 |
| DeviceSoftware | device_id、snapshot_id、product_id、source_key、version_text、architecture、install_date；version 不作浮點數 |
| DeviceSecurity | device_id、snapshot_id、signal、state、quality、metadata；禁止 secret/key value |
| DeviceInventorySnapshots | id、device_id、registration_id、sequence、payload_hash、observed/received_at、schema_version、normalized_payload；UNIQUE env+registration+epoch+sequence |
| InventoryDifferences | device_id、from_snapshot_id、to_snapshot_id、field、before/after、source；變更只含允許盤點欄位 |
| DeviceUserAssociations | device_id、directory_user_id nullable、observed_identity、association_kind、first/last_seen、source、confidence；owner/current/last user 分開 |
| DeviceNotes | device_id、author_principal、body、version、created/edited_at；長度限制與輸出 escaping |
| DeviceRepairs | device_id、date、category、description、cost optional、source_note_id |
| Tags | id、name、classification、security_scope_eligible；Environment 內唯一 |
| DeviceTags | device_id、tag_id、assigned_by、assigned_at；Agent 不可寫入授權標籤 |
| DeviceLifecycleHistory | device_id、before/after、reason、operator、operation_id；Retired 不觸發 AD delete |
| DeviceAgeEstimates | device_id、date_basis、source、confidence、estimated_age、evaluated_at、rule_version；有資料修正可重算 |
| ReplacementAssessments | device_id、priority、reasons、input_snapshot_id、rule_version、evaluated_at |
| CleanupReviewItems | device_id、evidence、status、reviewer、notes；無自動刪除外部 object |
| Favorites | principal_id、resource_type、resource_id；讀取時仍驗證資源 scope |
| SavedFilters | owner_principal、dataset、filter_ast、sharing、version；不能嵌入 SQL 或另行授權 |

Current state 與歷史：Snapshots 是不可變的標準化輸入；DeviceHardware/Network/Software/Security 是 current projection，交易內引用同一 snapshot。更舊資料保留於 snapshots，UI history/diff 從快照或差異 projection 取得，不必每次重算所有歷史。raw payload 不無條件保存；只保存 schema 允許的正規化資料。

## Agent / Health

| 表 | 核心欄位、鍵與關係 |
|---|---|
| EnrollmentGrants | id、token_hash、expected_device_ref、expires_at、consumed_at、issued_by、state；交易內一次性消耗 |
| PendingEnrollments | grant_id、CSR public metadata、evidence、approval_state、approved_by/at；不含 private key |
| AgentRegistrations | id、device_id、epoch、status、agent_version、capabilities、registered_at、disabled_at |
| DeviceCertificates | registration_id、issuer、serial、thumbprint、not_before/after、revoked_at；UNIQUE issuer+serial |
| AgentMessages | registration_id、epoch、sequence、request_id、payload_hash、result_code、received_at；去重狀態與結果一致寫入 |
| AgentHeartbeats | registration_id、received_at、agent_observed_at、version、result；server time 為連線來源 |
| InventoryRequests | device_id、kind、profile_version、state、requested_by、expires_at、lease_until、snapshot_id、error_code |
| DeviceHealthChecks | device_id、probe、state、evidence_json、source、observed_at、expires_at、policy_version |
| DeviceHealthScores | device_id、score nullable、coverage、status、critical_reasons、evaluated_at、policy_version、input_snapshot_id |
| HealthPolicyVersions | policy_id、version、weights、thresholds、critical_rules、coverage_minimum；可驗證且不能任意執行程式 |
| LifecycleDatasets | version、source_url、verified_at、edition/version/build constraints、support_dates |
| Alerts | resource_type/id、rule_id、fingerprint、state、first/last_seen、acknowledged_by；去重與恢復事件 |

Inventory request 狀態：Pending → Leased → Collecting → Uploaded → Completed，或 Expired/Failed/Cancelled。同設備請求可合併但保留各 requester 稽核。租約過期可重領；snapshot 去重不因重領而失效。

## Changes / Reporting / Audit

| 表 | 核心欄位、鍵與關係 |
|---|---|
| ChangePlans | id、requester、action、immutable_plan_json、plan_hash、policy_version、expires_at、state、reason |
| ChangePlanItems | plan_id、target_id、expected_version、sanitized_before、proposed_after、protection_status、excluded_reason |
| ChangeApprovals | plan_id、plan_hash、approver、step_up_at、approved_at、expires_at；禁止 requester 自批高風險變更 |
| ChangeExecutions | plan_id、executor_identity、job_id、started/ended_at、status、correlation_id |
| ChangeItemResults | execution_id、item_id、idempotency_key、actual_sanitized_state、status、error_code；Unknown 明確保存 |
| ScheduledOperations | plan_id、scheduled_at、state；執行前重新授權且計畫不可過期；scheduled disable 留實際時間/操作人/理由 |
| Jobs | id、kind、typed_payload、state、attempts、next_attempt_at、lease_owner/until、cancel_requested、dedupe_key；無秘密 |
| OutboxMessages | id、event_type、version、payload、created_at、delivered_at、attempts；與業務交易一起提交 |
| ReportDefinitions | id、dataset、filter_schema、columns、allowed_formats、version、owner、sharing |
| ReportJobs | job_id、definition_version、requested_filter、requested_by、authorization_version、status |
| ReportArtifacts | report_job_id、opaque_storage_key、content_hash、size、expires_at、download_policy；不能以 URL 作授權 |
| HelperWorkstations | id、owner_principal、device_binding、version、registered_at、revoked_at；由受控安裝註冊 |
| HelperTickets | id_hash、principal_id、session_id_hash、workstation_id、device_id、action、canonical_target、audience、nonce、expires_at、consumed_at、signed_claims_hash |
| AuditLogs | id、actor、actor_auth_method、environment、target、action、sanitized_before/after、reason、result、source_ip、occurred_at、correlation_id、connector_identity、plan_hash、policy_version |
| AuditArchiveReceipts | batch_id、first/last_event、archive_hash、signature_reference、sink_receipt、archived_at |

無登入成功的事件可進平台級 SecurityEvents（認證結果、來源與非機密識別摘要），Environment 已知後寫對應 AuditLogs。平台 audit-reader 權限與每個 Environment 的 Audit.View 分離，不能由一般 env 操作人讀到其他環境 failed-login 紀錄。

## 索引與資料庫隔離

- 所有查詢常用 `(environment_id, sort_key, id)`；Directory objectGUID/SID、Devices current hostname、identifiers、Inventory device+observed_at、Audit env+occurred_at+id、Jobs state+next_attempt_at 分別建索引。
- Search 投影帶 environment_id + resource_id；先過 permission/scope，才回片段/聚合。PostgreSQL trigram/GIN 視實測採用，V1 不先增加外部搜尋引擎。
- FK 以複合 env key 防止參照跨 Environment。SQL Repository 不允許全域 ignore-query-filter 作一般 API 路徑。
- RLS 使用 transaction-local Environment context；每次 checkout/transaction 明確設定，未設定則 deny，避免 pooled connection 泄漏。應用 DB role 不是 table owner、superuser 或 BYPASSRLS；migration owner 獨立。
- RLS 是誤用防線，不抵禦持有任意 SQL 能力的受入侵 API；不宣稱可保護不互信客戶。應用 Scope 仍需查詢授權與 negative tests。[PostgreSQL Row Security](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)
- Audit writer 只 append；一般 runtime 無 UPDATE/DELETE audit 權限。archive/retention 由獨立維運身分；hash chain 本身不能抵擋可重寫整條链的 DB 管理者，需外部 receipt/immutable retention。

## Retention / 容量 / 備援

初始建議可調：heartbeat 明細 7 天、日彙總 90 天；daily snapshot 180 天、月摘要 24 個月；reports 24 小時；audit 365 天以上依企業政策與法規確認。這些是設計起點，不是承諾。schema、purge jobs 與 UI 必須顯示 policy，不無限成長。

5,000 台、60 秒 heartbeat 約 720 萬筆/天，因此 lastSeen 使用 upsert，heartbeat 明細可配置抽樣/彙總；不可未估容量就全量長期保留。AgentMessages 去重高水位與窗口不得隨 heartbeat purge 一併清掉，否則舊訊息可能重播。

Snapshot size 必須在 pilot 實測 p95，再決定 ingestion body cap、分段上傳、壓縮解壓上限與日吞吐。software 清單可能遠大於硬體資料，不能一刀切小上限造成所有大企業設備失敗。

採 PostgreSQL backup + WAL/PITR，另備份報表儲存、Data Protection keys、設定與必要 PKI metadata；CA/secret 私鑰由其各自受控備份程序處理。加密備份與金鑰分開權限。初始 SLO 目標 RPO ≤15 分鐘、RTO ≤4 小時，待實際復原演練確認，不能以成功備份代替復原測試。

Migration 以 expand/contract 相容滾動升級，部署前備份與 rehearsal；破壞性 down migration 不作預設 rollback。恢復舊 binary 前檢查 schema 相容；無法回退以 forward fix 或經核准資料還原處理。
