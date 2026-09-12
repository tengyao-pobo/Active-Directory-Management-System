# 平台 initial enrollment grant 儲存層

此元件提供平台核准流程未來使用的私有授權發行與同一操作恢復契約。v2 增量加入私有狀態讀回與撤銷，並不代表公開操作端點、背景 worker、設備 mapping 建立或正式 Agent 註冊已啟用。公司是否安裝 RSAT 不影響平台的統一操作目標。

## 呼叫界線

發行使用獨立的 per-environment worker pool。環境由 SESSION_USER 的 binding 決定，caller 不能選擇其他環境；每次呼叫還帶入核定操作的 expected environment，只作相等斷言，與 binding 不符時在任何寫入前拒絕。登入只取得固定函式的 EXECUTE；Web/API、Ingest、Enroll、Issue 與 Projection 的既有登入不能取得發行權限。資料表仍屬 NOLOGIN table owner，固定函式使用另一個最小權限 NOLOGIN definer。

平台端必須先完成提案、目前目標／權限重查、獨立操作人員核准及 durable sealed delivery。`authorization_digest` 是核定 canonical plan 的 SHA-256 稽核關聯，不能當作簽章、bearer 或已獲人類核准的證明。C# 的核定授權及已準備 token hash 型別保持封閉工廠，未接上正式授權組合。

PostgreSQL 的[列鎖定查詢](https://www.postgresql.org/docs/current/sql-select.html)除 SELECT 外也要求至少一欄 UPDATE 權限。為避免給發行 definer 任意修改設備或 mapping 的能力，列鎖定使用 table-owner 擁有的固定 helper，只供指定 definer 呼叫，不能直接由 Web 或 worker 登入執行。新舊擴充的相容稽核也需涵蓋未安裝平台 grant 表的環境；[PL/pgSQL 分支會在首次執行時解析查詢](https://www.postgresql.org/docs/current/plpgsql-implementation.html)，因此有表與無表兩種路徑都要實際測試。

## 原子發行與恢復

一個 operation ID 對應一份 receipt 與一份 grant。首次呼叫鎖定操作、mapping 與設備，核對目錄 GUID、server Device ID、mapping 建立時間、設備狀態及既有註冊／發證／可用授權，再原子寫入。有效期固定 600 秒，以第一次成功發行的時間為準。

精確重試先找既有 receipt；完整 tuple、token hash 及 authorization digest 相同才回原 grant 與原到期時間。映射後來移除也不應使已提交的歷史 receipt 消失。不同 tuple 不能當作新的申請，也不能替換 token。新發行仍須通過目前 mapping 與設備條件；既有 receipt 的恢復不表示當下仍可領取或使用授權。

網路中斷或 commit 回應不明要讀回同一 operation，不能產生新 token。撤銷、過期、已消耗 grant、後續 CA 操作與憑證撤銷屬各自生命週期；此層不得把「授權曾建立」解釋成「設備已註冊成功」。

## 安裝與升級順序

新安裝與既有安裝都必須先完成 Ingest、Enrollment 及 Projection v2 的 store／provision，再以資料庫遷移管理身分執行 `build/upgrade-agent-platform-grant-isolation-v1.sql`。既有 Projection v1 要先執行原有 v1→v2 升級。不要重跑建表腳本來替代既有資料庫升級。

隔離升級腳本需要三個既有 NOLOGIN 角色變數：`agent_table_owner_role`、`agent_enrollment_definer_role`、`agent_projection_definer_role`。它在同一交易內替換三個既有權限稽核、安裝僅供其 NOLOGIN definer 使用的 binding 檢查函式，最後才建立 `platform_grant_isolation_profile()` 版本 1 完成標記。任一步失敗都回滾；既有 runtime 的稽核函式 EXECUTE ACL 保留。

完成隔離升級後，以 `build/agent-platform-grants-store.sql` 與 `build/agent-platform-grants/v1/provision-agent-platform-grants.sql` 建立 v1 基礎及 issuer binding；store 傳入 `agent_table_owner_role`、`agent_platform_grant_definer_role`，歷史 provision 另需該環境專用的 `agent_platform_grant_role` 與 `environment_id`。接著完成 capability isolation v2，再執行下節的 lifecycle v2 升級與新版雙角色 provision。這些步驟共同構成新安裝，不能停在 v1 就啟用新版 repository。角色及憑證應由部署機制管理，不能把密碼寫入 SQL、版本庫或命令輸出。新增 LOGIN 不能重用既有 Web、Ingest、Enroll、Issue 或 Projection 的身分。

安裝後仍須用各個實際 runtime LOGIN 執行其權限稽核，並確認新 repository 的啟動稽核成功。完成標記只證明遷移能力版本，不代表背景工作、API 或正式核准流程已啟用。

回復應先停用新增 worker 的組合並保留 grant／receipt 供同一操作調和。已安裝平台擴充時，Projection v2→v1 腳本會在任何修改前拒絕，避免回到不知道新 binding 的舊稽核。尚未安裝擴充時允許的降級會在同一交易內移除隔離完成標記，日後必須重新升級到 v2 並執行隔離升級。平台 grant v2 的受限回復見下節；不提供刪除已發行 grant 或歷史 receipt 的回復步驟，也不能用刪表處理不明發行結果。

## 私有撤銷 v2 增量

`build/upgrade-agent-platform-grants-v1-to-v2.sql` 從既有平台 grant v1 升級，要求 capability isolation v2 已完成；參數為 `agent_table_owner_role`、`agent_platform_grant_definer_role` 與既有 issuer 的 `agent_platform_grant_role`。環境從既有 binding 取得。升級以單一交易安裝狀態讀回、撤銷、永久撤銷收據及精確權限稽核。此版本不修改既有 capability isolation marker 的 v2 語義；PlatformGrant audit 必須另回 profile 2。

新版 `build/provision-agent-platform-grants.sql` 除既有 issuer 參數外，增加不同的 per-environment `agent_platform_grant_revoker_role`。Issuer 只發行，revoker 只讀回／撤銷；平台流程統一呈現，底層登入與 pool 維持用途隔離。不能把既有 Web、issuer 或其他 Agent 服務登入改綁為 revoker。實際呼叫前，以兩個登入各自執行 typed repository 的啟動稽核。

呼叫必須保留完整原 issue receipt，不可只保存 grant ID。狀態結果含資料庫查詢時間及適用的狀態變更時間；撤銷永久記錄 Revoked、Expired、Consumed 或 AlreadyRevoked。Consumed 不表示憑證已撤銷。精確重試保留相同 operation ID、完整 receipt 與 digest；取消或連線中斷不能當作交易未提交的證明。詳細時間與恢復契約見[私有撤銷與讀回](../architecture/platform-grant-revocation.md)。

`build/downgrade-agent-platform-grants-v2-to-v1.sql` 提供受限回復。存在任一撤銷收據時不得降級或刪除歷史。合成測試已驗證回復及重新升級；正式部署仍須在目標環境，以新、舊服務的實際登入執行稽核並保留證據。

受限降級需指定上述 table owner、definer、issuer 及 `agent_platform_grant_revoker_role`。整個資料庫須恰好只有一個撤銷 binding，且符合指定 revoker 與環境；其他環境或角色另有撤銷 binding 時拒絕執行。腳本使用 psql 目前連線的 `DBNAME`，並先核對 `current_database()`，不可用另一個資料庫名稱覆寫。通過精確 v2 前置稽核後，降級須在同一交易內移除撤銷函式授權、binding、能力保留及 revoker 的直接資料庫 CONNECT／schema USAGE，並將角色設為 NOLOGIN；最後驗證 v1 契約與角色停用結果。

PostgreSQL 的 PUBLIC CONNECT 可能仍給予間接連線權限，因此角色停用以 NOLOGIN 與零角色 membership 為必要條件。日後重升級不會自動恢復此登入：部署管理員須另行明確、可稽核地啟用該角色，再執行 provision。正常 provision 要求角色已具 LOGIN；遇到仍為 NOLOGIN 的 revoker 必須零變更失敗。

## 平台整合待辦

已提供唯讀 [EnrollmentTargetRead 與平台設備註冊準備狀態](enrollment-target-read.md)，先驗證有效會員、目前 Computer 與同一物件的 `Computer.View`／`AgentEnrollmentGrant.Manage` 交集，再解析 server-owned mapping tuple。Browser 不提供 server Device ID。沒有 mapping 或設備非 Active 時回明確資格狀態，不建立 outbox，也不自動新增 mapping；未配置 pool 時顯示不可用。安裝此能力需再完成 capability isolation v2 升級；完成後不得重跑會還原舊稽核的 v1 升級或 Projection 降級腳本。

正式組合仍需完善的角色／函式／RLS 稽核、public operation 與密文持久化、worker 中斷調和、領取所有權及 ACK、available grant 撤銷、listener 與部署驗收。部署前需精確預覽、獨立覆核及環境操作授權；本次開發與合成測試不操作企業 AD、CA 或實際設備。

## v2 驗證證據

合成 loopback PostgreSQL 通過完整後端 925 項測試，包含儲存層 173 項與設備查詢整合 40 項；locked restore、Release build 通過，零警告／錯誤。涵蓋永久收據與重試、terminal 狀態讀回、鎖等待跨越到期、並行 consume／revoke、取消、跨環境操作衝突、歷史 mapping 移除、完整角色／PUBLIC policy 集合、capability-v2 重跑保留新版稽核、升級回滾與降級停用／明確重新啟用。一般獨立覆核與最終專項覆核無剩餘阻擋。這些證據不表示公開執行或企業 Agent 註冊已啟用。

## v1 合併時的驗證證據

合成 loopback PostgreSQL 環境通過完整後端 645 項測試，包含本元件 28 項資料庫／靜態回歸；locked restore 與 Release build 通過，零警告／錯誤。涵蓋固定 TTL／精確重試、跨環境 operation 競爭、mapping writer 列鎖、目前環境斷言、連線失敗、封閉回應矩陣、額外 ACL／角色混用、安裝前置條件、升降級標記與交易回滾。另有 fresh-store／upgrade 函式及 runtime／provision 稽核條件的一致性測試。一般獨立覆核與專項安全覆核未留下阻擋項目；以上證據只涵蓋尚未啟用的私有儲存層。
