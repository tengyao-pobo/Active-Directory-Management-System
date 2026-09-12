# 平台 initial enrollment grant 儲存層

此元件提供平台核准流程使用的私有授權發行與同一操作恢復契約。v2 加入私有狀態讀回與撤銷；v3 加入發行許可期限。平台排隊 API 與歷史查詢已有實作，但 processor 預設不可用；背景 worker、設備 mapping 建立或正式 Agent 註冊尚未啟用。公司是否安裝 RSAT 不影響平台的統一操作目標。

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

完成隔離升級後，以 `build/agent-platform-grants-store.sql` 與 `build/agent-platform-grants/v1/provision-agent-platform-grants.sql` 建立 v1 基礎及 issuer binding；store 傳入 `agent_table_owner_role`、`agent_platform_grant_definer_role`，歷史 provision 另需該環境專用的 `agent_platform_grant_role` 與 `environment_id`。接著完成 capability isolation v2，再執行下節的 lifecycle v2 升級及歷史 v2 雙角色 provision，最後完成 lifecycle v3 升級與目前根目錄的 provision。這些步驟共同構成新安裝，不能停在 v1 或 v2 就啟用新版 repository。角色及憑證應由部署機制管理，不能把密碼寫入 SQL、版本庫或命令輸出。新增 LOGIN 不能重用既有 Web、Ingest、Enroll、Issue 或 Projection 的身分。

安裝後仍須用各個實際 runtime LOGIN 執行其權限稽核，並確認新 repository 的啟動稽核成功。完成標記只證明遷移能力版本，不代表背景工作、API 或正式核准流程已啟用。

回復應先停用新增 worker 的組合並保留 grant／receipt 供同一操作調和。已安裝平台擴充時，Projection v2→v1 腳本會在任何修改前拒絕，避免回到不知道新 binding 的舊稽核。尚未安裝擴充時允許的降級會在同一交易內移除隔離完成標記，日後必須重新升級到 v2 並執行隔離升級。平台 grant v2 的受限回復見下節；不提供刪除已發行 grant 或歷史 receipt 的回復步驟，也不能用刪表處理不明發行結果。

## 私有撤銷 v2 增量

`build/upgrade-agent-platform-grants-v1-to-v2.sql` 從既有平台 grant v1 升級，要求 capability isolation v2 已完成；參數為 `agent_table_owner_role`、`agent_platform_grant_definer_role` 與既有 issuer 的 `agent_platform_grant_role`。環境從既有 binding 取得。升級以單一交易安裝狀態讀回、撤銷、永久撤銷收據及精確權限稽核。此版本不修改既有 capability isolation marker 的 v2 語義；PlatformGrant audit 必須另回 profile 2。

v2 使用保存於 `build/agent-platform-grants/v2/provision-agent-platform-grants.sql` 的歷史配置腳本；根目錄同名腳本目前要求 v3。除既有 issuer 參數外，增加不同的 per-environment `agent_platform_grant_revoker_role`。Issuer 只發行，revoker 只讀回／撤銷；平台流程統一呈現，底層登入與 pool 維持用途隔離。不能把既有 Web、issuer 或其他 Agent 服務登入改綁為 revoker。實際呼叫前，以兩個登入各自執行符合版本的 typed repository 啟動稽核。

呼叫必須保留完整原 issue receipt，不可只保存 grant ID。狀態結果含資料庫查詢時間及適用的狀態變更時間；撤銷永久記錄 Revoked、Expired、Consumed 或 AlreadyRevoked。Consumed 不表示憑證已撤銷。精確重試保留相同 operation ID、完整 receipt 與 digest；取消或連線中斷不能當作交易未提交的證明。詳細時間與恢復契約見[私有撤銷與讀回](../architecture/platform-grant-revocation.md)。

`build/downgrade-agent-platform-grants-v2-to-v1.sql` 提供受限回復。存在任一撤銷收據時不得降級或刪除歷史。合成測試已驗證回復及重新升級；正式部署仍須在目標環境，以新、舊服務的實際登入執行稽核並保留證據。

受限降級需指定上述 table owner、definer、issuer 及 `agent_platform_grant_revoker_role`。整個資料庫須恰好只有一個撤銷 binding，且符合指定 revoker 與環境；其他環境或角色另有撤銷 binding 時拒絕執行。腳本使用 psql 目前連線的 `DBNAME`，並先核對 `current_database()`，不可用另一個資料庫名稱覆寫。通過精確 v2 前置稽核後，降級須在同一交易內移除撤銷函式授權、binding、能力保留及 revoker 的直接資料庫 CONNECT／schema USAGE，並將角色設為 NOLOGIN；最後驗證 v1 契約與角色停用結果。

PostgreSQL 的 PUBLIC CONNECT 可能仍給予間接連線權限，因此角色停用以 NOLOGIN 與零角色 membership 為必要條件。日後重升級不會自動恢復此登入：部署管理員須另行明確、可稽核地啟用該角色，再執行 provision。正常 provision 要求角色已具 LOGIN；遇到仍為 NOLOGIN 的 revoker 必須零變更失敗。

## 發行許可期限 v3

完整完成 lifecycle v2 的升級及雙角色 provision 後，才能執行 `build/upgrade-agent-platform-grants-v2-to-v3.sql`。尚未建立 revoker binding 的半完成 v2 安裝不符合前置條件。升級前應停止相關 worker／發行呼叫，保存仍待調和的完整收據；本次程式尚未啟用 worker。

v2→v3 升級參數為 `agent_table_owner_role`、`agent_platform_grant_definer_role`、一個既有 issuer 的 `agent_platform_grant_role` 及其既有 revoker 的 `agent_platform_grant_revoker_role`；不需要 `environment_id` 或 `DBNAME`。命名登入作代表性驗證，腳本仍會檢查全部環境 binding，並依各自用途保留新、舊函式的 EXECUTE 權限。新版 provision 則使用上述四個角色，加上 `environment_id` 與 psql 目前連線的 `DBNAME`；每個環境分別執行。

新收據保存 issue contract 2 與 `MintPermitNotAfter`；既有收據保留 contract 1、NULL deadline。新發行在最後一把必要鎖取得後使用資料庫時間檢查有限的許可期限，超過期限拒絕發行；grant TTL 仍固定為首次成功發行後 600 秒。精確重試可在許可到期後恢復原收據，不更換 token、不延長期限。舊七參數發行函式只恢復既有 legacy 收據，新的 issue 使用八參數 overload。

升級後 lifecycle audit 必須回 profile 3；capability isolation marker 仍為 2，不可混為同一版本。再套用 `build/provision-agent-platform-grants.sql`，並以每個環境的 issuer／revoker 登入驗證稽核。舊 v2 repository 不能通過 profile 3 啟動檢查，部署必須搭配新版程式。

沒有提供 v3→v2 自動降級。不能刪除 deadline 欄位、重寫收據、恢復舊 mint 函式或自行切換 profile 來回退；應停用新增服務組合並保留 schema／收據作調和。歷史 v2→v1 腳本在 profile 3 上會拒絕執行，即使表中沒有業務資料也不能略過檢查。

完整平台操作與未完成的 worker／密文交付契約見[排隊與恢復](../architecture/platform-grant-execution.md)。

## 唯讀狀態 profile 4

此版本讓後續領取流程以專用狀態查詢 LOGIN 讀回 grant，不必取得 revoker 的撤銷權限。平台使用者仍在同一設備頁操作；用途隔離由服務內部處理。

先部署接受精確 profile 3／4 的 issuer 與 revoker 程式，再停止相關呼叫、備份資料庫並執行 `build/upgrade-agent-platform-grants-v3-to-v4.sql`。參數沿用 table owner、platform definer、既有 issuer 與 revoker；升級檢查全部既有 binding，單一交易加入唯讀函式、purpose 與 profile4 audit。升級時可以尚未有 status LOGIN，讓既有簽發／撤銷程式繼續通過稽核。

每個環境另備妥唯一的 LOGIN，使用 `build/provision-agent-platform-grant-status-reader.sql`，傳入 `agent_table_owner_role`、`agent_platform_grant_definer_role`、該環境既有 `agent_platform_grant_role`、`agent_platform_grant_revoker_role`、新的 `agent_platform_grant_status_role`、`environment_id` 與 psql 目前的 `DBNAME`。不可重用 issuer、revoker、Web、其他 Agent capability 或 owner／definer 的角色。

新的 `PostgresPlatformGrantStatusReader` 僅接受 profile 4。以三個實際 LOGIN 分別完成 repository 啟動稽核：issuer 只簽發，revoker 只讀回／撤銷，status reader 只使用兩個 `read_initial_enrollment_grant_status` overload；共同保留 audit EXECUTE。狀態查詢綁定完整收據，不能只送 grant ID。

根目錄原有 v3 provision 仍是歷史 profile3 配置腳本，不能在 profile4 重跑它來修復 ACL。Capability isolation v2 的升級／重跑需使用本次一併更新的版本，以識別並保留 profile4；capability marker 本身仍為 2。

沒有提供 v4 自動降級。回復程式時保留 profile4 與歷史收據，先停用新增 status reader，使用可接受 3／4 的 issuer／revoker 程式調和。不要重寫 audit 版本、刪除新函式或修改歷史 receipt。此增量不會啟用領取 API、listener 或正式企業設備註冊；其交付限制見[領取契約](../architecture/platform-grant-delivery.md)。

## 平台整合待辦

已提供唯讀 [EnrollmentTargetRead 與平台設備註冊準備狀態](enrollment-target-read.md)，先驗證有效會員、目前 Computer 與同一物件的 `Computer.View`／`AgentEnrollmentGrant.Manage` 交集，再解析 server-owned mapping tuple。Browser 不提供 server Device ID。沒有 mapping 或設備非 Active 時回明確資格狀態，不建立 outbox，也不自動新增 mapping；未配置 pool 時顯示不可用。安裝此能力需再完成 capability isolation v2 升級；完成後不得重跑會還原舊稽核的 v1 升級或 Projection 降級腳本。

平台已有 public operation 與排隊稽核；正式組合仍需 worker 用途隔離、密文持久化、worker 中斷調和、領取所有權及 ACK、available grant 撤銷、listener 與部署驗收。部署前需精確預覽、獨立覆核及環境操作授權；本次開發與合成測試不操作企業 AD、CA 或實際設備。

## v3 與平台排隊增量驗證

完整後端 957 項測試通過，包含私有授權 179 項、設備查詢整合 40 項；locked restore 及 Release build 零警告／錯誤。涵蓋限時發行、鎖後期限重查、v1／v2 收據恢復與撤銷、跨環境 binding 升級、精確 CHECK／audit body／部分 profile 漂移拒絕、cap-v2 重跑保留 v3，以及 v2 正向降級停用登入與明確重新啟用的歷史相容性。一般覆核與最終 SQL／C# 專項覆核均無剩餘阻擋。平台已提供排隊及歷史查詢程式，worker、grant 發行組合與正式企業註冊尚未啟用。

## v2 合併時的驗證證據（PR 33，非本次 v3 結果）

合成 loopback PostgreSQL 通過完整後端 925 項測試，包含儲存層 173 項與設備查詢整合 40 項；locked restore、Release build 通過，零警告／錯誤。涵蓋永久收據與重試、terminal 狀態讀回、鎖等待跨越到期、並行 consume／revoke、取消、跨環境操作衝突、歷史 mapping 移除、完整角色／PUBLIC policy 集合、capability-v2 重跑保留新版稽核、升級回滾與降級停用／明確重新啟用。一般獨立覆核與最終專項覆核無剩餘阻擋。這些證據不表示公開執行或企業 Agent 註冊已啟用。

## v1 合併時的驗證證據

合成 loopback PostgreSQL 環境通過完整後端 645 項測試，包含本元件 28 項資料庫／靜態回歸；locked restore 與 Release build 通過，零警告／錯誤。涵蓋固定 TTL／精確重試、跨環境 operation 競爭、mapping writer 列鎖、目前環境斷言、連線失敗、封閉回應矩陣、額外 ACL／角色混用、安裝前置條件、升降級標記與交易回滾。另有 fresh-store／upgrade 函式及 runtime／provision 稽核條件的一致性測試。一般獨立覆核與專項安全覆核未留下阻擋項目；以上證據只涵蓋尚未啟用的私有儲存層。
