# 平台設備註冊準備狀態

設備 Inventory 頁籤內提供 Agent 註冊準備狀態與重新查詢。操作在平台內完成；公司原本使用 RSAT 不影響此流程。這一段只檢查目前目錄設備與平台設備對應，不建立 mapping、不核發 token，也不啟用正式 Agent 註冊、worker、CA 或 listener。

## API 與授權

`GET /api/v1/environments/{environmentId}/devices/{directoryObjectId}/enrollment-target` 先驗證有效會員、15 分鐘內完成且非未來時間的 Ready 目錄快照、目前 generation 的 Computer，再分別套用同一物件的 `Computer.View` 與 `AgentEnrollmentGrant.Manage` 範圍。全部通過後才呼叫私有 reader。後者為 Owner-only 權限，角色名稱叫 Owner 並不足夠；實際 BuiltInKind 必須是 Owner。升級會將新權限補入既有內建 Owner，新的環境沿用內建角色權限集合。

成功只回 `status` 與 `queriedAt`：

| status | 意義 |
|---|---|
| Eligible | 查詢時存在 Active 設備的目錄對應，可供下一步重新驗證的註冊申請使用 |
| MappingRequired | 缺少對應，或對應設備目前非 Active |

未授權或目標不符回 404；目錄、reader、連線或回應格式無法確認時回 503。所有結果 `Cache-Control: no-store`。Browser 不接收 server Device ID、mapping 建立時間或私有診斷，也不能提交它們來選擇註冊對象。

`Eligible` 不代表 grant 已核准、沒有既有註冊或一定能發行。未來建立 proposal 必須重新解析並保存 exact mapping tuple，mint 仍需再次鎖定／核對 mapping、設備與既有 enrollment 狀態；GET 結果不能作為持久授權證據。

## 設定

`EnrollmentTargetRead:Environments:{environmentId}` 每個環境需要獨立的 `ConnectionString`、`TableOwnerRole`、`FunctionOwnerRole`。環境 ID 使用 GUID D 格式。最多 32 個環境，連線與命令 timeout 上限均為 10 秒；非 loopback PostgreSQL 必須使用 VerifyFull TLS。

沒有配置的環境回不可用，不會回退到 Console Web、Projection、Ingest、Enroll、Issue 或 grant worker 登入。設定不合法或啟動權限稽核失敗時，API 以去除連線細節的錯誤拒絕啟動。憑證與連線字串由部署 secret 管理，不寫入版本庫。

## 私有查詢與隔離

固定 resolver 每次先由 SESSION_USER binding 取得環境，再比對 expected environment。以單一 SELECT 快照讀取 mapping 與設備狀態；只有 Active 設備才回完整內部 tuple。沒有列鎖或資料寫入。

Target Read 使用專用 LOGIN 與 NOLOGIN definer。Runtime 只取得固定 resolver／版本稽核函式 EXECUTE；definer 只取得所需 binding、mapping 與 device 欄位 SELECT。通用 capability registry 升級用來拒絕舊／新服務之間的角色重用，且必須交易式完成既有角色登記、稽核替換及 postflight 後，才建立 isolation profile v2 完成標記。任何會還原舊稽核的 downgrade 在此標記存在時都需先拒絕。

部署前仍須完成精確角色與升級預覽、獨立覆核及實際環境操作授權。程式及 loopback 合成測試不代表企業 AD／CA／設備部署驗收。

## 安裝順序

1. 先完成 [平台授權儲存層](platform-grants-store.md) 的既有安裝與 isolation profile v1；既有資料庫使用相應升級腳本，不重跑建表腳本。
2. 使用資料庫遷移管理身分執行 `build/upgrade-agent-capability-isolation-v2.sql`。提供既有 `agent_table_owner_role`、`agent_definer_role`、`agent_enrollment_definer_role`、`agent_projection_definer_role` 與 `agent_platform_grant_definer_role`。Ingest 的 `agent_definer_role` 沿用既有 table owner。
3. 執行 `build/agent-enrollment-target-store.sql`，提供既有 `agent_table_owner_role` 與新的 `agent_enrollment_target_definer_role`。新角色必須是專用 NOLOGIN，且不可與其他能力角色共用。
4. 每個環境執行 `build/provision-agent-enrollment-target.sql`，提供上述兩個角色、專用 LOGIN `agent_enrollment_target_role` 及 `environment_id`。透過 psql 連到目標資料庫，腳本使用其 `DBNAME` 變數；登入憑證由部署 secret 管理。
5. 執行各個既有 runtime 的權限稽核，確認新 reader 啟動稽核通過，再配置 API 的 `EnrollmentTargetRead`。沒有配置時平台維持明確的不可用狀態。

每份腳本使用交易；升級完成標記在 postflight 通過後才建立。v2 存在時，會還原舊稽核的歷史升級／降級腳本拒絕執行。此版本沒有刪除 registry 或回復舊隔離方式的自動降級；應先移除 API 的新 reader 配置以停用入口，保留既有資料與角色供檢查。需要資料庫回復時，使用事先驗證的備份與回復程序，不手動刪除標記來繞過版本檢查。

## 平台查詢驗證

34 項 API／設定測試通過，涵蓋同一設備權限交集、偽 Owner 角色、跨環境／generation、15 分鐘含界線的 freshness、未配置服務及不合法私有回應。完整桌面與手機瀏覽器回歸 130 項通過，包含繁體中文、重新查詢期間清除舊資格、未授權隱藏，以及切換設備後忽略延遲回應；前端 lint 與 production build 通過。這些平台測試使用合成資料與受控 reader，不能代替私有 PostgreSQL 稽核或企業設備驗收。

完整方案 locked restore、Release build（零警告／錯誤）及 716 項後端測試通過。其中 37 項私有 PostgreSQL 測試涵蓋六種 runtime 稽核、跨環境、角色重用、registry／ACL／policy 漂移、升級冪等及 late postflight 失敗整筆回滾。平台介面及私有隔離完成各自的獨立覆核；測試使用 loopback 合成資料，未操作企業 AD 或 CA。
