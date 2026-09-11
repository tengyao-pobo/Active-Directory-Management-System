# Agent 投影查閱

平台 API 使用獨立的 Agent 投影讀取連線。此連線只供固定 BitLocker metadata 查閱，不提供任意 collector、SQL、volume identifier 或 recovery key 查詢。正式環境的 Agent 註冊、CA、mTLS 與目錄綁定工作流程尚待完成；未配置時 API 回傳 `503 BitLockerUnavailable`。

## 資料與身分

`agent_device_directory_bindings` 明確綁定 environment、directory Object GUID 與伺服器 Device ID（`devices.device_id`）；兩個方向在環境內皆唯一。這個 ID 不是 Agent 本機持久化的 `device_guid`，也不能以目錄 GUID 代替。此表由部署 table owner 管理，Web、ingest、enrollment 與 projection runtime 均不得寫入。正式綁定必須來自後續受權限保護的註冊流程，不能由瀏覽器任意傳入對照。

讀取函式以 SESSION_USER 的 `agent_projection_database_bindings` 驗證固定環境與 ReadBitLocker 用途，再找出 Active device 與目前 Active registration／epoch。只有與其一致的目前投影才可回傳。可信 `received_at` 取自 receipt，其他來源的 collector payload 不回傳。

## 部署

先部署既有 `agent-store.sql`、`agent-enrollment-store.sql`，再以經核准的部署身分安裝 `agent-projection-store.sql`，最後執行 `provision-agent-projection.sql`。兩個新腳本皆在明確交易內執行；任何失敗須停止，不能把部分安裝視為完成。

投影使用新的 NOLOGIN function owner 與每環境一個專用 LOGIN。兩者不可與 table owner、ingest 或 enrollment 登入混用。function owner 只有必要欄位 SELECT；projection LOGIN 只有資料庫 CONNECT、私有 schema USAGE 與兩個固定函式 EXECUTE。安裝參數為 `agent_table_owner_role`、`agent_projection_definer_role`、`agent_projection_role` 與 `environment_id`，實際以各腳本列出的變數為準。角色建立與憑證／密碼配置由部署程序完成，不在原始碼內提供正式機密。

Web 設定使用 `AgentProjection:Environments:{environmentGuid}:ConnectionString`、`TableOwnerRole`、`FunctionOwnerRole`。只接受最多 32 組明確環境；沒有 catch-all 或預設共用登入。非 loopback 連線必須 VerifyFull TLS。連線與命令 timeout 最多 10 秒，例外訊息不向 API 或 log 暴露連線內容。

API 啟動時對每個池執行獨立 privilege audit，核對預期環境、角色、ACL 與 ownership。不合格設定使啟動失敗；未配置環境則在查閱時回不可用，不回退到 Web runtime、ingest 或 enrollment 連線。

## 驗證與恢復

測試只使用隔離 PostgreSQL 與合成 Agent／目錄資料。平台 API 測試涵蓋三種權限交集、scope／generation／membership 漂移、opaque denial、三個時間戳的過舊／未來／缺失、私有欄位排除及未配置行為。瀏覽器測試涵蓋桌面與手機、未知代碼、空觀測、不完整與過舊狀態，以及刷新失敗／401 時清除舊內容。

本機 locked restore、完整建置（0 警告／錯誤）與 521 項後端測試通過，其中投影 PostgreSQL 25 項、API integration 121 項。前端 lint、build、15 項單元測試及 92 項桌面／手機案例通過（90 項完整回歸，加上 2 項延遲 BitLocker 回應切換設備的新增案例）。一般正確性與 Daybreak 安全覆核均無剩餘 blocker。這些證據不等於真實端點、正式資料庫或企業環境驗收。

回退 Web 設定可停用投影讀取；資料表與 Agent 既有 receipt/history 保留。資料庫部署變更需另依核准的備份及回退程序處理，不以刪除 schema 作為正式環境的回退方式。
