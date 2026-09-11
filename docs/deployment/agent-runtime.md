# Agent 排程、傳送接點與 Windows Service 宿主

此增量將 Agent library 的執行生命週期接上 .NET Generic Host / Windows Service。採用 Microsoft 的 [BackgroundService 與 Windows Service 整合方式](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service)，服務名稱為 `IT Management Inventory Agent`。這裡只提供程式與測試，未安裝或啟動本機服務。

宿主預設使用 NotConfigured composition，結束碼 2；它不會建立 spool、收集資料、生成註冊身分或宣稱傳送成功。正式啟用時需由已完成註冊／憑證驗證的 composition 建立並擁有 spool，再注入 IAgentRunLoop。不能只將一個環境變數改為 true 就跳過 enrollment。

SCM 停止服務時透過 CancellationToken 停止執行器。非預期結束或失敗會停止宿主並保留非零結束碼；日誌只記固定錯誤碼，不傳入可能含盤點或檔案路徑的 exception。服務復原策略、最小權限 service identity、檔案 ACL 與簽章安裝包仍須後續部署實作及驗收。

傳送／重送的信任界線見 [Agent 傳送契約](../architecture/agent-delivery.md)。Authenticated 標記僅代表可信 transport adapter 的判斷結果，不能由遠端 JSON 自報；測試 fake adapter 不可在正式 composition 註冊。

執行器只接受固定 collector 集合，預設完整盤點 24 小時、心跳 60 秒 ±20%，重送採有上限的退避與 jitter。每個 runtime 只執行一次，佇列同時最多送一筆；若 transport 不配合取消，逾時保留資料並停止，不能用另一個 runtime 繼續共用仍在傳送的 spool。永久拒絕或收據不符同樣停止並保留資料。

Envelope digest v2 的位元組順序固定為：signed int32 big-endian hashVersion=2、protocolVersion；DeviceGuid 小寫 D 格式 UTF-8；signed int64 big-endian epoch、sequence；request ID 小寫 D 格式 UTF-8；signed int64 big-endian UTC ticks（自公元 1 年起每秒 10,000,000 ticks）；小寫 payload hash UTF-8。每個字串前加 signed int32 big-endian UTF-8 byte length，不加 BOM。結果為小寫 SHA-256 hex；payload hash 仍涵蓋保存的 payload JSON bytes。固定向量已由 Node crypto 獨立核對。

此 v2 取代前一個尚未部署的 JSON framing。既有開發測試 spool 的 digest 不相容會拒絕讀取，不會自動重建身分、重算 hash 或丟棄資料；需保留舊版與舊目錄供診斷。此變更沒有正式端點資料遷移。

驗證：Agent 與 AgentHost 合成測試在 Linux / Windows CI 執行，宿主測試涵蓋正常取消、非預期完成、例外不外洩與未配置拒絕啟動。未執行真實端點盤點或服務安裝。
