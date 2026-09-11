# Agent 盤點基礎

本增量提供 .NET 10 Agent library、型別化觀測、收集器與本機離線佇列。Solution 與 CI 在 Linux 執行合成測試，另有 Windows Agent 測試工作；測試不收集 CI 主機或開發者的實際盤點資料。

## 已實作與資料界線

- 觀測帶有來源、時間、品質與收集狀態。Unknown、AccessDenied、NotApplicable 與成功觀測分開；失敗不填入假的正常值。
- 收集器執行器限制數量、並行度、等待時間與輸出大小，各收集器錯誤隔離。逾時取消是合作式取消，不能強制終止卡住的原生呼叫；目前只供固定可信收集器使用。
- 基本裝置收集包含主機名、OS 版本／架構與網路介面；軟體收集只讀 HKLM 的 32 / 64 位元 uninstall registry，沒有使用 Win32_Product，也不觸發安裝修復。
- Spool 使用本機 DeviceGuid、registration epoch、單調 sequence、request ID 與 payload SHA-256。DeviceGuid 不是伺服器 DeviceID，也不證明裝置已註冊。SHA-256 用於偵測 payload 損壞，不是簽章或身分驗證。
- EnvelopeHash 另外涵蓋版本化的 protocol、DeviceGuid、epoch、sequence、request ID、UTC 觀測時間與 payload hash，偵測中繼資料損壞；它同樣是未加密鑰的 digest，不抵抗可重算 hash 的本機修改者。截斷的盤點資料帶有 IsTruncated，後續判定不得當成完整陰性證據。
- 達到容量上限時拒絕新資料，不會靜默刪除尚未送達的舊資料。持久化 sequence 先於 envelope，因此中斷可能留下 sequence 空洞；接收端不能要求 sequence 必須連續。
- Core 提供可配置心跳狀態政策，僅以 server-received 時間分類：預設小於 120 秒 Online、120–900 秒 Stale、超過 900 秒 Offline；沒有時間是 NeverConnected，未來時間是 Unknown。註冊狀態須另外呈現；此增量尚未接收心跳。

## 啟用前仍需完成

Windows Service、安裝／升級／簽章套件、專用 spool 目錄 ACL、註冊及 epoch 變更流程、憑證保護／撤銷／輪替、mTLS 傳輸、經驗證的伺服器 ACK、心跳與快照接收、重送去重、歷史與資料庫投影。此 library 尚未接入 API 或部署為服務，不宣稱端點身分可信。

目錄需由服務安裝流程建立在管理員控制的私有位置。檔案鎖用來防止合作實例同時寫入，不能抵抗可寫目錄的攻擊者，也不能取代 ACL 或檔案系統防竄改設計。不得將 ACK 刪除介面直接暴露給未驗證的輸入。

## 驗證

執行 `dotnet test tests/Agent/Agent.Tests.csproj -c Release`；完整後端使用 `build/verify.ps1`。硬體、registry 權限、原生呼叫逾時與 Windows Service 生命週期仍需隔離 Windows pilot 驗收。

本增量 Agent 25 項合成測試與心跳政策 12 項測試通過。接續傳送的精確 ACK、重送與停止條件見 [Agent 傳送契約](../architecture/agent-delivery.md)。
