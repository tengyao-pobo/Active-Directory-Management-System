# Agent 傳送流程實作契約

此文件描述接續盤點 library 的排程與傳輸要求，不代表網路端點或憑證生命週期已啟用。

每個 spool identity 同時最多傳送一個 envelope。重試保留原始 DeviceGuid、epoch、sequence、request ID、observedAt 與 payload，不得以新序號重新包裝既有資料。排程僅可呼叫編譯好的盤點收集器，遠端要求不能提供命令、URL、路徑或模組名稱。

Transport 結果為 Accepted、AlreadyAccepted、Retryable、PermanentRejected、IdentityConflict 或 Unknown。尚未配置的 transport 永遠回 NotConfigured；禁止預設成功。取消、逾時或連線中斷可能發生在伺服器完成提交之後，因此保留原 envelope。關閉時停止重試，不丟棄資料。

ACK 必須來自經驗證的連線，逐欄綁定 ACK schema、protocol、DeviceGuid、epoch、sequence、request ID、UTC observedAt、payload hash，並綁定完整 envelope 的版本化 digest。刪除前重新讀取佇列檔案核對，不只比對 sequence/payload hash。任何不一致停止該身分的傳送並保留檔案。AlreadyAccepted 只能回傳伺服器原本已持久化的同一份收據。

Retryable / Unknown 使用有上限的 exponential backoff 與 jitter；Retry-After 同樣設上限，成功驗證 ACK 才重設重試次數。PermanentRejected / IdentityConflict 保留資料並停止，不自動跳過、變更 epoch 或建立新身分。佇列滿時施加回壓，不覆寫最舊資料。

伺服器以實際憑證對應的註冊身分及 epoch/sequence 做持久化去重，不以 payload 自報 DeviceGuid 決定授權。同 key、同 envelope 回原結果；同 key、不同 envelope 拒絕。先提交資料再回 ACK，允許 sequence 空洞。重播心跳不能刷新 lastSeen。

正式啟用還需 enrollment、mTLS 憑證生命週期、主機名稱驗證、撤銷、server replay window、受限資料 schema、spool ACL 與 reparse 防護。不得加入匿名 fallback、忽略 TLS 驗證、內嵌憑證或自動產生可用的正式註冊身分。診斷僅記固定錯誤碼與計數，不記錄 payload 或 credentials。
