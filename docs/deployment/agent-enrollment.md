# Agent 註冊授權、發證調和與憑證格式

此模組接續本機 schema 2 身分及 Agent 接收資料庫，將一次性授權消耗、固定註冊編號、epoch 保留、發證工作與結果保存放入 PostgreSQL 交易。伺服器仍未開放 enrollment 或 mTLS listener，也未接上正式 CA。

## 一次性授權與重試

授權使用 32 bytes 隨機 token，資料庫僅保存 SHA-256。提交函式自行計算 token hash，不能把資料庫中的 hash 當作 bearer。環境由授權找到，再檢查 session_user 的 Enroll database binding；呼叫者不能自報另一環境。

第一次提交鎖定 grant 與 device，原子消耗授權，保留固定 registration ID、正數 epoch 與 issuance ID，保存完整 CSR、DeviceGuid、request ID 及 profile。完全相同的重試回同一結果，包括授權後來到期的情況；任一身分、CSR 或 request 差異會衝突。已發出的 epoch 不因失敗而重用。

此增量只處理 initial enrollment；已有 active registration 的設備不能走此入口。Renewal、撤銷與替換註冊需另行實作。grant 建立目前只供離線 table owner；平台 UI 發行授權仍需專用權限、scope 及稽核端點。

## 發證任務與結果不明

Issue 登入只能取得固定 issuance ID 的 lease。重領逾期工作仍使用同一個 issuance ID；未來 CA adapter 必須以該 ID 執行 IssueOrRecover，取回同一份 CA 結果。不能將網路逾時解釋為「一定沒有發證」。無法證明原 CA 結果時進入 OutcomeUnknown，停止自動發證；只有確認未發證的明確失敗才可標記 PermanentFailed。

完成函式以同一交易保存 active registration、certificate binding、不可變結果與 Issued 狀態。完全相同的完成重試回已保存結果；不同憑證或註冊 tuple 拒絕。連線或 commit 不明時 repository 回 Unknown，呼叫端需調和原請求。

## CSR 與憑證 profile v1

CSR 限制為單一完整 DER，最多 16 KiB。驗證使用 .NET 的 [LoadSigningRequest](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest.loadsigningrequest?view=net-10.0) 預設選項，保留內嵌公鑰簽章驗證，不載入 requested extensions 作為發證指示。先檢查 DER、金鑰界線及 signature OID，再驗證簽章。

允許 RSA 3072–8192 bits、奇數 exponent 65537–UInt32.MaxValue 與 PKCS#1 SHA-256／384／512；或具名 P-256/SHA-256、P-384/SHA-384。Profile v1 不支援 RSA-PSS、explicit EC parameters、SHA-1、其他曲線或含糊／重複 attributes。CSR subject、SAN 及 extension request 都不決定平台身分；平台從核定的環境／設備／註冊與 epoch 建立單一 URI SAN。

Leaf 必須有 CA=false 的 BasicConstraints、僅 DigitalSignature 的 KeyUsage、僅 ClientAuth 的 EKU，以及完全相符的單一 URI SAN。BasicConstraints／KeyUsage 必須 critical，EKU／SAN 必須 noncritical；只額外允許 noncritical SKI／AKI。金鑰需符合原 CSR，有效期最長 93 天。所有憑證均有大小界線，且中繼／root 需是合格 CA、具 KeyCertSign、符合金鑰與 SHA-2 演算法要求。

憑證鏈只接受設定中釘選的 roots 及回應中的確切有序中繼；停用憑證下載，拒絕重複、額外、錯序或非 CA 中繼。回傳型別使用複本，不能由呼叫者修改已驗證內容。

這個內部驗證器的範圍明確為 **IssuanceMaterial**，RevocationStatus 與 IssuerOperationBindingStatus 都是 **NotChecked**。它沒有 Authenticated／Trusted／UsableForTls 旗標。issuance ID 是持久化工作的參照，未宣稱由憑證簽章綁定。正式 CA composition 還須證明固定 issuance ID 對應的原 CA 操作、確切 leaf 及當時撤銷狀態；正式 TLS listener 另須檢查當下信任鏈與撤銷。這些條件未完成前不能啟用服務。

## 權限及驗證

既有 Agent table owner 擁有新增表格；獨立 NOLOGIN enrollment definer 僅擁有固定函式，透過明確 DML grants 與 FORCE RLS policy 存取必要資料，沒有 schema CREATE 或 table ownership。Enroll 與 Issue 登入只取得各自函式 EXECUTE，使用不同 pool 與精確環境 binding。新增函式不授予 PUBLIC 或 ingestion login。

測試只使用 loopback 的 `console_test`／`console_ci` 與合成 token、CSR、CA／leaf。AgentIngestion 和 AgentEnrollment fixture 透過相同 PostgreSQL advisory lock 排他使用固定私有 schema；專用連線關閉才釋放鎖。既有 schema 不屬於該次 fixture 時拒絕初始化，清理只移除自己建立的狀態。
