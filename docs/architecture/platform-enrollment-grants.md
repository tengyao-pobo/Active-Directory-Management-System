# 平台 Agent 註冊授權

此文件定義平台統一發行 initial enrollment grant 的目標契約。公司工作站是否安裝 RSAT 不改變此流程；操作人員在平台提出申請、檢查精確設備、取得另一位操作人員核准並領取授權。此文件本身不啟用執行端點、背景工作、CA 或 listener。

私有原子發行、固定 TTL 與同一操作收據恢復的實作／部署界線見[平台授權儲存層](../deployment/platform-grants-store.md)。此資料庫元件與下列密文 primitive 尚未組合成可執行的平台工作流程。

## 授權與不可變計畫

新增 Owner-only、Computer scope 限定的 `AgentEnrollmentGrant.Manage`。提案與執行要求 fresh step-up、目前有效的目錄快照及精確 GUID。計畫保存環境、目錄物件 GUID、伺服器 Device ID、mapping 建立時間、目錄 generation、授權版本、固定 600 秒 TTL，以及一次性接收公鑰與其 SHA-256 fingerprint。核准者須與提案人不同，並有 `Change.Approve`；執行前再次檢查權限、版本及目標。

接收端公鑰由平台瀏覽器產生，私鑰不可匯出。計畫不得接受 token、私鑰、自報操作者或可執行命令。接收公鑰 fingerprint 必須全域唯一且永久禁止重用，包括失敗、撤銷、過期及封存的操作。

## 兩個資料庫交易之間的恢復

1. 平台執行交易只建立固定 GrantOperation、audit 及 outbox。此交易不呼叫私有資料庫函式，不產生 token。
2. 專用 worker 產生 32 bytes 隨機 token、計算 SHA-256 並加密給核定的接收公鑰。單一交易保存加密封套與 hash，清除原始 bytes；並行 worker 只能有一份封套勝出。
3. Worker 使用持久化的同一份 hash 呼叫私有 grant 函式。環境由登入角色 binding 決定，不能由函式參數選擇。此 pool 與 Web/API pool 分離。
4. 私有函式鎖定並核對 mapping tuple、active device、現有 registration、live enrollment request 與 available grant，使用 operation ID 建立或讀回同一份 grant。第一次成功的到期時間固定，重試不得延長。
5. Worker 將私有 receipt 保存回平台 operation。任何 commit 回應不明都先讀回再以同一 ID、hash 與完整 tuple 調和，不能重新生成 token。證實沒有寫入的明確拒絕可結束為 Failed；不一致或無法確認的結果保留 OutcomeUnknown。

## 領取、遺失與撤銷

只有原提案人經 fresh step-up 可領取加密封套，回應使用 `Cache-Control: no-store`。領取在 ACK 前回傳同一封套；首次 GET 後立即刪除會使回應遺失無法恢復，因此不採用。ACK 刪除封套，保留操作、hash 與 receipt 的稽核關聯。

私鑰遺失後不得將舊 token 重新包裝給新公鑰。先撤銷舊 grant，再經新提案與獨立核准建立新操作。正式啟用前須完成 available grant 撤銷與結果讀回路徑；已消耗或已發證的身分須進入各自的憑證生命週期，不能假稱撤銷 grant 已撤銷憑證。

## 啟用前驗證

需涵蓋授權／mapping 漂移、跨環境登入、並行 worker、每個 commit 中斷點、同一 receipt 恢復、token 不出現在 DB／log／API、錯誤金鑰、領取所有權、過期、現有 grant 衝突、遺失金鑰撤銷與 role／function／RLS 漂移。私有函式與 auditor 採精確 allowlist；新增能力不得放寬既有 Enroll、Issue、Ingest 或 Projection 登入的權限。

所有程式與合成測試先保持未註冊狀態。完成 pool、auditor、加密交付用戶端、listener、撤銷與部署覆核後，才另行啟用正式組合。

## 已實作的封套 primitive v1

目前僅交付隔離的 .NET 封套產生器與 WebCrypto 接收類別，未接上上述提案、持久化、領取 UI 或任何 listener。RSA 公鑰限 canonical DER SubjectPublicKeyInfo，最多 512 bytes；完整 import 後重新 export 必須逐 byte 相同，key size 固定 3072、exponent 固定 65537。Fingerprint 使用 SPKI 的 SHA-256。

提案可先使用 `EnrollmentGrantRecipientKey.Validate` 驗證接收公鑰並取得 canonical DER 與 fingerprint，這個步驟不產生 token 或封套。驗證器先複製輸入，再套用相同公鑰限制；封閉的 validated 型別只回傳 byte array 複本。`Seal` 使用此型別執行加密，既有 DER overload 也先經過同一驗證器。此型別僅證明公鑰格式，不能證明核准、fingerprint 未重用或操作者權限；後續平台交易仍須分別保證這些條件。

使用標準 [RSA.Encrypt](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.encrypt?view=net-10.0) 與 OAEP-SHA256，OAEP label 為空。上下文綁定放在固定 116 bytes 的加密明文：

| Offset | 內容 |
|---|---|
| 0–7 | ASCII `ADGRTOKN` |
| 8–9 | UInt16 big-endian 格式版本 1 |
| 10–11 | UInt16 big-endian purpose 1，InitialEnrollmentGrant |
| 12–47 | 非空 Environment ID，36 bytes 小寫 canonical UUID D |
| 48–83 | 非空 Operation ID，同上 |
| 84–115 | 32 bytes 隨機非全零 token |

伺服器 production 方法自行產生 token，不接收 caller-supplied token；回傳型別只提供密文、token hash、公鑰 fingerprint 的複本。payload 與 token 暫存於 finally 清除，沒有伺服器解密 API。

瀏覽器依 [Web Cryptography](https://www.w3.org/TR/WebCryptoAPI/) 產生不可匯出的私鑰，公鑰只供建立提案；接收器不把私鑰持久化。輸入只接受 `{formatVersion,recipientKeyFingerprint,ciphertext}`，密文恰為 384 bytes，base64url 無 padding 且 canonical。解密後核對全部格式及來自已驗證 session／operation 的預期 ID，不能從封套自己取 expected ID。錯誤統一 `InvalidSealedGrant`，不回傳底層密碼學錯誤。

token 以 binary buffer 與 AbortSignal 交給有界 callback，完成或例外後清除；dispose 會丟棄 key reference、清除正在使用的 buffer 並取消訊號。解密或 callback 執行途中 dispose，整次 consume 會以 `AbortError / GrantDeliveryCancelled` 拒絕，不能當作成功接續 ACK。Callback 必須將 signal 傳入後續 I/O；一般 callback 失敗只回 `GrantDeliveryFailed`，避免把操作錯誤誤報為密文錯誤，也不保留可能含 token 的原因。取消不保證外部副作用未發生，後續正式交付仍需讀回調和。

JavaScript 的記憶體管理不保證立即從程序記憶體移除 CryptoKey，callback 也不得自行複製、記錄或保存 token。ACK、撤銷、過期、session／環境變更或離開交付流程時，未來 UI 必須呼叫 dispose。OAEP 不證明發送者身分；HTTPS、授權 operation、fingerprint 與持久化狀態仍是必要條件。

可重現互通測試：在 `src/Web` 執行 `pnpm test:enrollment-interop`，先用 locked restore 建置 test-only console harness，再由實際用戶端產生 key，以 stdin 傳送公鑰到 .NET production 封套產生器。測試在用戶端解密、比對 hash、驗證跨 operation 拒絕及 buffer 清除。沒有已簽入的私鑰或固定 bearer，也不連接資料庫。CI 同時執行互通與 Windows 密碼學測試。

此增量在合成環境通過 617 項後端測試（包括 6 項新封套測試）、37 項前端單元測試、1 項 .NET／WebCrypto 互通測試及 118 項瀏覽器回歸案例。另完成取消生命週期的獨立覆核與專項安全覆核；這些證據不代表正式 enrollment 已啟用或完成企業端驗收。
