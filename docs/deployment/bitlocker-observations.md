# BitLocker 狀態觀測

此增量提供獨立 `bitlocker` collector、伺服器接收驗證與設備 Security 頁籤，補充原始需求 39 的狀態來源。Windows Service composition、正式 enrollment／mTLS 與回復金鑰查閱仍未啟用；測試不查詢開發者電腦。

來源固定為本機 `root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume`。只查詢八個唯讀屬性：DeviceID、PersistentVolumeID、DriveLetter、VolumeType、ProtectionStatus、ConversionStatus、EncryptionMethod、IsVolumeInitializedForProtection。這些屬性與另行呼叫的方法定義見 [Microsoft Win32_EncryptableVolume 文件](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume)。程式不接受呼叫者傳入 WQL、namespace、主機或方法。

不呼叫加密、解密、protector、TPM 或回復密碼方法，也不查詢金鑰。加密百分比、protector 類型、TPM protector、AD DS／Entra escrow 及 recovery source 均未觀測，不能從 `IsVolumeInitializedForProtection=true` 或 `ProtectionStatus=1` 推論它們存在。完整系統後續需用受權限與稽核保護的另一路徑即時取得回復金鑰，不能把金鑰放入盤點、spool 或資料庫。

## 型別及品質

Data 固定為 `SchemaVersion=1, Volumes, IsTruncated, ErrorCode`。每筆 volume 使用八個具型別欄位；JSON 名稱為 `DeviceId`／`PersistentVolumeId` 及其餘屬性的原 PascalCase。必要 DeviceId 不得空白、含控制字元或超過 512 字元，無效列直接省略並標示不完整；不截斷身分。其他欄位可 null；0、false、合法空 PersistentVolumeId 都保留原意。uint32 的未來代碼原樣保留，後續顯示只能解讀成未知，不能自行等同停用或健康。

同一查詢成功回傳零列仍是 Observed，僅表示未觀察到 provider instance，不能據此判定 BitLocker 不適用。重複 DeviceId（不分大小寫）、不合規列、截斷或超過 128 列都使 IsTruncated=true。觀測屬性可能在不同時點改變，因此保留互相矛盾的狀態值，後續判定應呈現衝突或未知。

每個 reader instance 同時最多一個 native query。逾時／取消後若原查詢尚未結束，後續呼叫回 unavailable，不另起並行 WMI 查詢。中途存取拒絕、逾時或來源錯誤丟棄全部部分結果，只回固定錯誤碼與零筆資料；不把例外文字或 volume identifier 寫入 log。DeviceId 與 PersistentVolumeId 僅作為具驗證的盤點內容保存，不能加入一般 log／telemetry。

## 接收與部署

接收端以 exact keys、固定來源、真正 JSON number／boolean、uint32 範圍、count、identifier、去重及 status／quality／error matrix 驗證。未知 uint32 可接受，任何額外 recovery/password/key 欄位拒絕整個新 envelope，交易不更新 receipt、replay high sequence、snapshot history 或目前投影。既有 envelope 的精確重播仍回原收據。

伺服器須先部署新版 `agent-store.sql` 中的固定接收函式，再開始送出這個 collector；舊接收器不認得 `bitlocker`。現階段 Host 未組入 collector，不會在更新程式時自行啟動盤點或修改 Windows BitLocker。正式 Windows provider／權限驗收仍待隔離企業環境完成。

測試使用純 fake reader：涵蓋來源與欄位限制、未知代碼、空觀測、拒絕／逾時、native gate、截斷，以及 collector → spool → PostgreSQL 的精確重送與金鑰欄位排除。

## 平台查閱

設備明細的 Security 頁籤透過 `GET /api/v1/environments/{environmentId}/devices/{directoryObjectId}/bitlocker` 讀取。使用者須在同一份有效目錄快照中，對該 Computer 同時具備 `Computer.View`、`Computer.Inventory` 與 `BitLocker.ViewStatus` 的資源範圍。目錄快照須 Ready 且在 15 分鐘內；未通過範圍檢查時不讀取私有 Agent 資料。

目錄 Object GUID、伺服器 Device ID 與 Agent 本機 Device GUID 是不同身分。平台只經由明確的環境內綁定，取得目前 Active registration／epoch 的觀測，不以名稱猜配，也不退回舊 epoch 的資料。資料庫權限與部署順序見 [Agent 投影查閱](agent-projection.md)。

畫面區分 Missing、Unavailable、Current 與 Stale。收集時間、來源觀測時間、伺服器 receipt 時間皆須存在；任一時間超過伺服器時間 5 分鐘即不可用，任一早於 24 小時即過舊。Current 只描述查詢當下的資料時效；記錄中的 heartbeat 不代表現在上線。資料不完整時另外標示，未知代碼一律顯示未知，不將空清單或未知狀態視為正常。

API 只回傳磁碟代號、五個觀測欄位及必要時間／品質資訊。volume DeviceId、PersistentVolumeId、registration 與 receipt 識別碼不傳到瀏覽器。刷新失敗、切換裝置或 session 失效時清除先前觀測；不需要使用者另外開啟 RSAT 查閱。
