# AD 證據模型與隔離驗證

本階段增加 Connector 證據欄位及 Core 證據組裝契約。它不代表正式 AD 核准已可用；没有新增 API、DI 註冊、計畫、核准、資料庫欄位或寫入操作。

## Connector 證據

- VerifiedDomainId：保留既有 Base DN objectGUID 與設定 ExpectedDomainId 比對後的結果。
- ConfigurationHash：版本 2 的有效讀取設定 SHA-256 摘要，包含 host、Base DN、domain GUID、分頁與時間上限，單一目標讀取契約與期限，以及固定 LDAPS/636、Negotiate、不追蹤 referrals、平台憑證驗證語意。這是設定一致性指紋，不是簽章、身分證明或授權。
- ReadStartedAt / CapturedAt：保留整次分頁讀取區間。不能把完成時間當成所有物件的實際觀察時間；組裝器以起始時間計算兩分鐘新鮮度。
- Enabled：讀取 userAccountControl 的 ACCOUNTDISABLE bit，缺值為 null，非法格式或多值拒絕整次讀取。Group / OU 不推論帳號狀態。依據 [Microsoft 文件](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)。

以上新增欄位只存在 Connector 的記憶體結果；現有資料庫投影與 UI 不會將它們當成可執行證據。LDAP 保護分類依然為 unknown，不根據 adminCount 或其他單一屬性猜測為安全。

## Core 組裝界線

DirectoryEvidenceAssembler 接收伺服器端預期綁定、直接目錄讀取、範圍判定及保護判定。每個判定包含環境、網域、物件、操作者、操作權限、政策版本、設定摘要與契約版本，並以 DN / USN 綁定觀察對象。DisableUser 要求 User.Disable，SetUserDepartment 要求 User.Edit。

組裝器拒絕快取或未知來源、任一綁定不一致、過期／未來／顛倒時間、讀取前作出的判定、拒絕範圍、未知或受保護物件，以及無法確定啟用狀態的 DisableUser。成功值的 ObservedAt 使用整次讀取的起始時間。正向旗標必須來自獨立且對應目標的判定，不能沿用物件上的 ScopeKnown / ProtectionKnown 宣告。

**資料型別與來源 enum 本身不提供信任。** 呼叫端將來必須從受信任的 Connector 與即時授權／保護評估服務取得輸入，不能接受瀏覽器傳來的判定，也不能將資料庫快照標成直接讀取。當前沒有生產呼叫端；合成測試提供正向判定以測試契約。成功回傳只代表輸入一致且符合檢查，並非授權、核准或原子性保證，仍不能執行 AD 寫入。

## 驗證與部署

使用 fake LDAP transport 和合成判定測試，不連接真實網域。測試涵蓋設定指紋變化、GUID 比對、讀取區間、UAC 解析、逐欄位綁定漂移、來源降級、時間邊界與判定順序，以及寫入 adapter 持續回傳 Unavailable。執行 build/verify.ps1 進行完整後端驗證。

無 migration 或權限授予；按既有流程重新發佈 Connector/Core 即可，回復前一版本可撤回。新的 UAC 非法回應將使同步失敗並保留不可用狀態，而不是提供可能錯誤的啟用資訊。

單一目標重讀與保護分類服務接點已完成，詳見 [ad-target-read.md](ad-target-read.md)。目前接點尚未註冊為正式服務，保護分類預設仍為 Unknown。下一階段是可版本化保護政策及唯讀分類器，再建立獨立持久化計畫與雙人核准。真實 AD 寫入仍需受控驗收與明確授權。

安全複核後的成功結果為 DirectoryEvidenceReceipt：保留 Binding、完整讀取觀察、範圍及保護判定、與正規化的 Evidence。建構子僅供 Core 組件內使用。未來計畫橋接必須使用完整收據，不能只取出 Evidence 丟失操作者與權限等綁定。收據仍不是可跨信任邊界驗證的 token。綁定 schema v2 已要求完整 DC DNS / Service DN / DSA GUID / Invocation ID，單一目標讀取會比對前後來源。因為 uSNChanged 是 DC 本機版本，不能省略這項綁定；這也不代表未來寫入具有原子性。

最新目標重讀階段本機後端驗證：184 項通過（Core 48、Connector 58、Security 5、Integration 73），建置無警告或錯誤。
