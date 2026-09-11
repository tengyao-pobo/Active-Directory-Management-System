# 版本化 AD 保護政策與保守分類

DirectoryProtectionPolicy 以不可變集合保存明確受保護 GUID、完整 SID 與群組 SID。建立時必須由未來受控佈建流程提供獨立驗證過的目標網域 SID 與 forest-root SID；字串格式檢查本身不是來源驗證。無 HTTP 建立政策端點、持久化或正式註冊。

基線包含網域 Administrator / krbtgt、常見管理群組、DC / RODC、Protected Users / key administrators，以及 forest-root 的 Schema / Enterprise Admins 與 Builtin 管理 aliases。組織額外指定的 VIP、服務帳號、特殊 Tier-0 物件可加入集合。使用完整 SID，不以名稱、RID 尾碼或目標 SID 自行推測網域。基線採保守超集合，不能用來宣稱涵蓋組織所有特權。

政策 Hash 為 SHA-256：UTF-8 無 BOM，每欄位前加 signed int32 big-endian byte length，null=-1。欄位依序為 ProtectionPolicy/v1、Classifier/v1、environment GUID(D)、domain GUID(D)、version(十進位)、domain SID、forest-root SID、GUID 集合數量與字串排序內容、SID 集合數量與 ordinal 排序內容、group SID 集合數量與 ordinal 排序內容。GUID 一律小寫 D 格式，數字 invariant，集合凍結且去重。固定測試向量另以 Node crypto 計算交叉驗證。這是漂移指紋，不是簽章；任何規則語意改變都必須增加 classifier 版本。

DirectoryEvidenceBinding 升級 schema v3，必須包含 ProtectionPolicyHash。因此即使 version 沒變，內容被替換也會造成不一致；未來持久層另須強制不可變內容及單調版本。舊 v1/v2 binding 不接受。

## 判定順序

1. 驗證完整 binding、物件 GUID/domain/config/policy、一致的直接讀取來源與時間區間。失敗回 Unknown。
2. 政策環境、網域、版本、Hash 必須一致。明確 GUID 或既有 protected 標記回 Protected。
3. Facts provider 必須回傳綁定實際讀取來源 DC / invocationId 與實際目標的事實。窗口須位於目標讀取後、不可過期或在未來。
4. 已知服務帳號、VIP、特權分類，或任一有效受保護 SID 命中，優先回 Protected，不因其他欄位資料不完整而降為安全。
5. 任一必要維度缺失、default collection、非法 SID 或超過上限回 Unknown。僅所有必要負向證據完整才回 Unprotected。

Facts 使用 ImmutableArray，群組／SID history 每類最多 10,000。GroupsComplete 的正式語意必須包含 transitive security-token 群組、巢狀／primary group／跨網域可用性；完整性不能由「回傳空陣列」推論。沒有 adminCount 或 tokenGroups 絕不代表未受保護。

成功 Unprotected 判定保留 FactsHash、讀取起迄及理由，收據組裝器會再檢查摘要與時間。FactsHash 是長度前綴編碼的完整 binding、目標 DN/USN、事實時間、SID 與已驗證集合的摘要；完整負向旗標由 CompleteNegativeFacts 版本語意固定。這保留一致性及追溯資訊，但不是跨信任邊界的證明。

## 正式接線限制

目前預設 Facts provider 不可用，Unknown assessor 仍保留。測試的完整負向 Facts 是合成資料，不得用於正式目標。未來唯讀 provider 必須從實際 DC 取得完整事實，而不是把呼叫者宣告的 binding 複製回來假裝驗證完成；ReadServer / ReadObjectId 是必要 postcondition。接點尚未加入生產 DI / API / 執行路徑。

參考：[Microsoft protected accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)、[SID](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)、[tokenGroups](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups)。

無資料庫 migration 或 AD 操作。回復時同步回復 Core / ConnectorHost，避免 binding v3 不相容。下一步接受控事實讀取，再整合持久化計畫與雙人核准；其他 Agent / Inventory 開發同步依全項目追蹤推進。

安全複核確認本階段可維持隔離交付。正式來源接線前還需綁定 VIP／服務帳號／特權分類目錄的來源版本或 Hash，且網域 SID 佈建要有獨立驗證證據。政策摘要採上述長度前綴二進位規格，不是 JSON canonicalization。後端 213 項通過（Core 76、Connector 58、Security 5、Integration 74）。
