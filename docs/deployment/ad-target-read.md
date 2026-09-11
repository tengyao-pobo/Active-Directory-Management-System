# 單一 AD 使用者重讀與判定服務接點

本階段提供 IDirectoryTargetReader / LdapDirectoryReader.ReadUserAsync，以及 ConnectorHost 內的 DirectoryTargetEvidenceService。服務未註冊到正式執行流程，沒有新增 HTTP API、資料庫欄位、核准或 AD 寫入。

## 受控重讀

輸入僅為非空 object GUID，連線仍由受保護服務設定指定。使用同一個 LDAPS / Negotiate transport，維持平台憑證驗證、不追蹤 referral。先驗證 naming context 和網域 GUID，再取得來源 DNS 名稱、dsServiceName、DSA objectGUID 與 invocationId；GUID 查詢完成後重新讀取 RootDSE 並解析來源身分，任一變更均拒絕。網域 GUID 亦重新確認。

GUID 查詢採固定 User/person 類別與二進位 GUID escape，固定屬性清單、SizeLimit=2、不使用 paging。零筆、多筆、GUID 不符、Computer、命名範圍外、無效 USN 或來源身分缺值均失敗。缺少 invocationId（包含因權限或 RODC 而無法讀取）不允許以 DSA GUID 替代。

TargetReadTimeout 預設 30 秒，最大 60 秒。總期限取消後停止等待並釋放 transport；同步 LDAP 呼叫仍受 RequestTimeout 限制，受管取消無法證明遠端伺服器立即停止處理。這是唯讀請求，沒有寫入結果不確定問題。設定摘要升級為 v2，納入目標讀取契約版本與時間限制。

來源文件：[RootDSE](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adrootdse)、[invocationId](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/e8d35b69-07f4-48c9-8a99-e84c8220bed4)、[LDAP filter syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)。DC objectGUID 與資料庫 invocationId 必須一起綁定，不能將跨 DC 的 USN 當成同一個版本序列。

## 服務與信任界線

Core DirectoryEvidenceBinding 在此階段升級 schema v2（後續 [保護政策](ad-protection-policy.md) 已升為 v3 並加入政策 Hash），Server 是必要欄位，包含完整來源身分並隨每份判定及成功收據保留。旧 schema v1 不再接受。

DirectoryTargetEvidenceService 比對預期網域、設定摘要、GUID、種類與來源，再把同一筆觀察傳給 IDirectoryScopeAssessor、IDirectoryProtectionAssessor，最後交由既有組裝器驗證。預期綁定必須由未來伺服器控制層從受信任設定和操作者身分建立，不能從瀏覽器接受或用觀察結果自動替换預期來源。

目前僅提供 UnknownDirectoryProtectionAssessor，永遠回傳 Unknown。Scope assessor 的正式實作尚未提供；測試使用明確標示的合成評估器。這完成服務接點及隔離整合，**不是完整保護分類政策**，不根據 adminCount 或缺少群組資訊推論 Unprotected。正式資料永遠不能套用測試中的正向判定。

成功收據仍只是完整一致性資料，不是授權 token、數位簽章或核准。相同連線及前後身分比對不代表讀取與未來寫入之間具有原子性；未來執行仍需要重新驗證、持久化核准與結果 readback。

## 驗證與回復

fake LDAP transport 驗證正向讀取、前後來源及 invocationId 變更、缺值、錯誤網域、GUID byte order、查詢上限、錯誤目標、越界 DN、逾時與取消。Core 測試驗證 Server 每欄位漂移；隔離服務測試驗證 Unknown 阻擋、完整收據保留、錯誤來源不進入評估器、換操作者及過期觀察拒絕。未連線真實 AD。

無 migration 或新權限。重新部署相關程式即可；回復前一版時同時回復 Connector/Core，以避免摘要 v2 與綁定 v2 的契約不一致。現有快照同步及前端維持原流程。

下一階段：實作可版本化的保護政策及唯讀分類器，先辨認明確受保護目標並對不完整證據維持 Unknown，再做隔離測試。之後才將可信判定接上持久化計畫與雙人核准；正式 AD 寫入仍需受控驗收及明確授權。

本機測試共 184 項通過：Core 48、Connector 58、Security 5、Integration 73。建置零警告、零錯誤。
