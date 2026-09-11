# 個人儲存篩選

平台的「儲存篩選條件」頁可新增、編輯、移除及執行個人查詢。每個環境、每位使用者最多 50 筆；不共用、不當作角色範圍，也不保存查詢結果或授權。建立與刪除篩選不會變更 AD 或設備。

目前定義為 schema 1：名稱、User／Group／Computer／OrganizationalUnit 類型、字面文字搜尋及選用的設備 Tag ID。搜尋比對目前目錄的名稱或帳號；Tag 只允許 Computer，必須屬於同一環境，已封存 Tag 仍可篩選。Finance Computers 可使用 Finance 標籤保存；Age、Health、BitLocker、離線時間、磁碟與 MFA 尚未有跨設備查詢資料來源，因此此版本不能建立那些條件，不以空結果冒充支援。

## API 與版本

- `GET /api/v1/environments/{env}/saved-filters` 回傳最多 50 筆個人定義。
- `POST` 同一路徑接收 `{schemaVersion:1,name,kind,search,tagId}`，回傳 201 與伺服器產生的 ID、版本及時間。
- `GET /saved-filters/{id}` 讀取單筆；`PUT` 更新定義，`DELETE` 刪除，兩者要求 `If-Match: "version"`。缺少標頭為 428，過舊為 412。
- `GET /saved-filters/{id}/results?filterVersion=1&limit=50` 執行查詢；續頁帶回傳 cursor。filterVersion 必須是使用者目前看到的版本，不能省略。定義變動回 409 `SavedFilterChanged`，畫面要求重新整理清單，不會在舊條件標示下執行新條件。

所有個人操作要求有效會員資格，所有權取自 session，不接受 PrincipalId、EnvironmentId 或 caller-supplied ID 欄位。名稱最多 128 字元且不能空白，搜尋最多 128 字元；拒絕控制字元、未知欄位與不支援的 schema。沒有任意運算式、排序、SQL 或 LDAP 查詢輸入。

執行端重新檢查會員、15 分鐘內 Ready 目錄快照及目前種類對應的 View scope，再套用儲存條件。結果不含未授權總數。游標綁定環境、使用者、Filter ID／版本／定義、環境授權版本、目錄 generation 與排序位置；來源或權限漂移時拒絕沿用舊頁。

## 持久化與部署

套用 `20260911193547_SavedFilters`，再執行更新的 runtime provision。SavedFilters 使用環境／使用者／ID 複合主鍵、會員及同環境 Tag 外鍵，以及 FORCE RLS，只有對應使用者與有效會員資格可讀寫。Runtime 只能更新名稱、種類、搜尋、TagId、版本與更新時間，不能修改身分或建立時間。並行新增鎖定會員資料列後檢查 50 筆上限。

此為個人偏好功能，不需要 Owner 權限或雙人核准；儲存條件不授予新的目錄權限。重新整理、切換環境或 session 到期會清除舊結果；重複按執行也會重新查詢。

停用時可回退應用並保留個人定義。EF Down 會刪除 SavedFilters 表，正式回退前須先備份；不會刪除目錄或標籤。驗證使用合成 PostgreSQL 與模擬瀏覽器，真實企業部署仍需另行驗收。

## 驗證

本次通過 607 項後端測試（其中 188 項 Integration，包含 8 項儲存篩選整合測試）、18 項前端單元測試與 118 項瀏覽器案例。建立與更新時間統一為 PostgreSQL 微秒精度，確保寫入回應與重新讀取一致。一般覆核與專項安全覆核均無未解決阻擋項目。
