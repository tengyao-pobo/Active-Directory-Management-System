# AD 部門提案預覽

本階段提供使用者明細內的 SetUserDepartment 提案比較：精確 GUID、DN、目前與預計部門，以及快照時間。這是不可執行的資訊預覽，並非 Core DirectoryChangePreview 或持久化 ChangePlan。

POST `/api/v1/environments/{environmentId}/directory/users/{id}/proposal` 接受 `{kind:"SetUserDepartment",department:"Finance"}`。部門原始長度最多 128、不可空白或含控制字元，回傳值去除頭尾空白。需要有效 session、Origin、CSRF、環境 membership，並在同一筆目前 User 上同時符合 User.View 和 User.Edit 範圍。User.Edit 僅是額外查詢資格，不代表獲准寫入。Ready 快照不得超過兩分鐘或位於未來。

回傳 approvalAvailable=false、executionAvailable=false 與穩定阻擋代碼。snapshotValidUntil 僅代表快照有效時間，不是授權期限。未知保護狀態或已保護物件仍可提供已授權的資訊比較，但明確顯示阻擋原因。不產生計畫、核准、稽核、outbox 或 AD 變更。沒有新增 migration、權限授予、可執行 token 或 AD 寫入端點。

介面編輯輸入、離開目標或快照過期時丟棄比較，取消舊請求，核准按鈕永遠停用。無法預覽時顯示權限或快照不可用訊息，不呈現未經授權的目標資料。

驗證：後端 133 項（含 11 項新增整合案例）、前端單元 13 項；瀏覽器測試涵蓋 CSRF、前後值、核准停用、拒絕、過期及遲到回應。正式部署使用既有 build/publish 流程；可回復前一部署版本，無資料遷移。

下一階段先補齊 AD 核准所需的可信證據模型與隔離測試：DomainId、Connector 設定 hash、政策版本、帳號狀態、保護分類。這些證據成立後才能接獨立持久化計畫與雙人核准；不得直接套用現有平台管理 ChangePlan 的環境層級授權。真實 AD 寫入仍需受控驗收與明確授權。
