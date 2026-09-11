# 平台個人收藏

原始需求 68：電腦、使用者、群組及 OU 可從物件明細加入或取消收藏；側欄「我的收藏」集中顯示，電腦可直接開啟完整設備明細。收藏屬於登入者在各環境的個人資料，不變更 AD。

`GET /api/v1/environments/{environmentId}/favorites` 每頁預設 50、上限 100，使用受保護的 cursor 綁定環境、使用者與目錄 generation。查詢先套用各類型的 View scope，再分頁，不回傳無權查看的物件、歷史名稱或隱藏筆數。目錄未 Ready 或超過 15 分鐘未同步時回 503；generation 改變的 cursor 回 409，介面提供重新整理。

`GET /favorites/{objectId}` 回傳目前物件是否已收藏；`PUT` 加入收藏，由伺服器判定物件類型，重試保留原建立時間；`DELETE` 取消收藏。上述路徑均位於同一 environment API 前綴。DELETE 僅檢查收藏擁有者與有效環境資格，對不存在、已移出查看範圍及已刪除的物件一律回 204，允許清理過期的個人資料。PUT／DELETE 套用既有 session、Origin 與 CSRF 檢查。

每位使用者在每個環境最多 500 筆收藏，包括暫時不可見的舊收藏。新增時鎖定 membership row，於 serializable 交易中檢查容量及寫入；並行衝突回 409，重送已存在的收藏不占額外容量。資料表採 FORCE RLS，EnvironmentId、PrincipalId 皆需符合伺服器設定的交易 context，且 principal 必須啟用並具有 active membership。資料表不參照目錄 generation，避免移除目錄物件時連帶刪除個人收藏。

部署時先執行 `DirectoryFavorites` migration，再以既有 `build/provision-runtime.sql` 更新 runtime role 的資料表權限。只新增平台資料表；rollback migration 會移除收藏，操作前需保留資料庫備份。

驗證使用合成資料：四類型加入／取消與冪等、雙使用者隔離、scope／generation 失效、CSRF、偽造 actor、RLS 與並行容量。瀏覽器測試涵蓋桌面／手機、錯誤與空結果、session 到期，以及切換環境時丟棄舊回應。
