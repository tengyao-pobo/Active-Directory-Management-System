# Phase 5 — 電腦資產備註與生命週期

電腦目錄明細新增 IT 備註及 Unknown / Active / Spare / Repair / Retired 生命週期。資料存在平台 PostgreSQL 的 DeviceAssets，以 EnvironmentId + AD computer objectGUID 為鍵；不以主機名稱匹配，也不會修改 AD 或觸發遠端、盤點、自動化動作。這是 AD 電腦關聯的資產中繼資料基礎，尚不是 Agent 裝置身分、序號合併或完整資產台帳。

## API 與授權

`GET /api/v1/environments/{environmentId}/devices/{objectGUID}/asset` 回傳 item（尚無資料時為 null）、canEdit 與 ETag。item 僅包含 lifecycle、notes、version、updatedAt；不暴露編輯者身分。能以 Computer.View 讀取該電腦者可讀取備註，包括具此權限的 Viewer/HR；備註不應存放密碼或秘密。

`PUT` 同一路徑接收 lifecycle 與 notes，必須提供 Origin、CSRF token 與精確 If-Match。首次建立使用 `"0"`，更新使用目前版本；缺少前置條件回 428，版本不符回 412，併發交易衝突回 409。前端保存失敗不宣告成功，提供重新載入並捨棄編輯。

讀寫均重新檢查 membership、新鮮且成功的目錄快照、當代 Computer 物件與 Computer.View scope。寫入另要求同一物件落在 Asset.Edit scope。已知受保護物件唯讀；保護未知可編輯這些純本機註記。此例外不改動通用 AuthorizationEvaluator，也不將 Asset.Edit 改為讀取權限。若未來生命週期觸發停用或其他動作，必須另行設計權限、核准及審查。

備註最多 4,000 字元，僅允許換行/Tab 等指定控制字元；生命週期為固定列舉。資產與 Device.AssetUpdated 稽核在同一交易提交，稽核只含目標、生命週期前後值及版本，不含備註正文。沒有備註歷史還原、刪除或自動清理入口。

## 部署與恢復

先備份平台 DB，套用 `20260911140730_DeviceAssets` migration，再以既有 `build/provision-runtime.sql` 更新受限 API role grants。新表啟用並強制 RLS，依目前 environment 與 membership 限制。Connector grant script 不授予資產表存取。

資產不以外鍵依賴會被同步替換的 DirectoryObjects。電腦消失、快照失效或讀取權限撤銷時，資料保留但 API 不再提供；不自動將消失解釋為已退役。回復應用版本時可保留新表，以免遺失備註；migration Down 會刪除此表，僅在備份與明確資料刪除授權後使用。

## 驗證

本機後端 build 0 警告/錯誤，104 項測試通過（Core 27、LDAP 32、FIDO2 5、PostgreSQL/API 40）。新增 8 項整合案例涵蓋版本、同時建立/更新、scope/撤權、RLS 隔離、CSRF、輸入、受保護物件、失效快照與資料保留。Daybreak 獨立審查發現的 CSRF、DTO、稽核與併發例外問題均已修正。

前端測試以合成 route fixture 驗證儲存、CSRF/版本標頭、衝突及重新載入；不代表真實 AD 或 IIS 部署驗收。

下一階段建議：建立具來源與時間的人員—電腦關聯，區分人工資產使用人和 Agent 觀測登入者，補上雙向查詢、scope 與跨環境負測試。
前端最終驗證：build/lint、13 項單元與 46 項桌面/手機瀏覽器測試全數通過。
