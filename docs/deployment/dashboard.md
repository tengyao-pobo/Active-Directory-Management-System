# Phase 5 — 目錄與資產 Dashboard

總覽新增可見 User、Group、Computer、OU 數量、人工電腦生命週期分布與 Repair 清單。每一項數量只代表目前操作者的可見範圍；沒有權限時的零不等於全組織沒有物件。Agent 與健康狀態固定 Unknown，不能從人工生命週期推論設備健康。

`GET /api/v1/environments/{environmentId}/dashboard?cursor=...` 在同一 serializable 交易驗證 membership 與新鮮 Ready 目錄 generation，再各自套用 permission + scope 後 Count。Computer 以 environment + GUID 左連接平台資產；沒有資產列歸 Unknown，孤立資產與隱藏電腦不計入。Response 不含備註或使用人。

Repair 清單和分布使用同一 scoped join，每頁 50 筆。cursor 經 Data Protection 並綁定 actor、environment、generation、after GUID；篡改回 400、目錄換代回 409。每次請求重新讀取資產，跨頁期間的人工修改或撤權可能改變結果；沒有宣稱跨頁是一份不可變快照。

asOf 是目錄來源時間，queriedAt 是本次查詢時間，不是 Agent 心跳或健康觀測時間。未配置、失敗或過期目錄回 503，不傳回舊數量。UI 顯示未知／不可確認，提供重新整理回第一頁。環境切換或新請求會取消舊請求，避免延遲回應覆蓋目前內容。

本次無 schema、grant 或外部設定變更，可回復應用版本。需先部署既有 DeviceAssets migration 才能使用資產分布。

本機 backend build 0 警告/錯誤，共 117 項通過（Core 27、LDAP 32、FIDO2 5、PostgreSQL/API 53）；新增 6 項 Dashboard 案例覆蓋 scoped counts、缺值、孤立資產、跨環境同 GUID、撤權、過期／失敗、分頁與 cursor。前端 build/lint、13 項單元及 52 項桌面／手機測試通過，已檢視 Dashboard 畫面。Daybreak 獨立安全審查沒有剩餘阻擋項。

這是目錄／人工資產 Dashboard，不是完整 Health Engine 或自動診斷 Priority Inbox。下一步建議設備明細分頁與來源狀態，整合 AD、資產、人工關聯與稽核；硬體、軟體與健康資料仍須等待 Agent/API 階段。
