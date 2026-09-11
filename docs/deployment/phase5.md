# Phase 5 — 目錄查詢與明細介面

本次接通 Users、Groups、Computers、OU 四種唯讀目錄頁，使用 Phase 4 的真實 API 契約。支援名稱/帳號搜尋、游標前後分頁、重新授權的明細查詢、來源時間與保護狀態。繁體中文與英文、桌面與手機均提供對應介面。

API 決定每個物件的授權；前端不以全域 All scope 權限阻擋合法的 OU scoped reader。切換環境或類型會卸載頁面並取消請求；搜尋與換頁清空舊明細，較晚回應不能覆蓋新選擇。游標遇到 409 只自動重試第一頁一次；401 會清除登入後介面。

未設定、同步失敗、過期/不可用、拒絕存取與物件不存在分別顯示，不使用示範資料補值。保護判定未知仍顯示 Unknown。總覽 Connector readiness 也改讀 status API。狀態目前在進入頁面時讀取，沒有背景輪詢；同步狀態改變後可重新進入頁面取得最新狀態。

## 驗證

2026-09-11 本機執行 `pnpm build`、`pnpm lint`、`pnpm test` 全部通過，單元測試 13 項。`pnpm test:e2e` 桌面 Chromium 與 Pixel 5 共 34 項通過，包含四種物件、字面搜尋、分頁、409 換代、未配置/失敗、404 清除、401 登出及切換環境時的延遲回應。已檢視桌面與手機明細截圖。

瀏覽器測試使用合成 route fixtures；這是前端契約驗證，不是已連接真實 AD 的證據。後端此次未修改，既有 PostgreSQL/API、LDAP 與 FIDO2 測試由 CI 再驗證。

Daybreak Security Expert 完成此目錄介面的獨立靜態安全審查，未發現阻擋項。既有 status API 允許環境成員查看同步狀態/錯誤碼的政策未變更。

## 後續範圍

這是 Phase 5 的查詢/明細部分。完整 11 頁籤、人機關聯、IT notes/lifecycle、Dashboard/Priority 與變更預覽尚未全部實作。沒有啟用 AD 寫入、Agent、Helper 或雲端整合；真實網域驗收仍依 Phase 4 runbook 另行執行。
