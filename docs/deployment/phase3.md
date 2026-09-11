# Phase 3 — Web Console

深色 React / TypeScript 殼層提供 zh-TW/en-US、hash 導覽、環境切換、唯讀 RBAC 與稽核分頁、語言設定。導覽搜尋僅搜尋頁面名稱；AD、Agent、Helper、Graph 顯示尚未配置，沒有模擬健康數字或 production demo fallback。

## 建置與同源部署

工具版本以 `src/Web/package.json`、`pnpm-lock.yaml` 與 `global.json` 為準。前端使用 Node 24.19.0 / pnpm 11.19.0。執行：

```powershell
cd src/Web
pnpm install --frozen-lockfile
pnpm lint
pnpm test
pnpm build
pnpm exec playwright install chromium
pnpm test:e2e
cd ../..
./build/publish-web.ps1
dotnet publish src/Server/Api -c Release -o .local/publish
```

`publish-web.ps1` 複製編譯後資源到 API 的 wwwroot，先執行再 publish。正式更新使用完整的新 publish 目錄部署，保留前一版本以回復；不要將 Vite development server 當成正式站台。Vite preview/dev 只供畫面開發與合成路由測試，不含認證代理。真實登入必須由已配置 TLS 的 ASP.NET 同 Origin 提供。API 的 canonical HTTPS Origin 與 WebAuthn RP ID 設定依 Phase 2 runbook。

SPA 公開資源由 ASP.NET 提供，`/api`、`/health` 不經靜態檔案 middleware。CSP 不允許 inline script/style、外部連線或 frame 嵌入。密碼、註冊 grant、session、WebAuthn challenge 不存入 localStorage/sessionStorage；只有語言偏好寫入 localStorage，阻擋儲存時仍可使用。緊急登入需要原生 WebAuthn 與 secure context，沒有 password-only fallback。

## 資料庫與 API 增量

部署者須先以離線 schema 帳號執行 migration，再重新套用 `build/provision-runtime.sql` 給受限 runtime role。新增 Preferences 以 principal 主鍵儲存 zh-TW/en-US，RLS 限制目前 principal，沒有 environment 共用語言寫入。

- `GET /api/v1/session/preferences`：`{locale}`，未設定預設 zh-TW。
- `POST /api/v1/session/preferences`：`{locale:"zh-TW"|"en-US"}`，session + Origin + CSRF，成功留 SecurityEvent。
- 認證回應 `X-Session-Remaining-Ms`：idle 與 absolute deadline 中較早者；前端到期清除畫面，不以輪詢延長 session。

環境資料以 AbortSignal、世代檢查與載入環境 ID 控制。401 清除身分與資料；403 顯示權限不足，503 顯示服務不可用。到期與從背景恢復時檢查畫面鎖定；後端仍是授權權威。

## 驗證界線

2026-09-11 本機結果：後端 49 項（Unit 24、PostgreSQL/API 20、FIDO2 5）、前端單元 13 項、Chromium 桌面/手機 16 項全部通過；TypeScript、ESLint、Vite build 與 ASP.NET publish 通過。已檢視桌面/手機實際截圖；截圖中的帳號與環境來自測試 fixture。

前端單元測試驗證 CSRF、同源傳輸、401、WebAuthn buffer 轉換、字典對等與 session 到期。Playwright Chromium 使用明確的合成 API route fixtures 驗證瀏覽器狀態；不代表通過真實 Kerberos 或硬體金鑰驗收。後端 PostgreSQL 測試包含個人語言儲存與跨 principal RLS、無 CSRF 拒絕、靜態資源不能遮蔽 API；既有 FIDO2 測試使用真實簽章與 HTTP 流程。

正式 IIS/Kerberos、企業瀏覽器政策與實體 FIDO2 authenticator 仍須隔離環境驗收。所有真實 AD/Entra 寫入均未啟用。
