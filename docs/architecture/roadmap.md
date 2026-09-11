# 開發、驗收與上線路線

每 Phase 獨立留下設計更新、可重現命令與實際測試結果；Build/Test 未執行就標未執行，不能把「可編譯的構想」寫成通過。這份文件是計畫，沒有宣稱下列測試已通過。

## Phase 1–12

目前已交付 Phase 4 的讀取/同步基礎與 typed preview 契約，以及 [Phase 5 目錄查詢與明細 UI](../deployment/phase5.md)。真實網域與受控 AD 寫入尚未驗收，因此下表 Phase 4 的完整進階條件仍未滿足；不得將 unavailable adapter 視為已完成 AD mutation。Phase 5 的完整 11 頁籤、關聯、IT notes/lifecycle 與變更預覽仍待後續實作。

| Phase | 實作交付 | 關鍵驗收 / 進下一階段條件 |
|---|---|---|
| 1 Architecture | 元件、資料流、安全、schema、API/protocol、V1 與路線 | 13 項文件一致；獨立安全架構審查；使用者確認後開始程式實作 |
| 2 Database + Authentication + RBAC | Solution、EF migrations、PostgreSQL、Windows session、emergency Owner+FIDO2、custom role/scope/group mapping、audit intent/outbox、最小 ChangePlan | 真實 PostgreSQL migration 新建/升級；SID 與角色防提權；所有 permission×scope negative tests；cross-env；CSRF；最後 Owner 併發；audit outage；隔離 Windows/IIS Kerberos integration。WebAuthn 與 Kerberos 未驗證不能聲稱 auth 完成 |
| 3 Frontend Shell | Dark-first layout、zh-TW/en-US、偏好、路由、capability gates、表格/錯誤/空狀態 | TS/lint/build；i18n key parity；keyboard/focus；登入失效；403/503/Unknown 狀態；Production 無 demo fallback |
| 4 AD Connector | Read/sync、discovery、pagination、Users/Groups/OU/Computers、Template 與受控 mutation adapter | 假 connector contract + 隔離測試網域；LDAP injection；網域斷線；OU 範圍；protected objects；dry-run drift；讀回實際變更；無 Domain Admin |
| 5 Computer / User / Group UI | 11 detail tabs、全域搜尋、双向人機關係、IT notes/lifecycle、Dashboard/Priority、AD change preview | 每個 view 都 scope-filtered；搜尋/aggregate 不洩漏；confirmation 顯示精確目標；按鈕 status/capability 分離；排程停用結果與理由可追溯 |
| 6 Inventory Agent | Windows Service、typed collectors、本機 spool、CSR/enrollment client、outbound pull、installer | 本機 Windows collector 測試；不使用 Win32_Product；無 shell/任意內容執行通道；最小權限；SSID policy；重啟序號；本地測試接收器契約測試 |
| 7 Inventory API | mTLS ingress、grant/CA signer adapter、revocation/renewal、heartbeat、快照/current/diff、request queue | 真 Agent→Server integration；clone/跨裝置/replay/亂序/重复/到期憑證；異常 payload；壓縮炸彈/配額；DB 中斷重送；DNS 換 IP；CA 操作需另行核准 |
| 8 Health Engine | rule versions、freshness、coverage、critical override、age confidence、replacement、固定 diagnostics | Ping fail + recent heartbeat 仍 Online；邊界時間；缺值不是 Healthy；過期 evidence；規則更新；同名/改名/序號碰撞；probe 不能變任意網路掃描 |
| 9 Windows Helper | signed MSI/app、工作站註冊、signed ticket、6 個 allowlist launchers、UNC copy | 受支援 Windows matrix；改參數/雙重 decode/UNC injection；假 server/wrong SID/workstation/session；replay/expired ticket；不提權；原生 launch 與 downstream 成功分開 |
| 10 Reporting | Definition/filter/column engine、durable report jobs、7-sheet Excel、單機 Excel | 真 PostgreSQL scoped data；建立/執行/下載時撤權；超大資料；formula injection；Excel 可開啟且工作表/型別正確；無 key/secret；過期清理 |
| 11 Audit | 完整事件涵蓋、受控查詢/匯出、immutable archive、retention、reconciliation | 秘密 canary 不出現在任何儲存/trace/error；external timeout Unknown；故障 audit fail-closed；anti-tamper receipt；備份還原；登入/變更/Key reveal 皆涵蓋 |
| 12 Security Review | 獨立 code/architecture review、攻防負測試、部署/回復 runbook、pilot release | 實際權限委派、無憑證洩漏、跨 env/scope、TOCTOU、Agent/Helper supply chain、效能、還原與故障演練；所有阻擋項關閉後才標 V1 production-ready |

Phase 6 在 Phase 7 前，以已固定 protocol contract 及本機測試接收器驗證 Agent；Phase 7 才完成真實相互操作。Phase 11 是 audit 完整化，核心稽核與高風險核准從 Phase 2 起就是所有寫入的前置條件。

AD/Entra/GPO/憑證等高敏感真實變更，開發授權不等於環境操作授權。每次須 current-state discovery、精確預覽、impact、rollback、獨立安全審查與人類核准，僅在核准範圍執行並讀回驗證。純本機程式碼與測試 fixture 不需要因此停工。

## V1 / V2 / V3 追蹤

| 需求群 | V1 | 後續 |
|---|---|---|
| Server / DNS / Environment / i18n | 完整基礎、Settings 顯示實際網路與宣告端點 | HA/更多 auth issuer 按需求擴充 |
| Auth / RBAC / Protected / Dry Run | 全部必要控制；最小兩人高風險核准 | V3 完整多階段 workflow/approvals |
| AD Users / Groups / OU / Templates | 受控 CRUD/批次/排程、basic health | V3 跨系統 onboarding/offboarding |
| Computer / Inventory / Health / Age | V1 核心；所有欄位有品質/來源，權限不足標 unavailable | V2 高級 compliance/local admin baseline |
| Tags / Favorites / Saved Filters | 最小 tags（Scope 需要）、favorites | V2 完整 tags UX、saved/shared filters |
| BitLocker / Security | Agent status、AD escrow metadata/JIT single key；TPM/Defender/Firewall 等 observations | V2 Entra key source；不得保存 key |
| Agent | Read-only signed service 與正式憑證生命週期 | collector 能力擴充仍禁止任意命令 |
| Helper | RDP、Explorer、C$、Computer Management、Event Viewer、Services | 無 general shell 或 endpoint 管理 agent 化 |
| Reporting | 定義式 inventory/software/health/AD 基礎報表、7-sheet Excel、單機 Excel | V2 其餘報表/單機 PDF；V3 scheduled reports |
| GPO / DC Health | 頁面與 connector capability 標 unavailable | V2 固定 GPO operations、DC probes、GPUpdate |
| Graph / Entra / MFA / Intune | 介面與未配置狀態，無假成功 | V2 Graph/Entra/MFA；V3 Intune |
| Exchange / Offboarding | 不接外部 Exchange，不自動離職執行 | V3 Exchange adapter 與 checklist，先 check 後受核准動作 |
| Audit / Session / Secret handling | V1 上線必需完整化 | 後續新增功能一律帶 audit |

原需求 #75 的單機 PDF 明確排到 V2，#67 Saved Filters 和完整 #42 Local Admin Compliance 依 V2 範圍安排；V1 仍保留基本 Local Administrators 盤點。此為待確認的範圍取捨，不能在完成報告中宣稱全部 100 項已實作。

## 生產上線條件

1. 有效 TLS/DNS、真正 Kerberos 的 IIS 部署、SPN/NTLM 策略、受控 emergency Owner 演練。
2. 所有敏感端點都有 environment/resource/action authorization、anti-forgery、step-up、audit；跨 Environment / Scope 負測試通過。
3. AD/Graph/Exchange 實際 delegated privileges 與原始需求相符；Connector compromised blast radius 已記錄；無 Domain Admin 或無限制 delegation。
4. Agent grant、CA、renewal/revocation、replay/clone 防護驗證，Agent/Helper 安裝包簽章與更新通道驗證。
5. Protected Objects、精確核准、執行前授權/版本重查、部分結果與外部 timeout reconciliation 通過。
6. Recovery Key 不出現在 DB、cache、queue、snapshot、報表、log、trace、dump pipeline；僅單機即時揭露，scope 收斂。
7. PostgreSQL migration/備份/PITR 還原、CA/key backup 及 rollback 演練成功；API/Worker/Connector outage 可恢復。
8. 先對隔離測試網域與少量授權 pilot endpoint 執行真實測試，再擴大；沒有實際環境證據則標「待環境驗收」。

初始容量測試目標：5,000 台/60 秒 heartbeat、50 concurrent console users，scoped list p95 <2 秒，健康 agent 的 inventory request 在正常網路 90 秒內開始（不含蒐集時間）。這些是待測目標，規模、硬體與網路會影響結果。

Server 指標：API latency/error、job lag、connector freshness、inventory ingestion lag、audit backlog、DB/storage、certificate expiry；logging 不含 request/response body 預設擷取。告警不含秘密。背景工作使用 DB lease、retry/backoff、poison job/dead-letter、cancellation 與 per-environment concurrency，避免某環境拖垮其他環境。

## Phase 1 驗證紀錄

- 工作目錄原為空資料夾，未找到現有程式或 Git repository。
- 已檢查需求中的 13 項架構輸出與本輪文件对应。
- 已由 Security Expert（Daybreak Blue）完成獨立安全架構建議，修正結果見 security/design-review.md。
- 已查核 Microsoft Windows Authentication、Win32_BIOS、Graph/Exchange 與 PostgreSQL RLS 的官方資料；引用置於對應文件。
- `dotnet --list-sdks` 本機未列出 SDK；存在 dotnet executable 不代表已具備 .NET 10 開發 SDK。進入 Phase 2 前要重新確認/安裝相容 runtime 工具鏈。
- 本輪未產生應用程式，因此未執行應用 build/unit/integration test；沒有 real AD、Agent 或 Helper 環境驗收。

## 開始 Phase 2 的假設

除非需求方修正，採 Windows/IIS 生產宿主、單一組織部署且支援多 Environment、React 同 Origin、Agent 獨立 DNS/mTLS listener、V1 AD DS 為主、雲端整合按 V2/V3 分期。尚無企業資料時，以完全隔離的合成 fixture 與測試 adapters 開發，不需要提供任何真實 credentials。
