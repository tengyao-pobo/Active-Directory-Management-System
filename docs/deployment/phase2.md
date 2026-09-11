# Phase 2 開發與操作說明

此版本是可建置、可測試的後端基礎，**不是 production-ready release，也不宣稱完整 Phase 2 驗收已完成**。架構已核准；本機只建立合成測試環境，沒有修改真實網域/雲端/防火牆/DNS。

## 已實作與測試

- .NET 10.0.401 Solution；Core / Persistence / API / Provisioning 四個產品專案及 Unit / Integration / Security 測試。
- EF Core 10.0.12 / Npgsql EF provider 10.0.3；三個 migrations、複合 Environment 外鍵、RLS 與 append-only audit triggers。
- Opaque server-side sessions、閒置/絕對期限、revocation、principal 狀態、cookie/CSRF/Origin/HTTPS enforcement、登入 IP 節流與 password lockout。
- Emergency 密碼+Passkey，Fido2 4.0.1 真實驗證、UV-required、一次性 challenge/grant、counter 鎖定；Windows SSO adapter 不自動 provision 使用者。
- Role/Permission/Scope、Owner-only protection、未知保護狀態拒絕寫入、同一 assignment scope、OperatorId 雙人核准。
- DB-local Environment/RBAC 變更有 immutable plan、15 分鐘 expiry、時間精度穩定 hash、交易式單次執行、Audit 與 Outbox。

驗證證據：24 個 Unit、15 個 PostgreSQL/HTTP Integration、5 個真實簽章的 WebAuthn HTTP tests，合計 44 個。後續測試增加時以 CI 與最終結果為準。Integration 由獨立 Tester 撰寫，找到 PostgreSQL 微秒精度造成 persisted plan hash 改變的 bug，已修正並新增 regression；Root 另補 null-input regression。

Security tests 使用臨時 P-256 私鑰與 CBOR/COSE 產生軟體 authenticator 的真實簽章，驗證 API 註冊→密碼→assertion→session；也拒絕錯誤 origin/challenge、缺 UV、錯誤簽章及重播。**這不等於已驗證實體 FIDO2 金鑰、瀏覽器 UI 或 Windows Kerberos。**

## 開發工具

本次 Windows 開發工具放在 `.tools/dotnet` 與 `.tools/postgresql`，不更改 PATH 或全域 SDK。SDK ZIP 使用 Microsoft release metadata 提供的 SHA512 核對；PostgreSQL ZIP 來自 PostgreSQL 官方 Windows 頁面指向的 EDB 下載。下載與資料目錄不提交 Git。

標準環境自行安裝 .NET SDK 10.0.401 與 PostgreSQL 18。參考 [Microsoft Windows .NET 安裝](https://learn.microsoft.com/en-us/dotnet/core/install/windows) 與 [PostgreSQL Windows 下載](https://www.postgresql.org/download/windows/)。建置工具依 lockfile 還原，勿用不相容的新 major 版隨意更新。

`dotnet-tools.json` 保存 dotnet-ef 10.0.12。使用本機 SDK 時，將該 SDK 路徑放在目前終端機的 PATH / DOTNET_ROOT，讓 local tool runner 找到正確 runtime。

## 資料庫與 runtime 權限

1. 在獨立測試資料庫建立 migration/provisioning 身分與 runtime 身分。測試可用本機 superuser migration；正式環境採受控 offline migration/definer owner，具備必需的 schema 建立與 BYPASSRLS 能力，credential 不可被 Web/Worker 讀取。
2. 以 offline 身分設定 `ConnectionStrings__Console`，執行 migration：

```powershell
dotnet tool restore
dotnet ef database update --project src/Infrastructure/Persistence/Persistence.csproj
```

3. 透過企業 Secret Store 建立 runtime LOGIN。必須 NOSUPERUSER、NOBYPASSRLS、NOCREATEDB、NOCREATEROLE、非 table owner，且不是 offline/definer role 的成員。
4. 目前版本另需獨立 NOLOGIN lock owner；依[平台註冊計畫部署](platform-enrollment-plans.md)建立並驗證角色後，DBA 執行 `psql ... -v runtime_role=<runtime-role> -v enrollment_plan_lock_owner_role=<lock-owner-role> -f build/provision-runtime.sql`。此檔無密碼；僅套用已核准的資料庫權限，勿對不明資料庫直接執行。
5. API 只使用 runtime connection；啟動會檢查角色不得擁有 schema tables 或繞過 RLS。對 DB 連線強制 TLS VerifyFull 的正式 connection 範例在 `.env.example`。

RLS 同時核對 selected Environment 與 active principal membership。為避免 Memberships policy 遞迴，使用只回 boolean 的 `public.has_environment_membership(uuid,uuid)`，fixed search_path、schema-qualified tables、row_security=off、PUBLIC execute revoked。function owner 必須為受控 offline BYPASSRLS owner，runtime 只有 EXECUTE；runtime 不得 CREATE public schema 物件或改 function。若 owner 設錯則 fail closed。

RLS 防止應用查詢漏套環境/member條件，不抵抗能執行任意 SQL 的 runtime compromise，因 app GUC 可由 DB caller 改寫；不宣稱是多公司不互信 SaaS 隔離。

## API 與離線 bootstrap

預設所有登入方法關閉；API 開啟不會自動登入 demo owner。設定 `Console__Origin`、`Console__RelyingPartyId`、`AllowedHosts` 與 runtime DB connection。正式生產優先 IIS + HTTPS，Web 與 API 同 Origin；不支援把任意 proxy identity headers 視為可信。

Windows login 開 `Console__WindowsAuthentication=true` 且預設 RequireKerberos。需手動完成 canonical DNS、HTTP SPN、IIS Windows auth path 與匿名 emergency path 的核准設定，確認實際 authentication package。未取得環境資訊時不自行改 SPN/gMSA、憑證或網域設定。

Emergency login 開啟前列明 `Console__EmergencyAllowedAddresses__0` 等可信管理端來源。確認 IIS 傳遞實際 RemoteIpAddress，不能把所有 proxy-forwarded 請求都誤判成本機。API 不接受未設定 trusted proxy 的 X-Forwarded-For。

Provisioning 是單獨 executable，不經 HTTP。`CONSOLE_PROVISIONING_ALLOWED=true` 只是操作防呆開關，真正安全界線是其 DB credential/檔案/執行身分的 OS ACL 與人類核准。

```text
dotnet run --project src/Server/Provisioning -- create-environment <name> <dns>
dotnet run --project src/Server/Provisioning -- bootstrap-owner <environment-guid> <operator-guid> <local-name>
dotnet run --project src/Server/Provisioning -- provision-windows <operator-guid> <SID> <display-name>
dotnet run --project src/Server/Provisioning -- enrollment-grant <principal-guid>
```

bootstrap-owner 以隱藏 console input（或 stdin）取得密碼，不經 command-line argument。一次性 enrollment token 會有意只輸出到操作者的 console，必須視為機密，禁止將 console output 送 CI log。登入仍須完成 Passkey；不會以 bootstrap token 直接取得 session。為兩人核准規劃不同 OperatorId 的操作人；同一人的 Windows/local 身分沿用同一 OperatorId。

目前沒有 React UI，可依 docs/api/phase2.md 的 API 契約由客戶端完成 WebAuthn ceremony。正式導入前須完成 Phase 3 登入體驗與真實 authenticator 驗證。

## 重現測試

設定只供測試的 `CONSOLE_TEST_DB`（migration/seed owner connection）與 `CONSOLE_TEST_RUNTIME_DB`（restricted connection）。這兩個值不可 commit 或列印。執行：

```powershell
./build/verify.ps1
```

也可依序 `dotnet restore --locked-mode`、`dotnet build -c Release --no-restore`、`dotnet test -m:1 -c Release --no-build`。資料庫測試專案會修改共用角色／schema catalog，因此依專案循序執行；單一案例內的並行請求與交易競爭測試仍保留。整合測試若缺 DB connection 會失敗，不能靜默 skip 冒充驗證完成。tests 用真 PostgreSQL，不用 EF InMemory 替代交易/RLS。

測試資料都是新 UUID 與合成帳號。因 Audit/SecurityEvents append-only，測試故意保留這些記錄；只有重建整個明確隔離的 test DB 才清除，禁止對正式資料庫執行測試或 cleanup。

本機 PostgreSQL 只聽 `127.0.0.1:55432`；資料位於 `.local/pgdata`。停止開發資料庫可執行 `.tools/postgresql/pgsql/bin/pg_ctl -D .local/pgdata stop`；此操作限本專案建立的 instance。API 此輪未安裝為持續運行服務。

## 本階段未完成與上線阻擋

- 真實 IIS/Kerberos、SPN 唯一性/NTLM policy、來源 IP 與實體 Passkey 驗證；未提供真實環境，所以不作完成宣告。
- Owner transfer/removal/最後 Owner 併發的專用接受流程，recovery codes、登入告警投遞與 identity retention jobs 尚未完成；現有通用 RBAC API 禁止 Owner 變更。
- AD Group Mapping 可保存，但未以真實 AD group SID 解析 session 權限；待 Phase 4 Connector 實作。Scopes 本階段有核心與 fixture 驗證，OU/group資料來源尚未接入。
- Outbox 目前是 durable records，沒有假裝已投遞到 SIEM/外部 immutable archive；在 Phase 11 完整化之前須維運監控與處理 backlog。
- 部署檔案/資料庫/秘密與 Data Protection key store 的 ACL、備份還原、負載與保留政策尚需環境演練。

因此這次可提交並在 GitHub 持續開發，但不能直接部署給企業全員使用，也不能宣稱原始 100 項需求已完成。
