# Phase 4 — Directory Connector read/sync foundation

本次交付實際 LDAP 讀取 adapter、獨立 Connector Host、PostgreSQL 原子快照、具 scope 的查詢 API，以及變更範本/預覽的初始契約。**Phase 4 的真實網域驗收與 live mutation adapter 尚未完成，不代表整個 Phase 4 或正式 AD 管理功能已驗收。**

## 執行界線

Web API 不參考 DirectoryConnector，也不接收 DC、DN、LDAP filter 或 AD credentials。ConnectorHost 是獨立程序，由服務設定指定單一 DC、domain naming context 與 domain objectGUID；以目前 Windows 服務身分透過 Negotiate/LDAPS 636 讀取。正式部署使用可讀取所需目錄屬性的獨立服務身分，不需要 Domain Admin，不與未來寫入身分共用。

每次固定讀取 Users、Groups、Computers、OU，僅回傳 objectGUID、objectClass、DN、name、sAMAccountName、department、objectSid、uSNChanged。沒有 LDAP write、密碼重設、LAPS、BitLocker key、shell 或任意屬性查詢。這是全量快照，尚未實作 DirSync 增量與群組成員 range retrieval。

RootDSE 必須宣告設定的完整 naming context，該 base objectGUID 必須等於 ExpectedDomainId。此版本不接受 OU 當成 BaseDn；OU 是平台查詢授權範圍。讀取身分的 AD 可見性必須在隔離網域確認，LDAP 成功不代表能看見受 ACL 隱藏的全部物件。

AD 分頁搜尋不是跨物件的一致性交易；同步途中新增/移動可能到下一輪才完整反映。`asOf` 是讀取完成時間，不是 AD 全網域同一瞬間的快照證明；GUID 重複或不完整父鏈會拒絕本輪。

所有頁面、cookie 與必要欄位成功才發布；頁數、結果數、cookie、每次請求與總時間都有上限。DN 以結構化長度編碼處理 escaped comma/plus/UTF-8，OU scope 儲存 GUID 父鏈，禁止以字串後綴判斷物件身分。過期或失敗快照不供查詢；舊資料保留供下一次成功同步替换，沒有推論 tombstone 或執行 AD 刪除。

## 離線部署步驟

1. 備份資料庫；用既有 schema 帳號套用 migrations，再執行 `build/provision-runtime.sql` 更新 API role。API 對目錄投影只有 SELECT。
2. 用 Provisioning 的 `provision-connector-principal <environment-guid> <operator-guid> <name>` 建立無互動角色、無登入憑證的 Connector principal。此命令只操作平台 DB，不建立 AD 帳號。
3. DBA 建立**新的獨立** restricted LOGIN role，密碼透過外部秘密管理設定。以 `psql -v connector_role=ROLE -v environment_id=UUID -v principal_id=UUID -f build/provision-connector.sql` 給最小權限。不要把 API role、既有高權限 role 或同一 role 用於多環境。
4. 在 Connector 服務的保護設定中提供下列值；不提交實際設定：

```text
CONSOLE_CONNECTOR_ALLOWED=true
CONSOLE_CONNECTOR_ENVIRONMENT_ID=<platform environment GUID>
CONSOLE_CONNECTOR_PRINCIPAL_ID=<connector principal GUID>
CONSOLE_CONNECTOR_HOST=<approved DC FQDN>
CONSOLE_CONNECTOR_BASE_DN=<domain naming context>
CONSOLE_CONNECTOR_DOMAIN_ID=<verified domain objectGUID>
ConnectionStrings__Console=<connector database role connection string>
```

5. `dotnet publish src/Server/ConnectorHost -c Release`，以專用服務身分執行發佈的 ConnectorHost；每次一輪全量讀取。外部排程設定間隔低於 API 的 15 分鐘 freshness 上限，避免重疊。Host 在五分鐘取消本輪，進行中的 LDAP 呼叫可能需等每請求 timeout 結束；取消後不發布結果。Ctrl+C/取消使用短暫 cleanup token 記錄 Failed。不要以開發者的高權限帳號執行正式 Connector。
6. 驗證 `/api/v1/environments/{id}/directory/status` 為 Ready，並用不同 scope 帳號核對讀取結果。完整 API 路徑見下節。

Connector DB 身分由私有 `DirectoryDatabaseBindings` 綁定 login role、environment 與 principal。RLS 使用 PostgreSQL `session_user`，即使篡改 GUC 也無法改寫另一環境的投影或稽核。讀取前及發布前都重新驗證；LDAP I/O 不持有 DB transaction，發布使用短交易、advisory lock 與 run 時間序避免舊結果覆蓋較新結果。移除 membership/停用 principal 可阻止後續發布。

## API

- `GET /api/v1/environments/{id}/directory/status`：成員可見配置/完成時間/失效狀態；不回傳 DC 或 credentials。
- `GET .../directory/objects?kind=User|Group|Computer|OrganizationalUnit&search=...&limit=50&cursor=...`：最大 200，search 最大 128 字元，回傳 items/nextCursor/asOf/generation，不回傳未授權 total。
- `GET .../directory/objects/{objectGUID}`：無權限與不存在均回傳 404。

User/Group/Computer 對應既有 *.View，OU 使用 Environment.View。permission 與 scope 必須来自同一 assignment；支援 All、Department 與 GUID OU exact/subtree。Department 目前使用 AD department 原值精確比對；Group/DeviceTag scope 尚無來源投影，保守不授權。OU ancestry 是父 OU 集合，exact 指直接父 OU，subtree 指任一父 OU；範圍根 OU 自身仍須其父範圍權限，不自動包含自身。

cursor 經 Data Protection 驗證並绑定 actor/environment/kind/search/generation；篡改回 400，同步換代回 409，客戶端須重新開始分頁。Unconfigured、Failed 或完成時間超過 15 分鐘回 503 DirectoryUnavailable，不把缺值顯示為健康。

## 變更與下一步

Core 提供 DisableUser/SetUserDepartment 的 typed template、包含 before 值與到期/hash 的 preview，以及 GUID、DN、USN、domain/config/policy/protection/scope drift 檢查。hash 僅檢查內容一致，**不是授權**。目前唯一 adapter 回傳 Unavailable，沒有網頁執行端點；真實 LDAP protection 判定保守為 unknown，因此不能以此讀模型核准寫入。

接通寫入前仍需完整 Tier-0/保護分類、持久化雙人核准與稽核意圖、簽署 dispatch、執行前授權與遠端讀回、Timeout Unknown reconciliation、權限委派與隔離網域測試。此輪不會用 fake writer 宣稱已驗證真正 AD 變更。

## 測試

本機後端各套件共 96 項通過（Core 27、LDAP contract 32、PostgreSQL/API 32、FIDO2 5），locked restore/build 0 警告/錯誤。新增測試包含 DN collision、filter escaping、paging bounds、完整/失敗/取消同步、發布前撤權、scope/cursor/cross-environment 及 connector login 偽造 GUC。DB 測試使用臨時 restricted login role 並套用真實 grant script，測試後只撤销該測試角色的 grants 並移除該角色。

尚未連接真實 AD；TLS/Kerberos/gMSA、ACL 可見性、不同 DC 行為及實際設備規模必須在隔離網域驗收。前端目錄清單與明細屬下一階段 UI，不在此輪擴充。

## 實作依據

DN 字串解析與 LDAP filter escaping 採不同規則，分別參考 [RFC 4514](https://www.rfc-editor.org/info/rfc4514/) 與 [RFC 4515](https://www.rfc-editor.org/info/rfc4515/)。連線的 SSL/referral 選項參考 [Microsoft LdapSessionOptions](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapsessionoptions)；此專案鎖定的套件版本以 packages.lock.json 為準。
