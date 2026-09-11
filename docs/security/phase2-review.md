# Phase 2 程式審查與修正

以獨立 Security Expert（Daybreak Blue）session 檢查登入、Session、Passkey、RBAC、ChangePlan 及 Persistence。這是 bounded implementation review，並非完整企業上線安全掃描。

## 已修正

1. Protected Object 狀態原只有 true/false，缺資料可能被當作未保護。新增 `ProtectionKnown`，預設 false；未知狀態拒絕非唯讀 permission。
2. OU exact scope 原誤用 resourceId。改用明確 OrganizationalUnitId，另以 ancestry 判 descendant；新增單元測試。
3. 不同帳號仍可能屬同一人。新增 immutable、不可為空的 OperatorId，approval/execution 同時檢查不同操作人，runtime 不可修改 Principals。
4. 重新發出 Passkey enrollment grant 原未撤銷先前 grant。現在同一交易使旧 grant 與 register ceremonies 失效後才產生新 token。
5. Group→Owner 限制不只在 API，新增 DB trigger；BuiltInKind 修改亦被 trigger 拒絕。
6. RLS 原只比對 caller 選擇的 environment GUC，不足以擋住未來漏寫應用授權的路徑。新增窄權限 SECURITY DEFINER membership boolean function，所有 tenant policy 同時檢查 active principal membership；function 固定 search_path、全限定 table 名稱、PUBLIC execute revoked。runtime 帳號不可有 BYPASSRLS，function owner 是離線受控身分。
7. PostgreSQL timestamp 只有微秒，原 .NET hash 含更細 ticks，造成持久化後核准 hash 不一致。經獨立 Tester 發現，改為 UTC 微秒正規化，加入實際 DB roundtrip 測試。

## 實際驗證

- 真 PostgreSQL + runtime role 的直接 RLS 查詢：本 Environment 可讀、其他 Environment 或缺 principal context 無資料。
- HTTP Origin/CSRF、未登入、過期/撤銷 session、跨 Environment、同人雙帳號核准、撤權、版本 drift、單次 DB-local execution。
- 真 ECDSA P-256 / COSE / CBOR 的註冊與 assertion，使用正式 Fido2 verifier：合法成功，wrong-origin、wrong-challenge、missing-UV、invalid-signature、replay 拒絕。
- 所有管理變更只在本機資料庫交易內，無 AD/Entra/Exchange side effects；不能將此交易保證套用到未來外部 Connector。

## 保留的上線條件

真實 IIS/Kerberos、來源 IP、硬體 authenticator、故障/併發、production credential ACL、CA/secret/Data Protection 備援、audit 外部投遞、負載與 retention 尚需驗證。OperatorId 的身分對應必須經受控 provisioning 核實，不能靠系統猜 email 來保證不同人。

「目前未證實有直接繞過」不等於沒有漏洞。持有 runtime 任意 SQL 能力者仍可改 app GUC；平台 compromise 的上游 blast radius 仍需靠最小 Connector 權限與程序/網路隔離控制。正式 Phase 12 需新的獨立安全驗收。
