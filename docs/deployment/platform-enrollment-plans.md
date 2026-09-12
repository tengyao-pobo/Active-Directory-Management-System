# 平台 Agent 註冊申請與核准

設備的 Inventory 頁籤提供註冊申請及申請 ID 查詢。另一位管理者在同一設備頁開啟申請、檢查設備、原因、公鑰指紋及核准雜湊後核准。計畫、永久公鑰保留紀錄與稽核均在平台內保存。後續已加入[專用排隊交易與歷史查詢](../architecture/platform-grant-execution.md)，目前 processor 預設不可用，尚未開啟執行按鈕，不發行 token，也不呼叫私有 grant store、CA 或 listener。

## 操作流程

1. 註冊準備狀態為 Eligible 時，輸入原因並驗證身分。瀏覽器產生 RSA 接收公鑰及不可匯出的私鑰，提出固定設備的申請。
2. 平台重新檢查目前會員、Owner 角色、設備範圍、目錄快照及設備對應。通過後保存不可變計畫、公鑰指紋保留紀錄與稽核；三者在同一交易提交。
3. 另一位有該設備 `Computer.View` 與 `Change.Approve` 權限的管理者，以申請 ID 開啟同一設備的計畫。核准需要 fresh step-up，且兩個帳號的 OperatorId 必須不同，不能只以帳號 ID 不同視為獨立操作人員。
4. 核准前再次核對提案人仍有 Owner 及同一設備的 `Computer.View`／`AgentEnrollmentGrant.Manage`、目前目錄 generation、環境版本、公鑰、計畫雜湊與精確 mapping tuple。任何不符都不能新增核准。

計畫與核准效期均為 10 分鐘。準備狀態及已核准計畫都不是可直接發行 grant 的證明；後續執行功能仍須重新驗證並建立可恢復的操作紀錄。

## 金鑰與不確定結果

瀏覽器不持久保存私鑰。它只存在目前設備頁面，從產生起最多保留 10 分鐘；收到伺服器計畫後採本機期限與伺服器剩餘期限中較早者。離開設備、切換登入身分、清除畫面或開啟另一份申請會捨棄金鑰，但不會取消已提交的計畫。

回應遺失時，可重試同一份申請。用戶端保留相同 requestId、公鑰、預期版本與原因；伺服器以 requestDigest 比較完整請求，只能恢復相同計畫，不新增稽核或保留紀錄。若相同 requestId 帶不同內容，或另一份申請重用公鑰，回泛化衝突結果。

公鑰指紋在整個資料庫中永久唯一，跨環境也不可重用；計畫過期、拒絕或核准後不釋放。金鑰遺失需要新公鑰、新申請與核准。未來若 grant 已發行，必須先完成舊 grant 的撤銷與讀回，不能直接重新包裝或換公鑰。此增量尚不會發行 grant。

## API 契約

| 方法及路徑（共同前綴 `/api/v1/environments/{env}`） | 輸入 |
|---|---|
| POST `/devices/{directoryObjectId}/enrollment-grant-plans` | requestId、expectedEnvironmentVersion、expectedDirectoryGeneration、recipientSpki、reason |
| GET `/enrollment-grant-plans/{planId}` | 無 |
| POST `/enrollment-grant-plans/{planId}/approval` | planHash |

請求拒絕額外欄位；不能提交 server Device ID、mapping 時間、actor、指紋、效期或任意 action。公鑰使用 canonical base64url SPKI，經 `EnrollmentGrantRecipientKey.Validate` 重新驗證。

回應只包含計畫／環境／目錄設備／提案人／請求 ID、公鑰指紋、hash、版本、generation、效期、查詢時間、狀態、原因及可操作旗標。不得回傳 server Device ID、mapping 建立時間、原始 SPKI、requestDigest、token 或密文。回應禁止快取；瀏覽器也拒絕多餘欄位、其他設備的計畫及核准後被替換的不可變內容。

既有一般 change-plan 的 GET、approval、execution 不接受此 action，資料庫亦禁止此 action 進入 Executed。後續正式啟用必須有獨立覆核與相應 migration，不能只增加一個前端執行按鈕。

## 一致性與部署界線

初次 public transaction 驗證授權後結束，再呼叫私有 EnrollmentTargetRead；隨後以新的 public transaction 重新驗證目前狀態並提交。不可在同一 SERIALIZABLE snapshot 中重讀後宣稱已看見 resolver 期間的更新。

最終交易依固定順序鎖定環境、目錄同步狀態、設備、涉及的 principal、membership，再於核准時鎖 plan。權限及 OperatorId 在取得鎖後重讀。私有 mapping 與 public plan 沒有共同交易，因此後續 execution 仍須重新解析並精確比對 mapping；本階段只核准被綁定的快照。

公鑰保留表啟用 FORCE RLS，限制目前環境及有效會員；runtime 僅可 SELECT／INSERT，禁止 UPDATE／DELETE／TRUNCATE，並保留不允許修改或刪除的資料庫保護。新權限不得因重新套用廣泛 table grants 而放寬。

部署需要既有 [EnrollmentTargetRead](enrollment-target-read.md)、public schema migration 及相應 runtime 權限配置。真實資料庫部署須先預覽及驗證備份／回復；不能刪除指紋紀錄來解除衝突。所有開發證據均使用合成環境，未操作企業 AD、CA 或設備註冊。

### Public database 升級

以離線 migration 身分套用 `20260911214940_EnrollmentGrantPlans`，再由 DBA 建立獨立的 lock owner。以下名稱只是範例，需替換為該部署的專用角色；它不使用密碼、不登入，也不加入其他角色。

```sql
CREATE ROLE console_enrollment_plan_locker NOLOGIN NOSUPERUSER NOBYPASSRLS
    NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
```

既有 API runtime 也須為 NOINHERIT、NOREPLICATION，且沒有角色成員關係、資料庫／schema／table／function 所有權或繞過 RLS 的能力。兩個角色都不得在目前資料庫取得 CREATE；API runtime 不得在 public schema 建立物件、取得其他 schema 的直接物件權限，或透過 table／column 權限寫入 DirectorySync／DirectoryObjects。現有 runtime binding 只能是 Api，lock owner 不得另有 binding。Preflight 會拒絕角色用途或權限漂移，不會將其他用途的登入重新配置成 API。完成角色檢查後，使用既有受控 DBA 連線執行：

```text
psql <approved-database-connection> -v runtime_role=<api-runtime-role> -v enrollment_plan_lock_owner_role=<lock-owner-role> -f build/provision-runtime.sql
```

此腳本以同一交易配置 runtime 與 lock helper 權限，最後驗證所需的資料庫設定。API 啟動另會驗證函式本文、owner、ACL 及公鑰保留表的保護設定。檢查不符時應修正部署差異，不能跳過啟動檢查。新 NOLOGIN 角色只供固定函式取得資料列鎖，不應放入任何服務連線字串。

一旦存在公鑰保留紀錄，migration Down 會拒絕刪除資料表；回退應用程式時保留 schema 與永久指紋紀錄。不能藉由回復舊備份後重新開放發行，讓已使用的公鑰重新取得資格；正式災難復原須保留這些紀錄並核對已發行操作。

## 驗證

後端完成 locked restore、零警告／錯誤的 Release build 及 777 項完整方案回歸。當中包括 59 項註冊計畫 PostgreSQL／HTTP 測試與 5 項登入安全測試：涵蓋兩份實際等待同一資料庫鎖的相同申請、單次恢復、跨環境衝突交易回復、損壞計畫拒絕、resolver 期間權限漂移、取得最後一把鎖後的期限／step-up 重查、非空 rollback 拒絕，以及角色、函式、RLS、索引、trigger 與 table／column 權限漂移。修改共用 PostgreSQL catalog 的測試專案循序執行，案例內的並行競爭仍照常驗證。最終 API、migration、provision 腳本與 CI 權限配置已完成專項安全覆核。

前端 lint、production build、37 項單元測試及完整 164 項桌面／手機瀏覽器回歸通過。新增的 34 項瀏覽器案例涵蓋真實 WebCrypto 公鑰產生、原請求重試、獨立核准、跨設備／登入切換、私鑰期限、查詢失敗後保留同一金鑰、額外 DTO 欄位拒絕，以及舊申請到期不影響另一份查詢。平台 UI 的一般覆核與專項安全覆核均完成；瀏覽器 API 使用合成回應，資料庫行為另以後端整合測試驗證。
