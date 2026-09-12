# 平台註冊授權的執行資料庫

此部分將既有背景恢復契約接到 PostgreSQL。使用者仍在平台設備頁申請、核准與查看操作；RSAT 是部署環境資訊，不會另設一套操作流程。背景 host、密文領取、ACK 與正式 listener 尚未組合，API readiness 仍維持不可用。

## 資料與交易

四個 forward-only migration（`20260912103000` 至 `20260912103300`）加入用途身分保留、計畫讀取與鎖定、目前授權判定，以及 permit／結果／隔離的固定交易函式。既有 journal 與排隊歷史保留；回退應用程式不應刪除這些資料或 migration history。

`PostgresEnrollmentGrantExecutionStore` 使用指定環境的獨立連線池。每次 SERIALIZABLE 交易先取得共用部署鎖，以程式內嵌的 catalog 查詢驗證 audit 函式，再呼叫完整 profile audit。只有稽核通過才進入固定入口；失敗回報不確定結果，不會改用 API 或資料表 owner 帳號。

發行前先讀取嚴格的 50 欄 operation／journal 契約，再以 33 欄計畫 context 驗證完整 operation、原始 payload、計畫 hash、唯一項目、核准與接收公鑰保留紀錄。context 的 domain-separated operation digest 固定完整 19 欄 operation，不能以呼叫者提供的操作者或期限替換儲存值。

鎖定順序為環境、目錄同步、目前目錄設備、排序後的操作者與會員、計畫、operation、outbox。父計畫鎖與既有 anchor triggers 保護子項內容。最後取得資料庫時鐘，再驗證目前帳號、會員、權限範圍、版本、generation 與期限；通過後 permit 與密文在同一交易提交。

同一 operation 的競爭者使用首先提交的 permit 與密文。已有 permit 不會重新取得新的發行期限。結果保存與隔離鎖定同一 operation；確定拒絕刪除密文，結果未知或隔離則保留既有密文供調和。撤權會阻止尚未建立的 permit，但不會遮蔽已保存操作，背景程序仍能讀回及保存已發生的確定結果。

取消在 COMMIT 開始前生效；一旦送出 COMMIT，程式等待 provider 的提交結果。部署連線池須配置有限的 command timeout。provider 在提交期間取消或連線失敗時回報 OutcomeUnknown，由既有 executor 讀回持久化狀態，不能將記憶體候選當作已提交資料。

## 部署契約

離線部署者先套用 migration，配置獨立的每環境 LOGIN，以及分開的 execution／queue NOLOGIN definer，再執行 `build/provision-enrollment-execution.sql`。腳本與同目錄的 `enrollment-execution-functions.sql`、`enrollment-execution-queue.sql`、`enrollment-execution-profile.sql`、`audit-enrollment-execution.sql` 及 API operation audit 應整組部署。

必要 psql 變數為 `execution_runtime_role`、`execution_definer_role`、`execution_queue_definer_role`、`expected_table_owner_role`、`expected_environment_id` 與 `DBNAME`。連線憑證由部署環境提供，不寫入腳本。profile 以同一排他部署鎖完成預檢、函式／RLS／精確 grants 配置、永久角色身分保留及最終 audit；marker 最後建立。API audit 同時辨識尚未安裝與已安裝的精確狀態。

v2 已安裝的資料庫先套用 queue migration，再以 `build/upgrade-enrollment-execution-v2-to-v3.sql` 及 `execution_definer_role`、`execution_queue_definer_role`、`expected_table_owner_role` 變數執行一次交易式升級。不要用首次安裝腳本覆蓋 v2。`build/enrollment-execution/v2/` 保留原版安裝與稽核快照；新版 repository 要求 profile v3。升級前應停止舊 worker，升級失敗則整筆交易回復，既有操作與認領歷史不得刪除。

執行 LOGIN 僅可呼叫指定入口及 audit，不能直接讀寫應用資料表。definer 只取得固定欄位與 journal 權限；為取得列鎖而需要的 UPDATE 權限另由不可改寫 trigger 限制。環境隔離不依賴原申請人的會員仍有效，避免撤權後無法恢復既有操作。

角色名稱與 OID 的用途保留不可改寫或重用。停用帳號時保留歷史與保留紀錄；不能藉刪除角色後同名重建繞過用途檢查。跨資料庫部署須配置不同用途的獨立憑證。

本版的 execution public DB 必須與 private Agent DB 分離，背景程序使用各用途獨立的連線池。安裝預檢與每次交易的 audit 只透過 PostgreSQL catalog 偵測私有 capability registry／marker；任一存在即拒絕，包括未完整安裝的狀態，不讀取或呼叫私有物件。這項檢查只涵蓋目前資料庫，不能取代部署時為各用途配置獨立憑證。

現有 installer 不能在共同的非登入、無角色 membership table owner 下完成獨立 definer 的函式 ownership 配置，因此本版不宣告支援同庫配置。後續若需要同庫，須另有版本化安裝與升級契約。此限制屬背景部署配置，申請、核准、執行結果與設備資訊仍統一在平台內操作。

## 驗證狀態與下一步

以下為已合併 v2 執行儲存層的歷史驗證；v3 認領與升級的驗證另見[工作認領](platform-grant-queue.md)。

完整後端回歸共 12 個測試專案、1,159 項測試全部通過，含 468 項整合測試與 execution library 的 44 項單元測試；locked restore 與 Release build 零警告／錯誤。九個 repository 案例涵蓋併發、等待列鎖時取消、撤權與收據重試。全新隔離 public DB 完成 migration、實際 psql 首次安裝、兩層 audit 與讀取入口驗證；12 項 profile 測試包含不完整 private footprint 與任意 marker overload。另一項測試使用正式 capability-v2 升級流程建立的 private fixture，確認安裝以 55000 拒絕且 catalog 不變。一般覆核與 Daybreak 專項覆核均無剩餘阻擋；此結論限於本資料庫與 repository 部分。

持久化工作認領與重試已接到[工作認領層](platform-grant-queue.md)。接續工作為 host 組合、私有 target／issue 連線池、同設備頁密文領取及 ACK，然後完成正式註冊 listener。每個部分都必須有實際整合證據，不能因資料庫函式存在便開啟 readiness。
