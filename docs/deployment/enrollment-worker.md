# Enrollment Worker 設定與驗證

平台設備頁仍是註冊申請、核准與結果的操作入口。這個獨立後端程式負責 Worker 的設定、資料庫契約驗證及資源生命週期；不需要操作人員改用 RSAT。

目前唯一可執行的功能是 `--verify`：驗證全部環境設定、建立每環境兩個用途專用連線池、核對 public execution profile v3 與 private issue profile v3／v4，再釋放全部連線池。它不認領工作、不發行 grant、不交付密文，也不改變 API readiness。無參數、`--process` 或任何其他參數皆以代碼 2 結束；不存在可啟用正式處理的 `Enabled` 設定。

## 設定來源

使用執行檔目錄的標準 .NET `appsettings.json`／環境設定與環境變數，在 `EnrollmentWorker` 區段填入下列 typed properties。區段中未知屬性會被拒絕。不要把含密碼的設定提交到 repository，也不要把連線字串放在命令列。

| 屬性 | 規則 |
|---|---|
| `Concurrency` | 1–8，預設 4；供後續背景迴圈組合使用 |
| `Environments` | 1–32 個，`EnvironmentId` 非空且不重複 |
| `PublicDatabase` | public execution runtime LOGIN；`ExpectedTableOwner`、`ExpectedExecutionOwner`、`ExpectedQueueOwner` |
| `PrivateDatabase` | private Issue LOGIN；`ExpectedTableOwner`、`ExpectedFunctionOwner` |
| 兩側共用欄位 | `Host`、`Port`（預設 5432）、`Database`、`Username`、`Password`、`RootCertificate` |

Host 必須是單一小寫 ASCII 完整 DNS 名稱；拒絕 IP、多主機、連線字串、任意 `Options` 與 TLS 覆寫。RootCertificate 是服務帳號能讀取的絕對路徑。登入名稱不能跨環境或用途重用，也不能使用任何設定中的 owner/definer。Public 與 private 不可指向相同的 host/port/database；資料庫稽核仍須另外驗證實際隔離，DNS 別名本身不是隔離證明。

每個 pool 固定 VerifyFull、撤銷檢查、GSS encryption disabled、UTC、`pg_catalog,pg_temp`；min 0/max 1，connect 10 秒、command 30 秒、取消等待 2 秒。禁用 Enlist、Multiplexing、NoResetOnClose、詳細錯誤與參數記錄。部署只能直連 PostgreSQL 或使用經確認的 session pooling；不要使用 transaction/statement pooling。

## 執行與結果

發佈 `src/Server/EnrollmentWorker/EnrollmentWorker.csproj` 後，執行 `EnrollmentWorker --verify`（或 `dotnet EnrollmentWorker.dll --verify`）。設定與秘密由部署機器保管；Windows Service 秘密 ACL、DNS、TLS 根憑證／撤銷可用性仍需實際部署驗收。

- 0：全部資料庫 profile 驗證及連線池釋放完成；不表示註冊功能可用。
- 1：設定、profile、連線、逾時或清理失敗；輸出固定診斷碼，避免洩漏 provider 錯誤中的秘密。
- 2：不支援的執行模式；可用 `--help` 查閱說明。
- 130：使用者取消驗證。

驗證在五分鐘後要求取消；清理會等待全部資源釋放，並非強制終止程序的時間上限。任一環境失敗便反向清理已建立的環境，不會部分開始處理工作。資源清理會嘗試所有項目；重複 disposal 共用同一個結果。此入口目前是部署前的驗證命令，尚未註冊 Windows Service／SCM 停止生命週期。

## 背景迴圈與尚待組合部分

Library 中的迴圈每環境一次只處理一筆，另受全域併發上限控制。Completed／Deferred 後等待 100 ms，LeaseLost 等待 1 秒，NoWork 等待 5 秒；OutcomeUnknown 使用 2、4、8、16、32、60 秒退避，收到已知結果後重置。取消或意外失敗會停止其他環境，等待全部工作結束後才由擁有者釋放連線池。未知結果不能轉成永久拒絕。

目前 CLI 沒有呼叫這個迴圈。正式啟動仍待同設備頁密文領取與 ACK、listener、憑證生命週期及完整恢復契約完成審查。這些能力完成後才能接上常駐服務與 readiness；不得僅增加設定開關啟動。

本次自動測試使用合成設定與 fake environments，涵蓋設定邊界、固定連線參數、多環境取消、併發上限、退避、反向清理與驗證模式不處理工作。TLS hostname／撤銷實際握手、Windows Service 安裝與正式資料庫跨環境驗證仍需獨立環境證據。
