# Agent 註冊前身分持久化

`OfflineSpool.PrepareEnrollmentAsync` 先取得 spool 的獨占鎖，將 schema 2 的 DeviceGuid 與 EnrollmentRequestId 原子保存，才將 lease 回給註冊呼叫者。呼叫者必須在註冊及結果調和期間保留 lease。這兩個識別碼在取消、逾時與程序重啟後保持相同，伺服器後續須使用 request ID 實作冪等註冊。

Pending 狀態固定為 epoch 0、NextSequence 1 且沒有 envelope；不能啟動 runtime 或排入盤點。可信註冊 adapter 驗證伺服器結果後，呼叫 `CompleteAsync`，精確核對 DeviceGuid、request ID 及正數 epoch。相同結果重複完成不改寫檔案；不同身分或 epoch 會拒絕。這個本機方法不代表已驗證憑證或取得伺服器授權。

`OpenEnrolledAsync` 只開啟既有 schema 2、已完成且符合指定 GUID／epoch 的 spool，並先驗證所有待送 envelope。它不重建、重設或轉移身分。enqueue 保留 enrollment request ID 與版本，只推進 sequence。既有 schema 1 開發入口 `OpenAsync` 已改為 internal，僅供既有測試 fixture 使用，宿主不能呼叫；它拒絕 schema 2，也不自動轉換舊 spool。

若 epoch 已保存，但憑證／設定保存前程序中斷，`ResumeEnrollmentAsync` 可取得既有識別碼、request ID 與 lease 取得時的 PersistedEpoch，讓 adapter 調和相同的伺服器註冊結果。它僅接受尚未供 runtime 使用的 NextSequence 1 且佇列為空的身分，不建立新檔、不重設 epoch。後續憑證／設定保存亦須冪等。

身分遺失但有待送資料、格式錯誤、版本不符、epoch 變更或 envelope 損壞都保留檔案並停止。錯誤不觸發重新註冊、清空資料或自動換 epoch。正式服務仍使用未配置 composition；此增量不呼叫網路、CA、RSAT 或任何 AD 操作。

檔案鎖只協調合作程序；私有 spool 目錄 ACL、防 reparse、憑證私鑰保護與簽章安裝仍須另行完成。lease 不是安全憑證，不能從遠端輸入直接呼叫 CompleteAsync。

合成測試涵蓋 pending 重啟、取消、排他鎖、冪等完成、不同 GUID／request／epoch 拒絕、舊版入口隔離、版本／狀態錯誤、資料不變、spool 重啟及損壞 envelope 保留。
