# 平台註冊授權的背景恢復基礎

操作入口仍是平台設備頁。背景恢復基礎提供獨立 execution library 與封閉的資料庫 journal；後續的用途專用函式與 PostgreSQL repository 見[執行資料庫](platform-grant-public-store.md)。worker host、交付 API 與 listener 尚未組合。API readiness 維持不可用，不能以建立了資料表或配置了連線字串視為可發行授權。

## 恢復契約

`EnrollmentGrantExecutor` 先讀 operation 與持久化結果。沒有 permit 才產生記憶體候選封套；store 必須在重新驗證授權的同一交易保存 permit 與封套。store 的 commit 結果不明時先讀回，只有已持久化且完整驗證的 tuple 才能交給 private issue。重新啟動、重試及競爭者都使用同一 token hash、密文、deadline 及 authorization digest。

Private issue 的 Created／AlreadyCreated 結果必須通過完整收據驗證，再保存為發行結果。連線失敗、回應未知或取消不能寫入永久拒絕；OperationConflict 或矛盾收據使用可信的查詢環境與 operation ID 隔離，不能以損壞回應中的 ID 選取另一筆操作。

授權重查失敗與 permit 過期分別保存 `AuthorizationChanged`、`AuthorizationExpired`，只適用尚無 permit 的操作。隔離原因固定為 `StoredDataInvalid`、`OperationConflict`、`ReceiptMismatch`。這些狀態不能覆寫已保存的發行結果，也不能用來清除未知 private 結果的密文。

## Journal 與遷移

`20260912090000_EnrollmentGrantExecutionJournal` 及 `20260912090100_EnrollmentGrantExecutionStops` 建立 `enrollment_execution` schema。所有表 FORCE RLS，沒有授予 runtime 直接權限，也沒有可供 worker 使用的執行函式。既有 public schema 的批次配置不會授權這些表。

| 表 | 不變條件 |
|---|---|
| `mint_permits` | 每 operation 唯一、全域 token hash 唯一、期限最長 60 秒、不可更新或刪除 |
| `sealed_envelopes` | 固定 384 bytes、SHA-256 對應 permit、與 permit 同交易保存 |
| `issue_results` | 完整 contract-v2 receipt 或封閉的確定拒絕；環境／grant 唯一；不可改寫 |
| `delivery_acks` | 原 requester、密文 digest、token hash 及時間完全對應發行結果；與刪除密文同交易 |
| `execution_stops` | 發行前授權失效或隔離；不可覆寫 permit／issue 歷史；已有 stop 不能再建立 permit |

Deferred constraint triggers 在交易結束驗證跨表一致性；stop／permit 邊界另鎖定同一 operation，避免分別寫入不同表而形成矛盾狀態。ACK 與確定拒絕會要求刪除封套，permit、結果及接收公鑰指紋仍保留。ACK 只代表申請人完成領取確認，不代表設備已註冊或 grant 已消耗。

兩個遷移皆為 forward-only。回退應用程式時保留 journal；不能刪除 schema 或移除 migration history 來繞過資料保護。

## Canonical authorization digest

Digest v1 使用 SHA-256。輸入依序為 ASCII `ADGRAUTH`、大端序 uint16 版本、完整 19 欄 operation，以及 permit 版本、發行／截止時間、token hash、recipient fingerprint、ciphertext hash。GUID 為固定 36-byte lowercase ASCII；字串／SPKI 使用 uint16 byte-length prefix；時間為 Unix epoch 起的有號 int64 微秒，整數皆大端序。輸入只接受 UTC 微秒精度。

測試向量以獨立 Node encoder 核對：1110 bytes，SHA-256 `210FEA5449810D619EF3E5FED16435448AF5C7E48063A4A0651BC10FF14CE255`。Digest 提供完整性與冪等比較，本身不是授權憑證。

## 下一個組合步驟

新增的 `20260912100000_EnrollmentGrantQueuedAnchors` 固定排隊後的計畫、計畫項目、核准及 outbox 內容。API 先在原交易中保存 Queued，再新增 operation 與通知；deferred constraint 在提交時要求三者完整對應。PlanItems／Approvals 的新增、修改、移動及刪除都鎖定舊／新計畫，父項不存在或不可見時拒絕。Outbox 只允許 Attempts／DeliveredAt 的投遞記帳。既有 runtime audit 同時釘選必要觸發器、函式內容、屬性及權限。

`20260912100100_EnrollmentGrantExecutionReadContract` 提供固定 50 欄的 typed read 契約與 SQL binary digest helper；兩者都是 owner-only SECURITY INVOKER，不授予 API 或 worker 呼叫權限。`PostgresExecutionRecordCodec` 驗證完整單列、欄名／型別、狀態形狀、密文／摘要／收據與查詢身分；損壞或矛盾資料回報 OutcomeUnknown。SQL helper 使用整數大端序及 Unix 微秒，無 JSON 計畫重新序列化，也不把摘要當成授權。

Public-store repository 必須以獨立 per-environment LOGIN 及精確 profile audit 呼叫固定函式；不得沿用 API LOGIN 或直接授予表權限。在同一 SERIALIZABLE 交易先鎖定／重查 public context，以共用 `EnrollmentGrantPlanValidation` 與既有 `ChangePlanService.ComputeHash` 驗證原始計畫，再由最後一個固定函式取得 DB clock 並原子保存 permit／封套。其後組合 private target／issue pools、host、同設備頁交付與 ACK；listener 尚未完成之前，仍不能啟用正式 readiness。

Anchor 遷移不會回溯修復舊資料。正式啟用前必須預檢既有 Queued 計畫的雜湊、operation、核准與完整 outbox 對應；背景授權函式每次仍要重查，不得僅相信舊狀態值。

## 已合併基礎的驗證

後端 12 個測試專案涵蓋 1,078 項測試。完整回歸先通過 1,077 項，最後一項 EF 例外包裝的測試斷言修正後，定向重跑通過；正式程式沒有因此修改。Locked restore 與 Release build 零警告／錯誤。Execution library 共 33 項單元測試；399 項整合測試包含 45 項 journal、15 項 queued anchor、12 項 SQL read/digest，以及 24 項 catalog drift 案例。一般覆核與 Daybreak 專項覆核均無剩餘阻擋。

以上為背景恢復基礎的歷史驗證紀錄。後續 public-store repository 與 per-environment LOGIN 的驗證另記於[執行資料庫](platform-grant-public-store.md)；跨庫 host 與正式部署仍須獨立驗收。
