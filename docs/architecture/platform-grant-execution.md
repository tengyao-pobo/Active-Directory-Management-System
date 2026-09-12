# 平台註冊授權執行與恢復

本增量實作平台排隊交易與私有發行期限契約。背景 worker、單次許可持久化、密文保存與交付尚未接上；正式組合的 readiness 固定為不可用，不會建立新的佇列。最終操作流程在既有設備頁面完成申請、核准、執行與查看結果；底層用途隔離不增加外部工具切換。

後續已新增獨立 execution library 與封閉 journal schema，詳見[背景恢復基礎](platform-grant-worker.md)，以及[用途專用 PostgreSQL repository](platform-grant-public-store.md)。worker host 與交付介面尚未組合。

## 執行交易

專用執行端點只接受原 requester 的 fresh step-up session 與精確 plan hash。鎖定 plan、reservation、approval 及 public context 後，重新驗證 requester 與 approver 的 Enabled、active membership、不同 OperatorId、目前 Computer scope、環境版本及目錄 generation。Requester 必須同時具 Computer.View 與 AgentEnrollmentGrant.Manage，approver 必須同時具 Computer.View 與 Change.Approve。私有 target resolver 仍須回傳計畫中的 device／mapping tuple。

交易原子保存不可變 operation、唯一 outbox 訊息、audit 與計畫的排隊結果，不產生 token 或呼叫私有發行函式。排隊不代表授權已發行或設備已註冊。相同計畫重試只讀回相同 operation；不同 hash 或內容不能建立第二份操作。

Operation 綁定 plan／approval ID 與 hash、requester／approver、環境、directory object、server device、mapping timestamp、generation／version、canonical SPKI／fingerprint 與 queued time。`AuthorizationNotAfter` 固定為 plan expiry、approval expiry、執行時 step-up expiry 與 session expiry 的最早值，不因重試或重新登入延長。

Outbox 只保存版本、環境與 operation ID。它是喚醒提示，不能當作授權來源；worker 必須重新取得不可變 operation 及目前授權狀態。

## 發行前許可與期限（worker 尚待實作）

Worker 先在記憶體產生候選封套，再於同一 SERIALIZABLE 交易鎖定並重新驗證 requester、approver、目前 scope、版本、generation 及 target，原子保存單次 mint permit 與封套。不得先提交 permit 再產生封套；這樣的中斷會留下缺少原始密文、不能判定是否能重新產生 token 的窗口。`MintPermitNotAfter = min(AuthorizationNotAfter, PermitIssuedAt + 60 seconds)`，時間由最後一次可能阻塞的檢查之後的資料庫時鐘決定。Enqueue 後的撤權或版本漂移會阻止許可；permit 建立後至期限內的漂移是有界的剩餘時間窗，不能宣稱即時取消。

既有 operation 沒有保存原始 session ID。已提交的排隊授權可在固定 `AuthorizationNotAfter` 前跨登出存活，最長十分鐘；worker 仍重查帳號、會員、目前 scope、版本、generation 及 approval。不得宣稱 worker 會偵測原 session 撤銷。若未來需要登出即取消，必須用新版本 operation 明確綁定 session。領取密文每次仍需目前有效的 fresh step-up。

Permit 後再次 resolve mapping；私有 issue 函式也必須在自身鎖內核對 mapping、device 與 deadline。新發行在鎖後以資料庫時間拒絕過期許可。精確 receipt 恢復保留原 deadline，不會延長 grant TTL 或要求重新 mint。

私有 lifecycle profile 3 與 receipt 的 `issue_contract_version` 是兩種版本。舊收據的 issue contract 1 保留 NULL deadline；新版 issue contract 2 必須綁定有限、精確到 PostgreSQL 微秒的 `MintPermitNotAfter`。八參數 issue 函式只在鎖後的資料庫時間仍小於期限，且期限不超過 60 秒時建立新授權。七參數舊函式只恢復既有舊收據，不能再新增授權。讀回與撤銷必須使用與收據版本相符的完整 tuple。

Authorization digest 從完整 operation／permit canonical bytes 計算，只用於完整性、稽核與冪等比較。真正的授權由 operation／permit、可信 worker、環境 binding 及用途專用登入共同建立；digest 本身不是 bearer 或核准證明。

## 密文與不確定結果（尚待實作）

只有確認尚無 permit 時才產生記憶體候選封套。密文、token hash、recipient fingerprint 與 permit 在同一交易持久化；競爭 worker 必須使用資料庫中已保存的那一份封套。Commit 回應不明時先依 operation ID 讀回，無法確認便保留 OutcomeUnknown，不發行記憶體候選、不重新產生 token。

私有 issue 一律使用已持久化的 hash、deadline 與 tuple。確定未寫入的拒絕可轉為 Failed；連線中斷或矛盾回應須以同一操作調和。收據回存後才可讓原 requester 經 fresh step-up 領取同一密文；ACK、私鑰遺失與撤銷遵守既有[平台交付契約](platform-enrollment-grants.md)。

即使 permit 已過期，調和仍使用相同 tuple 呼叫 private v3 issue，讓它先恢復已提交的收據；只有明確 `MintPermitExpired` 等封閉拒絕結果才能結案。矛盾收據或 OperationConflict 應隔離待查，不能歸類為可重生 token 的失敗。

## API 與資料庫部署

專用 POST `/api/v1/environments/{env}/enrollment-grant-plans/{planId}/execution` 只接受 `{ "planHash": "..." }`。首次排隊回 202；精確重試回 200 與同一 operation；integrity 或目前核准內容變動回 409；缺少可用 processor 回 503。排隊狀態為 `Queued`，不可當成 `Executed`。普通 plan execute 持續拒絕此 action。

GET `/api/v1/environments/{env}/enrollment-grant-operations/{operationId}` 與已排隊計畫的 GET 僅供原 requester 在目前有效 Computer 權限交集內查詢，不依賴舊版本、舊 mapping 或原計畫尚未到期。Plan GET 另外核對 operation／outbox 完整性；歷史讀取不需要 step-up，但重新送出執行仍需要。畫面保留已排隊狀態，不因原計畫期限到期而改成 Expired，也不提供核准或重新申請操作旗標。

以離線 migration 身分套用 `20260912003114_EnrollmentGrantOperations`，再執行既有 `build/provision-runtime.sql`。部署套件必須一併保留同目錄的 `build/audit-enrollment-grant-operations.sql`，psql 透過 `\ir` 載入；API 嵌入同一 SQL 作每次操作的 catalog audit。API runtime 僅有 operation SELECT／INSERT；表有 requester-specific FORCE RLS、完整複合外鍵與不可變 trigger。資料庫 catalog 漂移使 API 拒絕操作，provision 的最終稽核失敗則整筆回滾。

已有 operation、Queued plan 或執行 outbox 時拒絕 migration Down；回退應用程式需保留不可變操作與永久接收公鑰指紋。離線 bootstrap-owner 及 connector-principal 配置現在也在同一交易鎖定並遞增環境版本，讓既有計畫看見會員／角色改動。

## 驗證與後續工作

完整後端 11 個測試專案、957 項測試通過；locked restore 與 Release build 零警告／錯誤。包含平台申請／核准／排隊及離線配置的 85 項 PostgreSQL／HTTP 回歸、私有授權 179 項與設備查詢整合 40 項。驗證真正同時送出的單次提交、等待環境／計畫／session 列鎖後的期限重查、Queued 歷史讀取競爭、processor 停用後同一操作恢復、catalog 漂移及 provision 回滾、兩層歷史資料的降級拒絕。前端 lint、正式建置、37 項單元測試、完整 170 項桌面／手機瀏覽器測試及 .NET／WebCrypto 互通測試通過。一般覆核與凍結程式碼的專項覆核均無剩餘阻擋。

後續 worker 必須另驗證 enqueue 後 requester／approver 撤權、版本或 mapping 漂移、queue／permit 過期、跨環境 worker、偽造 outbox、並行封套保存、各個 commit 中斷點、未知結果不重生 token 與領取所有權。這些 worker／交付情境目前尚未實作或驗證，不能用排隊測試替代。
