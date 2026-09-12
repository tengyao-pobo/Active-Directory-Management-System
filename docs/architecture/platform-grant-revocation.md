# 平台 initial grant 撤銷與讀回契約

此增量提供私有資料庫與 typed library，尚未啟用 HTTP、worker 或 listener。它是平台授權交付、金鑰遺失及不確定結果恢復的前置能力；不代表撤銷已簽發的設備憑證。

## 固定身分與輸入

使用獨立的 per-environment `RevokeInitialGrant` 登入與 pool，與 `IssueInitialGrant` 分離。兩者透過既有 PlatformGrant capability 的不同 purpose binding 保持隔離，不能重新配置既有 issuer 登入作為 revoker。runtime 只呼叫固定函式，不直接存取資料表；Web/API、Enroll、Issue、Ingest、Projection、EnrollmentTargetRead 都不取得此能力。

撤銷與狀態讀取須帶完整原 issue receipt：環境、原 issue operation、grant、directory object、server device、mapping 建立時間、token SHA-256、原核准 digest、issue 建立／到期時間。撤銷另帶不可變 revocation operation ID 與核准 digest。不能只憑 grant ID 操作；digest 只是稽核關聯，不是簽章或人類授權證明。未來平台執行交易仍須自行完成當前權限、step-up 與操作計畫驗證。

## 讀取與撤銷結果

資料庫仍保留 `Available / Consumed / Revoked` 三種 grant state。讀取以當前時間將已過期的 Available 顯示為 Expired，不新增第四個儲存狀態。

| 儲存狀態與時間 | 狀態讀取 | 撤銷動作 | 永久 disposition |
|---|---|---|---|
| Available，尚未到期 | Available | 轉為 Revoked | Revoked |
| Available，已到期 | Expired | 轉為 Revoked，釋放 available 唯一索引 | Expired |
| Consumed | Consumed | 不修改 grant | Consumed |
| Revoked | Revoked | 不修改 grant | AlreadyRevoked |

Consumed 表示 grant 已被 enrollment 流程使用；此結果不能被 UI 顯示為「設備憑證已撤銷」。已使用的身分必須交由其 enrollment／憑證生命週期處理。過期清理也不能宣稱撤銷了一份仍有效的 bearer。

缺少原 receipt 或資料庫內容不一致時回 OutcomeUnknown／ReceiptUnavailable；完整 tuple 不符時回 OutcomeUnknown／OperationConflict，不以找不到資料推斷「先前一定沒有發行」。狀態讀取沒有副作用。

狀態讀回包含資料庫的 `ObservedAt`；Consumed／Revoked 另帶原 `consumed_at`／`revoked_at` 作為 `StateChangedAt`，Available／Expired 則不帶狀態變更時間。這是查詢當下的觀察，不能當作之後執行仍然有效的證明；撤銷在鎖內重新判斷。Unknown／Unauthorized 不帶這兩個時間。

所有 receipt 與觀察時間須為有限的 UTC 微秒精度值，mapping 建立時間不得晚於 issue 建立時間，issue 有效期恰為 600 秒。Available 的觀察時間必須早於到期，Expired 則包含到期當下；Consumed 的原消耗時間必須早於到期。狀態變更時間不得早於 issue 或晚於觀察時間。

## 永久 receipt 與不確定結果

每個 grant 只能對應一個永久 revocation operation。新的 append-only、FORCE-RLS receipt 保留完整原 issue tuple、撤銷 digest、disposition、完成時間及適用的 revoked_at，透過外鍵綁定原 issue receipt／grant。revocation operation ID 全域唯一。

完全相同的重試在核對登入 binding 後，優先讀回原撤銷 receipt，不根據後來變動的 grant state 重新判定 disposition。相同 operation ID 搭配不同欄位或 digest 必須衝突；同一 grant 改用另一個 operation ID 也衝突。receipt 永不因過期、清除封套或重試而刪除。

完成時間不得早於 issue。Revoked／Expired 的生效時間須等於完成時間，分別要求早於到期／已達到期；Consumed 沒有撤銷生效時間。AlreadyRevoked 保留原撤銷時間，範圍為 issue 建立至本次完成時間。精確重試同樣驗證此矩陣；矛盾的資料庫回應統一回 Unknown／ResponseUnavailable，不顯示為成功。

grant 狀態改變與 receipt 寫入在同一交易完成；receipt 寫入失敗時整個轉換回復。不確定 commit 必須以相同操作和完整 tuple 讀回／重試，不能換 ID 猜測成功與否。

## 鎖順序與歷史對應

撤銷固定採 binding／輸入檢查 → revoke-operation advisory lock → 原 issue receipt → environment＋grant advisory lock → grant row。不得取得 mapping 或 device row lock，避免與既有 consume 的 grant → device 順序相反。判定有效期及記錄撤銷時間須在取得 grant row lock 後完成。

原 receipt 是歷史授權對應；mapping 之後變更或移除不應阻止撤銷原 grant。撤銷只允許修改 Available 的 state 與 revoked_at，不修改 consumed 欄位，也不重新建立 token。

## 升級與驗證界線

以交易式升級加入 receipt、固定函式、精確 RLS、purpose binding 與 PlatformGrant privilege profile v2；同步所有受影響的 legacy audit。不能直接重跑建立腳本覆蓋既有服務。存在任一 revocation receipt 時拒絕降級，保留永久操作歷史。

既有 capability isolation marker 維持 v2；它表示跨服務能力隔離的版本，不代表撤銷 store 已安裝。新增撤銷能力由獨立的 PlatformGrant store／audit profile v2 識別。

合成測試涵蓋四種有效狀態、expired slot 釋放、tuple 欄位衝突、跨環境操作 ID、mapping 移除、撤銷與 consume 競爭、鎖等待跨越到期、取消與精確重試、角色隔離、ACL／RLS 漂移、升級交易回復，以及既有服務 auditor 相容性。儲存層 173 項測試與設備查詢整合 40 項測試通過，一般覆核及最終專項覆核無剩餘阻擋。這些證據限合成 PostgreSQL 與尚未組合啟用的 library；正式交付與企業部署仍需驗收。
