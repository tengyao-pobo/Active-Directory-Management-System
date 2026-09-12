# 平台註冊工作的認領與恢復

平台設備頁的排隊操作由背景處理器接續。認領租約只協調工作排程；發行前仍由既有 executor 與 execution store 重查授權、保存唯一 permit／密文及核對完整收據。此部分尚未接上正式 host、交付 API、ACK 或 listener，不能單獨啟用 readiness。

## 認領與歷史

`work_queue` 保存每個環境與 operation 的目前排程狀態；`claim_leases` 永久保留每次認領 token 及其原始 operation。固定入口只從既有 `EnrollmentGrantExecutionRequested` outbox 探索工作，不接受呼叫者指定任意待執行內容。

同一 token 的重試只能恢復原本的認領。租約固定為 120 秒；到期後由新 token 接手，舊 token 回報 StaleClaim。token 不會因工作完成、延後或程序重啟而綁定另一筆操作。attempt 是可飽和的重試計數，不作為認領身分；到達整數上限仍可使用新 token 恢復工作。

延後保留原始轉移結果與下一次嘗試時間，重送不延長等待。完成與延後入口自行檢查已持久化的執行終態；若已有確定結果，便在同一交易更新 queue 與 outbox 的完成時間，即使呼叫者要求重試也不再延後。呼叫者回報「成功」或執行程序正常返回，都不能取代這項資料庫檢查。

## 程序與交易

`PostgresEnrollmentGrantWorkQueue` 使用每環境的用途專用連線池；每筆 SERIALIZABLE 交易先執行完整 profile audit，並核對三個 queue 入口的預期 owner。參數化入口與嚴格欄位解碼不接受額外資料、身分不符、無限時間、延長租約或矛盾狀態。無法確認交易結果時回報 OutcomeUnknown。

`EnrollmentGrantWorkProcessor.ProcessOnceAsync` 每次處理一筆認領。同一 processor 的呼叫序列化；認領回應不明時保留 token，下一次呼叫以同一 token 查明結果。程序重啟後以新 token 探索，原租約到期後可恢復。

執行預算取資料庫剩餘租約，扣除取得回應所花的單調時鐘時間與 5 秒餘裕，最多 45 秒。取消要求傳遞給 executor；確定 caller 取消時保留租約供後續恢復。一般例外或內部期限到達嘗試延後工作，不寫成永久拒絕。完成與延後各有獨立 10 秒期限。依賴服務仍須遵守取消並配置有限的網路及資料庫 timeout。

## 部署與驗收界線

profile v3 使用獨立 NOLOGIN queue definer，與執行授權的 definer 分開。public execution DB 與 private Agent DB 仍須分離；這是背景部署契約，使用者維持平台內的單一操作流程。

既有 v2 部署透過版本化升級腳本轉換；歷史快照與 journal 應保留，不可重寫已發布的 v2 安裝契約或刪除歷史以完成升級。API catalog 查詢兼容未安裝、v2 與 v3，並嚴格配對各版本的函式內容；API 不需要取得 execution schema 使用權。

## 驗證

完整後端回歸為 12 個專案、1,234 項測試全部通過，含 495 項整合測試與 execution library 的 92 項單元測試；locked restore 與 Release build 零警告／錯誤。最終 SQL 在全新資料庫的 28 項定向測試通過，涵蓋首次安裝、競爭與取消、租約過期與飽和計數、不可改寫歷史、終態記帳及權限漂移。獨立 v2 升級案例核對永久角色／環境綁定保留、錯誤 owner 回復、過度授權時 installer 拒絕，以及舊 installer 不能覆蓋 v3。

後續補強的升級測試清理、catalog 回讀與 installer grant-option 拒絕案例亦定向重跑通過；只清理該次測試成功建立的隔離資料庫與角色。一般覆核與 Daybreak 專項覆核均無剩餘阻擋。

後續依序組合 host 與用途連線池、同設備頁密文領取與 ACK，以及正式 enrollment listener。正式 Windows、CA 與企業環境的驗收須另留實際證據。
