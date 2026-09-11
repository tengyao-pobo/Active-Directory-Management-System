# 平台設備盤點

設備明細的盤點頁提供設備與網路、九類硬體來源及已安裝軟體。頁面只讀取平台已接收的目前快照，不從瀏覽器觸發遠端 WMI、RSAT 或端點操作。正式 Agent 註冊與傳輸仍待完成；沒有已配置且通過驗證的資料庫讀取來源時，畫面顯示不可用。

## API 與可見範圍

`GET /api/v1/environments/{environmentId}/devices/{directoryObjectId}/inventory` 需要有效會員資格、15 分鐘內的 Ready 目錄快照，以及對同一 Computer 的 `Computer.View` 與 `Computer.Inventory` 範圍交集。不要求 `BitLocker.ViewStatus`；這個端點也不回傳 BitLocker 資料。授權完成後才呼叫固定 `read_current_inventory_projection`。

私有讀取使用明確的目錄物件到伺服器 Device ID 綁定，並要求 Active device、目前 Active registration、epoch、sequence 與 receipt 一致。三個 collector 來自同一快照；不混用不同註冊或歷史快照。瀏覽器 DTO 不包含伺服器 Device ID、Agent Device GUID、registration／receipt ID、內部診斷或原始 normalized payload。

## 可用性與資料時效

每個來源使用兩個欄位：`availability` 為 Observed、Missing、Unavailable 或 NotApplicable；`freshness` 為 Current、Stale 或 null。這讓「來源曾回報不適用，但資料已過舊」能同時呈現，不會被誤當作目前不適用。

快照收集時間與伺服器 receipt 時間必須存在；任一超過伺服器時間 5 分鐘，整份觀測不可用。任一早於 24 小時，所有可呈現來源都標示過舊。各 collector 的來源時間另外獨立判斷；硬體 section 還須計入 hardware collector 與該 section 的時間。單一 collector／section 的未來或無效時間只使該部分不可用，其餘有效部分保留。

Missing 表示沒有目前資料；Unavailable 表示來源失效、資料格式無法驗證或讀取不可用。NotApplicable 只保留 provider 支援的選用硬體來源語義；即使沒有任何可用的數值，結構有效的 hardware collector 仍能呈現各 section 的不可用／不適用狀態。已記錄的 heartbeat 是歷史資訊，不代表即時上線。

## 顯示與限制

- 設備與網路：Agent 回報主機名稱、OS 說明／版本／架構與網路介面。主機名稱不是授權或身分綁定依據。IP／MAC 僅作為盤點文字，不會因查看而自動連線。
- 硬體：System、Product、BIOS、OperatingSystem、Processor、Memory、Video、Disk、Battery。各類欄位固定且有型別驗證，缺值顯示未知。大型 UInt64 數值以 decimal string 傳送，容量以 BigInt 換算成標示明確的二進位單位，避免 JavaScript 整數精度遺失。
- 軟體：機器層級 HKLM 解除安裝登錄的 32／64 位元檢視，支援名稱、版本、發行者的本頁篩選及每頁 50 筆。日期只在回報值為有效 YYYYMMDD 時顯示，無法辨識時保留未知。清單不是軟體授權、安裝完整性或執行狀態的證明。

截斷或缺少資料有獨立提示。BIOS release date 不是製造日期；基本磁碟、電池或記憶體盤點不等於 SMART、健康評分或汰換建議。觀測資料不包含回復金鑰。

重新整理會先清除舊內容，切換設備／頁籤會取消請求；晚到回應不能寫回其他設備，401 會清除登入中的設備內容。

資料庫 clean install、v1／v2 相容性與升降級方式見 [Agent 投影查閱](agent-projection.md)。測試使用合成 API、固定時間與隔離 PostgreSQL，不宣稱完成企業端點驗收。
