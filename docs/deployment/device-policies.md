# 設備健康、機齡與汰換政策

本增量實作 Core 純計算政策與合成測試。它不執行網路 probe、不接受瀏覽器自報評分，也不改變設備權限；實際盤點接收、正規化 adapter、政策持久化及畫面資料綁定仍待接續。

## Health

Health policy 帶有版本，各 HealthRule 包含權重、證據最大年齡與 Critical override 開關。有效觀測以權重計算分數，另計 evidence coverage。預設分數 80 以上 Healthy、60 以上 Warning、其餘 Critical；覆蓋率小於 80% 時 Unknown。門檻與覆蓋率皆可配置。

新鮮且確定的 Critical override 優先於分數與覆蓋率，即使該項沒有數值分數仍能回 Critical。過期、未來時間、Unknown、Unavailable 與非法分數不當成通過。只有來源有效且新鮮的 NotApplicable 能排除權重；所有項目都不適用仍顯示 Unknown。重複同一 rule 的觀測拒絕，需先由接收端做來源調和。

結果保留 ruleVersion、證據 ID、缺少項目、Critical 理由、未四捨五入的覆蓋率。狀態依未四捨五入分數判定，再輸出顯示分數；Ping 狀態與 Agent Online 政策各自獨立。此引擎不自行將 Defender、BitLocker 等欄位解讀成安全證據，來源 adapter 必須另外實作與驗證。

## Age

依序選擇已核實製造日期、BIOS 日期、Agent 首見日期，排除未來日期與不合理早期日期。每筆結果保留 estimate、source、confidence；BIOS 日期可信度低，可能是韌體更新日期；首見時間只提供觀測下限。不得顯示成購買日期或保固期限。

預設滿 3 年 Yellow、滿 5 年 Red，其餘 Green；以日曆週年判斷，不以顯示小數推算，涵蓋閏日。可為 notebook 建立不同政策。若只有 Agent 首見下限，未滿 Critical 年限時燈號保留 Unknown；剛納管不能证明設備年輕，已觀測滿 Critical 年限則確定是 Red。Windows install date 不在主要估算輸入。全部來源缺失時 Unknown，不填入 0 年。

## Replacement

政策要求 Age、Health、Disk、RAM、WindowsSupport、TPM、RepairHistory 七種因素，各有正權重。輸入為來源 adapter 正規化的 concern（0 正常、100 不利），不是直接由年齡決定汰換。預設 35 / 65 分分隔 Medium / High；未滿最低覆蓋率一律 Unknown，不能由缺值產生 Low。

結果保留政策版本、各因素來源／權重／concern、缺少因素及覆蓋率。不支援 Windows 版本的判斷仍需版本化 lifecycle dataset；此增量未自行維護支援終止清單。正常化規則與原始 evidence 必須在接入盤點後保留，這是建議資訊，不會自動採購、刪除或停用設備。

## 驗證

43 項合成測試涵蓋門檻、coverage、Critical precedence、缺少及過期資料、權重、重複輸入、日曆週年／閏日、來源可信度與七因素汰換。執行 `dotnet test tests/Unit/Unit.csproj -c Release`。
