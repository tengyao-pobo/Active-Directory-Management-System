# 唯讀硬體盤點

Agent 新增 `hardware` 收集器，以固定 enum 選擇九組本機 `root\cimv2` 查詢：ComputerSystem、ComputerSystemProduct、BIOS、OperatingSystem、Processor、PhysicalMemory、VideoController、DiskDrive、Battery。查詢只含列明的 properties，不提供遠端主機、任意 WQL、方法呼叫、命令或腳本介面。

內容涵蓋製造商／型號、UUID、序號、BIOS 版本、Windows edition/version/build、安裝及開機時間、CPU、DIMM、GPU、磁碟與電池基本資訊。BIOS ReleaseDate 是韌體日期，不能直接當作已核實的製造日期；SMBIOS 來源與欄位語意見 Microsoft [Win32_BIOS](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios)。

每組最多 128 列、每個字串最多 512 字元，保留 IsTruncated。只輸出 allowlist properties，未取得或無法解讀的值保留 null；整列存在不代表每個欄位完整。每組保存來源、觀測時間、品質與固定錯誤碼，單組錯誤不丟棄其他結果。必要來源沒有列時 Unknown；Battery / Video 成功查詢且沒有列時 NotApplicable。

原生呼叫在背景工作執行，設定 WMI timeout 並限制等待時間。單一 reader 保持一個原生查詢 gate；若 provider 卡住，gate 要等原生呼叫實際返回才釋放，後續查詢不再啟動更多工作。此機制不能強制殺掉 WMI provider；服務必須重用 reader，不能透過反覆建立 reader 繞過限制。未查詢本機主機上的真實資料。

日期保留 WMI DMTF 原始字串，容量保留來源整數單位。AdapterRAM 等來源可能有舊 API 位寬限制，不推算成 GPU 真實可用記憶體。此增量沒有 SMART、battery degradation、pending reboot、安全姿態或製造日期驗證，不能以基本磁碟／電池資料宣稱健康。

System.Management 只在 Windows 支援；Linux CI 使用 fake reader。測試驗證 allowlist、來源隔離、錯誤資訊不外洩、row/string 上限、可選／必要空結果與取消。Windows WMI 權限、provider 卡住與真實硬體矩陣仍需隔離端點驗收，宿主預設保持 NotConfigured。
