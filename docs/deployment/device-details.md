# Phase 5 — 設備明細頁籤與導覽

電腦清單的明細改為 AD、資產、使用人、稽核、盤點五個頁籤。一次只掛載目前頁籤；資產與使用人仍使用既有寫入 API，切換前須儲存，離開會捨棄本機未儲存編輯。盤點明確標示硬體、軟體及健康來源尚不可用，不提供假觀測。

Dashboard 維修項目與清單明細均可開啟完整設備頁 `/#/device?environment=...&id=...`。連結必須與目前選取的環境一致；不一致時不發出設備 API 請求，使用者可切换到有權查看的對應環境或返回清單。直接連結仍重新向 API 驗證可見 Computer，無權、不存在、錯誤類型或失效快照不顯示設備資料。頁籤支援方向鍵、Home/End 與 ARIA tab 語義。

## 設備稽核

`GET /api/v1/environments/{environment}/devices/{computer}/audit?cursor=...` 在新鮮 Ready 快照下同時要求對該 Computer 的 Computer.View 與 Audit.View。兩種權限的範圍必須涵蓋同一物件；不從環境全部稽核下載後做前端篩選。

只提供 exact TargetId 的 Device.AssetUpdated、Device.PrimaryUserUpdated 事件，回傳 id/action/result/occurredAt，不帶 ActorId、Reason、SourceIp、CorrelationId。此為平台資產／人工關聯活動，不是 Windows Event Log 或完整 AD 變更紀錄。

每頁最多 50 筆，依時間及 GUID 降冪排序；游標經 Data Protection 綁定 environment、actor、computer、目錄 generation 與排序位置。同時間事件不重複分頁；篡改回 400、換代回 409。讀取每頁均重新授權，失去 scope 回 404。前端切換頁籤／設備時取消請求並清除舊內容。

## 部署、驗證及後續

本次沒有 schema 或 grants 變更，可用應用版本回退。本機 backend build 0 警告／錯誤，122 項測試通過（Core 27、LDAP 32、FIDO2 5、PostgreSQL/API 58）。新增 5 項設備稽核案例涵蓋雙權限、分離 scope、允許的事件與欄位、同時間分頁、目錄換代、失效及跨環境拒絕。Daybreak 獨立安全審查沒有剩餘阻擋項。

瀏覽器以合成 API fixture 驗證維修連結、頁籤、鍵盤操作、按需讀取、環境不符時零設備請求與延遲回應丟棄；仍不代表真實 AD、Agent 或 IIS 驗收。

五個頁籤整合目前已有的來源，並非完整 11 個設備頁籤或硬體盤點完成。下一階段建議 AD typed 變更預覽與核准介面，先提供可檢視的計畫與不可執行狀態；真實 AD 寫入仍須獨立完成控制與隔離網域驗收。
前端最終驗證：build/lint、13 項單元與 58 項桌面／手機瀏覽器測試全數通過。
