# 平台設備標籤

平台提供 VIP、財務、共用、會議室、機房、關鍵設備、測試、待汰換八種標籤。環境的「設備標籤」頁可建立／封存／重新啟用標籤及處理計畫；設備資產頁可提案指派或移除。設備列表提供標籤篩選。

## 變更與核准

所有變更使用既有管理 change plan：新鮮 step-up、15 分鐘有效期、不同操作人的核准，再由提案人執行。管理需要內建 Owner、`DeviceTag.Manage` 及明確 All scope，`Asset.Edit`、Admin 或 Tag-scoped Owner 均不能管理。核准人使用 `Change.Approve`；全域標籤頁不要求查看特定設備。

伺服器產生不可重用的 Tag ID，計畫綁定環境版本、Tag 版本與預期指派狀態。執行在 Serializable 交易內重驗，成功時一起更新版本、稽核與 outbox。若另一項環境管理變更已成功，舊計畫須重新提出；不自動重送失效計畫。畫面以伺服器查詢時間判斷是否已到期，最終仍由執行端檢查。

首次版本只支援八種固定 Key，不支援自訂、改名或硬刪除。封存保留既有指派與範圍授權，禁止新指派、新 scope 及透過既有 scope 新增 role assignment／group mapping；移除既有關係需另外提案。重新啟用不會重建 Tag ID。每次計畫只處理一個操作，每環境最多 100,000 筆設備標籤指派。

## 授權與範圍

`ScopeKind.DeviceTag` 的 Value 必須為小寫 D 格式 Tag GUID，不能使用顯示名稱，且不支援 descendants。目錄、收藏及其他共用 scoped query 的讀取只匹配目前 generation 的 Computer。Filter 在授權範圍內執行，不提供跨範圍計數。目錄與收藏游標綁定環境版本，授權或標籤變動時回 409 並重新查詢。

目錄重新同步不會刪除標籤指派，因為指派不以快照資料列作外鍵。已不在目前目錄的設備不會因指派而變得可見；Owner 可經明確的 `device-tag.unassign` 計畫移除其既有指派。此初版的設備畫面操作入口仍需要目前可見的設備。

目錄顯示與範圍可共用標籤。專用報表與 Protection Rule 尚待實作；標籤不會啟用 AD 保護政策、AD 寫入、健康判斷或遠端命令。

## 部署與恢復

先套用 EF migration `20260911190943_DeviceTags`，再執行 `build/provision-runtime.sql`。Migration 建立兩張 FORCE RLS 表及環境複合外鍵，固定 Key 的 CHECK 與唯一約束限制每環境八種標籤；只為既有 `BuiltInKind=Owner` 補上新權限，不改角色指派或 scope。

Runtime 不得 DELETE Tag，也不得 UPDATE 指派；Tag UPDATE 僅允許 Version、ArchivedAt、UpdatedAt、UpdatedBy。ID、Key、EnvironmentId 與建立資訊都不能由 runtime 改寫。必須套用更新後的 provision 腳本才能得到此欄位級限制。

正式回退前須備份標籤及指派；EF Down 會刪除這兩張功能資料表，並移除內建 Owner 的此項權限。一般停用應先回退應用程式並保留資料，不以刪表作日常恢復方式。測試僅使用 loopback 合成 PostgreSQL 與模擬瀏覽器，不涉及公司 AD 或正式權限變更。

## 驗證

整合盤點 v2 後，locked restore、完整建置（0 警告／錯誤）與 599 項後端測試通過，其中 API integration 180 項，標籤專屬 33 項。前端 lint、build、18 項單元測試及 108 項桌面／手機案例通過。測試涵蓋欄位級 ACL、跨環境外鍵、Owner backfill 的冪等與不改既有 scope／assignment、封存後拒絕新授權、重複計畫至多執行一次、游標版本漂移，以及用戶端時鐘偏差下的核准畫面。
