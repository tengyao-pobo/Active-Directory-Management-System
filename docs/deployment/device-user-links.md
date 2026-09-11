# Phase 5 — 人員與電腦雙向關聯

電腦明細可搜尋並人工指定一位主要使用人，或解除關聯；使用者明細列出目前有權查看的關聯電腦。來源固定 Manual，顯示最近更新時間。這不是登入者觀測、資產所有權證明或 AD manager/memberOf 變更，也不觸發遠端或自動化。

## API

- `GET /api/v1/environments/{environment}/devices/{computer}/user`：user、version、updatedAt、source、canEdit 與 ETag。
- `PUT` 同一路徑：必須明確包含 `userId`（GUID 指定；null 解除），並提供 Origin、CSRF 與精確 If-Match；成功回 204 與新 ETag。缺少 userId 回 400，缺少 If-Match 回 428，舊版本回 412，交易競爭回 409。
- `GET /api/v1/environments/{environment}/users/{user}/devices?cursor=...`：每頁最多 50 筆，先在資料庫套用可見電腦範圍，再分頁，無全域 total。受保護 cursor 綁定 actor/environment/user/目錄 generation，換代回 409，UI 可重新載入。

搜尋使用者最多回傳 50 個可見候選；更多結果時要求縮小條件。電腦可重新指定使用人，一個人可關聯多台電腦。此版本提供当前關聯，不提供歷史清單；成功操作有版本稽核。

## 權限與保留

必須有有效 membership 與新鮮成功快照。讀取電腦關聯同時要求 Computer.View 與對應人的 User.View；隱藏或消失的對應人會使整個端點回 404，不透露姓名、GUID、版本或 ETag。反向查詢需要來源 User.View，並逐筆依 Computer.View 範圍過濾。

修改需要電腦的 Computer.View + Asset.Edit，已知受保護電腦不可修改；新、舊兩位使用人都必須可見。保護未知只允許此純平台人工註記，不放寬 AD 寫入規則。若舊使用人已消失或不在範圍，解除／替換也拒絕；清理須未來另設經審查的特權流程，不能藉由覆蓋跳過授權。

DeviceUserLinks 使用 EnvironmentId + computer GUID，RLS 強制 environment/membership 隔離。解除仍保留 UserId=null 的列並遞增版本，避免舊版本重新建立關聯。兩端均不外鍵依賴會被同步替換的 DirectoryObjects。稽核与關聯在同一交易，只記錄電腦目標、Manual 來源與版本，不把使用人身分複製到通用稽核查詢。

## 部署與驗證

先備份 DB，套用 `20260911142431_DeviceUserLinks`，再執行 `build/provision-runtime.sql`。Connector 未取得新表權限。回復應用可保留表；Down 會刪除關聯資料，必須先備份並取得資料刪除授權。

本機後端建置 0 警告/錯誤，111 項測試通過（Core 27、LDAP 32、FIDO2 5、PostgreSQL/API 47）。新增 7 項關聯案例涵蓋建立／反查／解除、隱藏前後使用人、必要欄位與 CSRF、範圍與 RLS、同時建立／修改、游標換代與使用人／actor 綁定。Daybreak 獨立安全審查未發現剩餘阻擋项。

前端 build/lint、13 項單元與 48 項桌面／手機瀏覽器測試通過。瀏覽器使用合成 fixture，不代表真實 AD 或 IIS 部署驗收。

下一階段建議：具範圍過濾的 Dashboard，顯示目錄類型數量、人工生命週期分布與維修待辦；健康、Agent 與 M365 缺資料時維持未配置／未知。
