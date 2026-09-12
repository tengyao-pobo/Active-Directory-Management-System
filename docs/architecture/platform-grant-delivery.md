# 平台註冊授權領取契約

操作入口維持在平台設備頁。此增量提供密文交付與 ACK 的資料契約，以及私有 grant 狀態的專用唯讀查詢；尚未註冊領取 API、背景刷新或 listener，不能據此啟用註冊 readiness。

## 對外資料

`EnrollmentGrantDelivery` library 將結果限制為 Available、Pending、Acknowledged、Unavailable、NotFound 或 OutcomeUnknown。只有 Available 可攜帶密文，建立結果時必須再次核對預期 environment ID 與 operation ID。格式不正確或身分不相符時回 OutcomeUnknown，不傳出部分內容。

Available 的 DTO 僅有七個欄位：`formatVersion`、`operationId`、`recipientKeyFingerprint`、`ciphertext`、`ciphertextSha256`、`deliveryNotAfter`、`queriedAt`。指紋與 SHA-256 固定 32 bytes，RSA 密文固定 384 bytes；對外以 canonical、無 padding 的 base64url 編碼。它不包含 token hash、authorization digest、私有 grant ID 或設備 mapping。

時間必須是 UTC、PostgreSQL 微秒精度且不是極值；有效期限晚於查詢時間，間隔最多 15 秒。此處只驗證資料形狀與相對期限；真正 GET 仍須查目前時間、目前 requester 權限與最新私有狀態，不能將有效 DTO 視為交付許可。

ACK parser 限制輸入 1,024 bytes，只接受 `formatVersion`、`recipientKeyFingerprint`、`ciphertextSha256`。重複鍵、未知鍵、不同大小寫、非 canonical base64url 或錯誤長度均拒絕。ACK 的身分與操作由之後的路由／授權流程綁定，不從 JSON 接受；parser 成功不代表可以刪除密文。

## 私有狀態查詢

`PostgresPlatformGrantStatusReader` 使用每環境專用 LOGIN 與連線池。它只接受 lifecycle audit profile 4，驗證兩個固定狀態函式的 EXECUTE，並明確拒絕取得簽發、撤銷或舊 revoker read 函式的能力。查詢綁定完整原始 issue receipt，包括 contract version 與 mint permit deadline；結果與輸入不完全相符、無列、多列或未知格式均保守回 Unknown。

既有 issuer／revoker repository 接受精確的 profile 3 或 4，支援先部署程式、再升級資料庫的順序。新 status reader 不回退使用 revoker 帳號。SQL 安裝與配置的驗收須涵蓋三種角色互斥、跨環境拒絕、既有收據、原子回滾及 capability isolation 重跑。

## 接續整合

已在 public execution database 加入不可變狀態觀測基礎，讓 Unknown 立即使舊 Available 失效，讓已消耗／撤銷／過期狀態持續阻止交付。領取 API 必須重新核對原 requester、有效會員、目前設備權限交集及 fresh step-up；ACK 還需要 CSRF 防護與完整密文指紋匹配。

Browser 必須先將解密 token 成功交給受信任的本機 listener，之後才 ACK。ACK 與密文清理要同一交易，重試不能改換 token。尚未完成的過期密文清理需要持久化處置記錄，不能直接刪除現有 journal 所要求的封套。

狀態 journal 的資料規則如下：

- Unknown 不虛構私有查詢時間，時間欄與可交付期限皆為 NULL，保留固定診斷碼。
- Available 必須使用私有資料庫時間，晚於 public 記錄時間前 15 秒且不晚於 public 記錄時間，並落在原 grant 有效期內。可交付期限由資料庫取最早到期值，重試不延長。
- 新 Available 的私有查詢時間不得早於所有 Unknown 中最大的 public 記錄時間，避免較晚回來的舊查詢清除失效狀態。
- Consumed、Revoked 或 Expired 一旦記錄，後續狀態不能恢復交付。完整收據與合理的狀態變更時間仍須驗證。
- Observation UUID 精確重試回原序號與時間；任何輸入差異視為衝突。序號與 public 記錄時間由資料庫在取得操作鎖後產生。

## 狀態紀錄的啟用界線

新 migration 建立 append-only `status_observations`、插入防護與 SECURITY INVOKER 記錄 helper。每次呼叫要求 SERIALIZABLE，先鎖 observation UUID，再鎖 operation，核對完整 Issued 收據；由資料庫產生序號與時間。並行寫入遇到 serialization failure 時，呼叫端必須使用相同 observation UUID 與原始內容重試。

此增量不配置新的角色或 policy，也不改既有 public profile 3。FORCE RLS 且沒有允許 policy，表示一般 owner 與 runtime 都不能使用新紀錄功能；只有合成測試的管理連線可驗證規則。下一增量必須安裝完整 profile 4 的專用 status／delivery 能力後才可接入服務，readiness 仍為 false。

`Recorded` 與 `AlreadyRecorded` 綁定本次 observation UUID；`Terminal` 則回傳既有終態證據，不接受或保留新的 UUID。精確舊 UUID 重試仍回傳原始紀錄，不能把它當成目前可交付狀態。GET 必須查最新序號與固定 deadline。

## 前一增量驗證

Locked restore 與 Release build 零警告／錯誤；完整後端 14 個專案、1,358 項測試通過。最後加入跨環境資訊保護與配置前角色檢查後，受影響的私有授權專案再跑 220 項全部通過，包含 22 項 profile4 資料庫整合測試。新增交付契約另有 23 項測試。升級、配置及 capability 重跑直接使用 `psql`；提交前注入指定錯誤，驗證函式、constraint、binding 與角色能力保留完整回滾。一般檢查及 SQL／C# 專項檢查均無剩餘阻擋。這些是合成資料庫證據，尚未驗收正式企業部署。
