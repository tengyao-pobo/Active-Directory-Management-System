# Phase 1 安全架構審查

日期：2026-09-11。審查角色：Security Expert，工具指定模型 gpt-daybreak-blue-latest。範圍：新系統信任邊界、登入/RBAC、Agent/Helper 協定、Key reveal、audit 與 job integrity；唯讀架構建議，**不是程式碼稽核、滲透測試或生產認證**。

結論：架構可行，但管理伺服器或 Connector identity 被入侵會暴露其上游實際權限範圍。平台 Scope 並不能縮小被竊取 credential 本身的上游權限，必須拆分 Connector、身分與部署邊界。

| 審查議題 | 已納入的設計決策 | 仍需實作/環境證據 |
|---|---|---|
| Kerberos/雙跳 | 使用者驗證與服務身分分離；禁 unrestricted delegation；不轉送密碼；Graph token 另有流程 | IIS/SPN/gMSA、實際 Kerberos、NTLM 策略、受限 IPC |
| Browser CSRF | 同 Origin、anti-forgery + Origin；所有 unsafe operations 包括 Helper ticket | session/bootstrap/logout/step-up CSRF 負測試 |
| Environment/Scope | 複合 env FK、RLS、Permission 與同一 assignment scope 一起判斷 | cross-env 搜尋/報表/jobs/caches 以及 pooled connection 測試 |
| Emergency Owner | 強密碼 + FIDO2、網路限制、使用告警、離線 recovery、禁止日常使用 | AD outage、authenticator loss、最後 Owner 併發與恢復演練 |
| Enrollment/replay | 一次性 hash grant、CSR possession、mTLS、sequence/epoch、revocation、受控 CA | clone/renew/disable/replay/clock skew；正式 CA 與 key ACL |
| Helper broker | signed claims、原子單次票券、user/session/workstation/env/action/target 綁定、固定工具與本機確認 | workstation binding、signature/nonce、URI fuzzing、Windows OS matrix |
| Key reveal | separate read identity、fresh step-up、理由、intent/result audit、no-store、禁止 bulk/export | canary 掃描 DB/log/queue/cache/trace；來源實際 OU 或 tenant 權限 |
| Audit outage | durable intent/outbox 前置；結果不明需 reconciliation，不能顯示成功 | crash/timeout、outbox 滿載、外部封存不可用與拒絕操作測試 |
| Batch TOCTOU | exact plan hash、非自批、expiry、逐目標 version/scope/protection 再驗 | 目標搬 OU、群組變更、撤權與部分完成測試 |
| Protected targets | 由受限安全管理維護 stable identity deny set；Agent 不能改 tags/scope/protection | Tier-0/DC/privileged membership discovery 與變動刷新 |

## 補充的強制實作規則

- 不使用 unconstrained delegation，也不把 Windows credential 自動交換成 Graph token；若日後必要使用 constrained delegation，必須提出 exact SPNs 與獨立審查。
- Production、Demo、測試使用獨立 instance、DB、queue namespace、CA/key、connector identity；禁止 production 存取測試 secret store。
- Enrollment token 至少 256-bit 隨機；原子一次性消耗；enrollment/renewal 禁 TLS 0-RTT。憑證預設 30 天、提前 7 天 renewal、最多 24 小時 overlap，均為有界 policy；每次請求即時查 registration active/revoked 狀態。
- Replay 建議即時請求 clock skew 5 分鐘、sequence 亂序窗口 128 筆；upload 歷史期限依 snapshot policy；重試可回先前成功但不能刷新 heartbeat。超窗進受控 resync，不任意歸零高水位。
- Helper 兌換後回 server-signed claims，Helper 必須本機驗證簽章/issuer/audience；信任公鑰由受控安裝或既有可信 key rotation 更新。不能從 ticket 自帶的未知 URL 取得公鑰。
- Helper 工作站經受控安裝註冊 device binding；兌換要求工作站私鑰 proof 與 Windows SID。Browser session 以 ticket 發行紀錄綁定，兌換時 Server 再查 session 未撤銷；不要求 Helper 竊取瀏覽器 cookie。
- Helper 完成簽章與 binding 校驗後、回應 launch 前原子 consume，重試返回已消耗而不重複啟動。票券過期或當前角色變動時不自動續期。
- Protected security tags 只能受限安全管理更新；一般 Asset.Edit 不得改用來扩大自身 scope 的部門、群組或 security tag。變更 scope-driving attributes 須專用授權並檢查變更前後可見性。
- 高風險 AD/Entra/GPO/Owner/RBAC 操作 V1 即要求 requester 以外合格核准者。僅一名 Owner 的部署仍須另一名被授權 reviewer；無人核准就不可執行此類平台變更，break-glass 不自動繞過。
- Owner 身分不應 bypass Protected Object、step-up 或 audit。移除最後一個 Owner 以 DB transaction 鎖定檢查，不能只靠前端按鈕。
- Connector outcome audit 無法提交時，持久化 intent 與預先已建立的執行狀態保留 unknown；Worker 重啟必須 reconciliation，禁止重新执行不確定的非冪等動作。

## 殘餘風險與可恢復性

Windows 原生工具開啟後的操作不受平台細粒度權限控制，須靠 Windows/網路授權與原生稽核。Recovery Key 一旦顯示可被截圖或複製；no-store 不等於防止管理員端惡意程式。Endpoint 管理者可偽造本機盤點，mTLS 只證明 enrollment identity，不是可信裝置健康 attestation。

平台故障時先停用受影響 Connector、registration、Helper ticket 發行或服務身分，保留 audit，再按事件範圍輪替金鑰；相關正式權限/憑證變更需要單獨的現況發現、impact、rollback、獨立審查與人類核准。資料庫還原不會復原 AD 已執行動作，須逐項以 immutable plan、audit 與上游實際狀態核對。

進入 Phase 12 必須建立全新 Security Expert 審查任務，對程式與執行證據做獨立評估；本次建議不能替代該驗收。
