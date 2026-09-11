# IT Management Console

企業內網 IT 管理平台，採 ASP.NET Core / .NET 10、React / TypeScript、PostgreSQL，預設深色與繁體中文。

An internal web-based Active Directory management platform with role-based access control, computer monitoring, remote administration, and IT management tools.

目前階段：**Phase 5 目錄查詢、跨類型搜尋與明細 UI 已實作；真實網域與寫入驗收仍待完成。**

已實作 .NET 10 Solution、PostgreSQL migrations/RLS、opaque session、Windows SSO adapter、緊急帳號密碼 + Passkey、細粒度 RBAC/Scope、雙人核准的本機設定變更、Audit/Outbox 與離線 provisioning 工具。

React UI 提供深色雙語介面、登入、環境切換、唯讀 RBAC/稽核與語言設定。AD Connector 提供受限 LDAPS 讀取、原子同步與 scoped API；實際 AD 寫入保持不可用。Inventory Agent 已有收集器及離線佇列 library，尚未部署為服務或接入伺服器；Helper 與雲端整合尚未實作。Windows SSO 尚需企業 IIS/Kerberos 驗收；Owner 轉移/移除、AD 群組即時角色解析與復原碼流程尚待完成，相關變更入口未開放。

- [架構設計：13 項交付內容](docs/architecture/architecture.md)
- [資料模型與資料保護](docs/architecture/database.md)
- [分階段實作、驗收與上線條件](docs/architecture/roadmap.md)
- [安全架構審查與決策](docs/security/design-review.md)
- [Phase 2 執行與驗證紀錄](docs/deployment/phase2.md)
- [Phase 3 前端建置與驗證](docs/deployment/phase3.md)
- [Phase 4 Connector 與驗收界線](docs/deployment/phase4.md)
- [Phase 5 目錄介面與驗證](docs/deployment/phase5.md)
- [Phase 5 電腦備註與生命週期](docs/deployment/device-assets.md)
- [Phase 5 人員與電腦雙向關聯](docs/deployment/device-user-links.md)
- [Phase 5 Dashboard 與維修清單](docs/deployment/dashboard.md)
- [Phase 5 設備明細頁籤](docs/deployment/device-details.md)
- [目前 API 契約](docs/api/phase2.md)

三個產品界線：Web Server 負責平台與受控 Connector；Endpoint Agent 僅盤點；Windows Helper 僅在管理員工作站啟動允許的本機工具。

原始碼與測試資料使用合成資訊。沒有對任何真實 AD、Entra 或 Exchange 執行操作。正式環境名稱、帳號與機密均須由部署設定提供。`.local/`、`.tools/`、credentials 與測試輸出不納入 Git。

開發需求：.NET SDK 10.0.401、PostgreSQL 18，以及分開的 migration/seed 與受限 runtime 資料庫帳號。快速驗證方式與實際測試範圍見 Phase 2 文件；不要用資料庫 superuser 啟動 API。

- [AD 部門提案預覽與限制](docs/deployment/ad-proposals.md)

- [AD 證據模型與隔離驗證](docs/deployment/ad-evidence.md)

- [單一 AD 目標重讀與判定服務接點](docs/deployment/ad-target-read.md)

- [全部需求實作追蹤](docs/architecture/implementation-status.md)

- [版本化 AD 保護政策與保守分類](docs/deployment/ad-protection-policy.md)
- [Agent 盤點與離線佇列基礎](docs/deployment/agent-foundation.md)
- [Agent 排程、傳送與 Service 宿主](docs/deployment/agent-runtime.md)
