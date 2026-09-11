# 全項目實作追蹤

使用者已於 2026-09-11 指示：每部分完成驗證及合併後直接接續，直到所有項目完成。此表對照最初 100 組需求；V2 / V3 仍屬待開發範圍，不因先前 V1 排程而視為免做。程式完成與正式環境驗收分開記錄。

使用者於 2026-09-12 補充公司平常使用 RSAT，並明確要求盡量統一由平台操作。RSAT 是環境背景，不是要求將管理流程拆成外部工具入口；AD 查詢、受控變更、結果與稽核以平台內完成為優先。必要的底層 Connector 與權限界線不應變成使用者需要自行切換的流程。

狀態：I=已有實作；P=部分實作／契約／文件；A=尚未實作；E=需要真實環境驗收。I 不代表企業正式上線驗收已完成。

| 原始需求 | 目前狀態 |
|---|---|
| 1–5 | 1 P；2 P；3 A/E；4 P/E；5 P |
| 6–8 | 6 I；7 I；8 P/E |
| 9–13 | 9 P；10 P；11 P；12 P；13 P/E |
| 14–20 | 14 P；15 A；16 A；17 P；18 P；19 P；20 P |
| 21–27 | 21 P；22 P；23 P；24 P；25 P；26 P；27 P |
| 28–38 | 28 A；29 P；30 P；31 P；32 P；33 P；34 A；35 P；36 P；37 P；38 P |
| 39–47 | 39 A；40 A；41 P；42 A；43 A；44 A；45 A；46 A；47 A |
| 48–55 | 48 P；49 P；50 A；51 A；52 A；53 A；54 P；55 A |
| 56–63 | 56 A；57 A；58 A；59 A；60 A；61 A；62 A；63 A |
| 64–70 | 64 P；65 P；66 A；67 A；68 A；69 P；70 A |
| 71–78 | 71 A；72 A；73 A；74 A；75 A；76 P；77 A；78 P |
| 79–87 | 79 P；80 P；81 P；82 P；83 P；84 P；85 A；86 P；87 P |
| 88–90 | 88 P；89 A；90 A |
| 91–100 | 91 P；92 P；93 A；94 A；95 P；96 P；97 A；98 P；99 P；100 P |

## 已合併的實作基礎

- PR1–3：PostgreSQL / 認證與 RBAC、React 雙語殼層、唯讀 LDAP 同步。
- PR4–9：範圍化目錄 UI、跨類型搜尋、資產備註／生命週期、手動人機關聯、Dashboard、設備明細及限定設備稽核。
- PR10：AD 部門提案的資訊預覽，不可核准／執行。
- PR11：證據模型及完整綁定收據。
- PR12：單一 GUID 目標重讀、DC + Invocation ID 綁定、判定服務接點；正式保護分類尚未啟用。
- PR13：版本化保護政策與保守分類 library；正式事實來源與寫入仍未啟用。
- Agent 基礎：觀測型別、收集器與離線 spool；服務、註冊與伺服器傳輸仍待完成。
- Agent runtime：固定盤點／心跳排程、精確收據與重送、Windows Service 宿主；預設未配置，正式 enrollment / mTLS 與伺服器持久化尚未啟用。
- 設備政策：Health 權重／證據覆蓋率／Critical override、機齡來源與下限、七因素汰換引擎；原始盤點 adapter、policy 持久化、API 與畫面綁定仍待完成。
- 硬體收集：固定唯讀 WMI 來源與逐來源錯誤／截斷資訊；SMART、安全姿態與 Windows 實際驗收仍待完成。
- Agent 接收資料庫：獨立 schema 與登入、憑證綁定映射、原子收據／心跳／快照歷史／投影與重送調和；尚未接上正式 enrollment、mTLS listener、Web 授權查詢與畫面。
- Agent 註冊身分：schema 2 pending／enrolled 狀態、穩定 request ID、獨占 lease、精確完成與中斷恢復；伺服器 grant／CSR／CA／憑證領取及 listener 仍待完成。

## 目前開發順序

1. AD 版本化保護政策、唯讀事實分類、可信範圍判定、持久化變更計畫／雙人核准與受控執行契約。
2. Agent 型別契約、收集器、離線 spool、Windows Service；Enrollment / mTLS / 心跳／快照／歷史／request queue。
3. Health / Age / Replacement / Security / BitLocker metadata 與受控即時金鑰揭露。
4. 11 頁籤、完整搜尋、Tags / Favorites / Saved Filters / Priority Inbox。
5. Windows Helper allowlist 啟動及簽章票券。
6. 報表引擎、Excel / 單機報表、稽核完整化、背景工作／備份／回復／部署。
7. GPO / DC health / Graph / Entra / MFA / Compliance，再接 Exchange / Offboarding / Onboarding / Intune 與進階工作流程。

## 必須另留實際證據的驗收

隔離 Windows / IIS Kerberos、AD delegated rights / 真實變更 readback、Agent 憑證生命週期與簽章套件、Helper 原生啟動、Graph / Exchange tenant、容量及故障還原、正式 DNS / TLS / CA 與企業 pilot。沒有環境或授權時持續開發其他程式項目，不偽造成功或將 unavailable adapter 計為完成。

相關詳細紀錄見 [roadmap](roadmap.md) 與 [部署文件](../deployment/)。本表將隨後續實作更新。
