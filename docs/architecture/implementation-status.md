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
| 39–47 | 39 P；40 A；41 P；42 A；43 A；44 A；45 A；46 A；47 A |
| 48–55 | 48 P；49 P；50 A；51 A；52 A；53 A；54 P；55 A |
| 56–63 | 56 A；57 A；58 A；59 A；60 A；61 A；62 A；63 A |
| 64–70 | 64 P；65 I；66 P；67 P；68 I；69 P；70 A |
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
- BitLocker 觀測：固定本機唯讀屬性、typed metadata、單一 native query、來源失效／不完整語義與接收端 exact schema；另有獨立投影讀取角色、目錄身分綁定、三項資源權限交集 API 與設備 Security 頁籤。百分比、protector／TPM／escrow、正式 Windows 驗收及正式註冊連線仍待完成。沒有收集或保存回復金鑰。
- Agent 接收資料庫：獨立 schema 與登入、憑證綁定映射、原子收據／心跳／快照歷史／投影與重送調和；BitLocker 與基本資料／硬體／已安裝軟體已有 Web 授權查詢與畫面；其餘 collector、正式 enrollment 與 mTLS listener 仍待完成。
- Agent 註冊身分：schema 2 pending／enrolled 狀態、穩定 request ID、獨占 lease、精確完成與中斷恢復；伺服器 grant／CSR／CA／憑證領取及 listener 仍待完成。
- Agent 註冊資料庫與格式驗證：一次性 grant 原子消耗、固定發證編號、租約調和、不可重用 epoch、不可變發證結果，以及 CSR／釘選憑證鏈的嚴格 profile。正式 CA 操作綁定、撤銷驗證、平台授權發行 UI、憑證領取與 mTLS listener 仍待完成，服務維持未啟用。
- 平台註冊加密交付：固定 RSA-OAEP-SHA256 封套、一次性接收 key、用戶端精確環境／操作核對與 token buffer 清除，並有 .NET→WebCrypto 互通測試。公鑰驗證已供提案使用；封套交付仍未組合啟用，領取 UI、撤銷與 worker 尚待接上。
- 平台初始註冊授權儲存層：獨立環境登入、固定到期時間、精確 mapping 與 operation 收據、重試調和及新舊服務隔離升級。v2 加入帶查詢時間的狀態讀回、完整收據綁定的撤銷、永久撤銷結果，以及保留歷史的升降級。v3 綁定限時 mint permit，舊 issue 僅可恢復歷史收據；此為 dormant library，尚未註冊到 API／DI／worker。平台已有申請／核准及排隊交易，密文持久化／領取與撤銷操作介面仍待完成。
- 平台設備註冊準備查詢：Inventory 頁籤內唯讀查詢、Owner-only 物件範圍交集、server-owned mapping 解析與通用服務角色隔離。畫面不揭露內部 Device ID；mapping 管理、加密交付、grant 撤銷及註冊 worker 仍待完成。
- 平台 Agent 註冊申請與核准：固定設備與接收公鑰、永久指紋保留、同 requestId 恢復、目前權限／mapping 重查及獨立操作人員核准。Web 提供申請、查詢、核准與有期限的本機金鑰保留；不能把 Approved 當作設備註冊成功。
- 平台註冊排隊：專用執行交易、不可變 operation、單一 outbox／audit、原 requester 的目前權限重查與歷史讀回，以及共用 catalog audit。畫面能呈現已排隊歷史；正式 processor 預設不可用，worker／單次許可持久化／密文保存與領取仍待完成，沒有啟用 grant 發行。
- 平台註冊背景恢復基礎：獨立 execution library、固定 canonical digest、原子 permit／密文 journal、完整收據／ACK 與發行前終止／隔離紀錄。API 與後續 store 可共用既有計畫驗證；用途專用 public-store 函式與 repository、host、交付 API／畫面及正式 listener 仍待組合，readiness 未啟用。詳見[背景恢復契約](platform-grant-worker.md)。
- 背景資料庫讀取契約：排隊後計畫／核准／通知內容的不可變防護、提交時跨表一致性、嚴格 50 欄 PostgreSQL 解碼與 SQL／C# canonical digest 對照。helper 保持 owner-only；不代表正式背景帳號或發行服務已啟用。
- 平台註冊執行資料庫：用途專用 PostgreSQL 入口與 repository、33 欄計畫 context、目前權限重查、原子 permit／密文保存、確定結果與隔離，以及用途角色永久保留。部署與每筆交易執行精確 catalog audit；private Agent DB 與 public execution DB 分離。安裝 profile 後僅專用 definer 可呼叫必要 helper，執行 LOGIN 不直接取得表權限。背景 host、密文領取與 ACK、正式 listener 仍待組合，readiness 未啟用。詳見[執行資料庫](platform-grant-public-store.md)。

- 個人收藏：四種目錄物件的加入／取消、私有持久化、範圍化分頁及雙語介面；只顯示目前有權查看且仍在有效目錄快照中的物件。

- 平台註冊工作認領：持久化 queue 與不可改寫 token 歷史、固定租約、過期接手、重試延後、資料庫終態確認及 outbox 原子完成；用途專用 queue definer、profile v3 首次安裝與 v2 升級，以及單次處理器。租約不取代發行授權。host、密文領取／ACK 與 listener 仍待組合，readiness 維持未啟用。詳見[工作認領與恢復](platform-grant-queue.md)。

- 平台盤點：Inventory 頁籤提供基本系統／網路、九類硬體與可篩選分頁的已安裝軟體；逐來源與硬體分區區分缺失、不可用、不適用、過舊與截斷。私有投影 v2 提供精確版本稽核及交易式 v1 升降級。尚不代表正式 Agent 連線啟用或設備健康判定。

- 設備標籤：八種固定標籤、環境管理入口與設備資產頁指派、雙人核准計畫、封存／重新啟用、範圍化設備篩選及授權游標版本。專用報表、Protection Rule 與非目前設備的圖形化清理入口仍待完成。

- 個人儲存篩選：類型／字面文字／設備標籤的個人定義、50 筆限制、CRUD 版本控制及重新套用目前權限的結果分頁。機齡、健康、BitLocker、離線、磁碟與 MFA 的跨設備條件仍待資料來源與查詢 adapter。

## 目前開發順序

1. AD 版本化保護政策、唯讀事實分類、可信範圍判定、持久化變更計畫／雙人核准與受控執行契約。
2. Agent 型別契約、收集器、離線 spool、Windows Service；Enrollment / mTLS / 心跳／快照／歷史／request queue。
3. Health / Age / Replacement / Security / BitLocker metadata 與受控即時金鑰揭露。
4. 11 頁籤、完整搜尋、Tags / Favorites / Saved Filters / Priority Inbox。
5. Windows Helper allowlist 啟動及簽章票券。
6. 報表引擎、Excel / 單機報表、稽核完整化、背景工作／備份／回復／部署。
7. GPO / DC health / Graph / Entra / MFA / Compliance，再接 Exchange / Offboarding / Onboarding / Intune 與進階工作流程。

## Worker 設定與驗證入口

獨立 EnrollmentWorker 已有 typed 多環境設定、public/private 兩池 profile audit、全有或全無的初始化、反向清理、固定併發與取消／退避迴圈。CLI 目前僅提供 `--verify`，不認領、不發行，API readiness 仍為 false；Windows Service 啟動、密文領取／ACK 與 listener 還待組合。此次 62 項合成設定／生命週期測試通過；完整 TLS、撤銷與正式服務驗收另留證據。部署說明見 [Worker 驗證](../deployment/enrollment-worker.md)。
## 授權狀態與領取資料契約

新增私有 lifecycle profile4 的專用唯讀 status LOGIN、完整收據讀回與 v3→v4 原子升級；issuer／revoker 支援先部署程式再升級資料庫，capability isolation 重跑保留 profile4。密文交付 library 有有限結果型別、七欄 DTO、UTC 微秒與 15 秒期限檢查，以及嚴格 ACK parser。這些元件仍未接到領取 API；public 狀態 journal 已新增不可變觀測、完整收據綁定、Unknown 障礙、終態鎖定與精確重試，仍未配置 runtime policy。專用 public profile 4、原 requester 目前授權、ACK 原子清理、Browser handoff 與 listener 為下一部分。詳見[領取契約](platform-grant-delivery.md)。

## 必須另留實際證據的驗收

隔離 Windows / IIS Kerberos、AD delegated rights / 真實變更 readback、Agent 憑證生命週期與簽章套件、Helper 原生啟動、Graph / Exchange tenant、容量及故障還原、正式 DNS / TLS / CA 與企業 pilot。沒有環境或授權時持續開發其他程式項目，不偽造成功或將 unavailable adapter 計為完成。

相關詳細紀錄見 [roadmap](roadmap.md) 與 [部署文件](../deployment/)。本表將隨後續實作更新。
