# Phase 4 bounded security review

2026-09-11，Daybreak Blue Security Expert 對本階段 LDAP adapter、同步發布、RLS/role scripts、查詢 scope/cursor 與 unavailable mutation boundary 完成獨立唯讀複核。這是增量範圍審查，不是整個產品的 production security certification。

已修正並複核：

- Connector login 與環境/principal 使用 session_user 綁定；不能以偽造 GUC 改寫其他環境投影或 Audit。
- 移除 Connector 對全平台 Principal/Membership 的讀取；DB role startup 檢查拒絕超出投影/Audit INSERT 的表權限與高權限 flags。
- LDAP I/O 在發布交易外執行，發布前重新驗證當下 binding/membership；同步中撤權測試通過。
- 發布鎖與 run 時間序阻擋舊 run 覆寫，取消使用獨立 cleanup token 記錄失敗並保留上一 generation。
- Paging 有獨立頁數/結果/cookie/時間上限；缺少 page control、非 Success、referral 或重複 cookie 均拒絕完整快照發布。
- DN canonical key 改為結構化長度編碼，escaped comma/plus 與顯著 trailing space 不會產生身分碰撞。
- 查詢 permission/scope 由同一 assignment 連接，opaque cursor 綁定 actor/environment/query/generation。

最終目前程式碼未發現已記錄讀取/同步基礎範圍的未解 release blocker。LDAP protection 狀態仍為 unknown，唯一 mutation adapter 為 Unavailable；preview checksum 不能充當授權。

殘餘驗收：真實隔離 AD 的 TLS/hostname、Kerberos/NTLM 策略、gMSA/委派 ACL、完整可見性、故障/複寫/規模與無機密日誌。正式 DBA 仍須檢查新建專用 role 的完整有效 grants（包括繼承/schema/function/TRIGGER/REFERENCES 等）；啟動檢查不是完整 PostgreSQL 權限證明。Group/DeviceTag scope 未投影時保持不授權，OU 根物件自身語意見 deployment/phase4.md。
