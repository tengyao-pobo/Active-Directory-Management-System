# Agent 盤點持久化與資料庫界線

接收端使用獨立 schema、連線池與資料庫登入。機器不建立假的人員 Principal 或 Membership，也不呼叫 Web 的 BeginEnvironment。Web 對設備資料的讀取仍須套用正常的環境與物件範圍授權。

## 接收權限

專用 ingest login 僅有 CONNECT、schema USAGE 與固定 ingestion 函式 EXECUTE。沒有表格／view／sequence 的直接讀寫權限，不可繼承或切換 definer role，也不可具有 SUPERUSER、BYPASSRLS、CREATEROLE、CREATEDB 等權限。

NOLOGIN definer 擁有私有 schema、八張 Agent 表格及固定 SECURITY DEFINER 函式。所有表格啟用 FORCE RLS，policy 僅授予該 definer；Web membership SELECT 尚未開放。函式使用固定 search_path 與完整 schema 名稱，不接受動態 SQL、任意資料表或環境 authority。

這是接收登入的最小可呼叫權限；definer 本身因擁有資料表，仍有 DDL 權力。啟動稽核檢查它不可登入、沒有任何成員，以及表格 owner、FORCE RLS、policy、函式 owner 與 search_path。正式網路啟用前應將表格／schema ownership 留給離線 migration role，再縮減 definer 為必要 DML grants；未來任何新增 definer 函式仍需重新審查。

接收函式由 leaf DER SHA-256 找到有效憑證綁定、註冊、server DeviceID 與 EnvironmentID，再要求 session_user 具有該環境的 Ingest DatabaseBinding。每環境使用不同登入可進一步縮小被竊取資料庫 credential 的影響範圍。GUC／request payload 的環境欄位不能取代此映射。

憑證 fingerprint 參數是可信 listener 驗證 TLS 後的斷言，資料庫本身不能證明 TLS possession。尚未實作的 listener 必須完成 client-auth EKU、信任鏈、撤銷與連線政策，再建立 adapter-attested peer；不能從 header 或 JSON 讀取「已認證」旗標。本增量不對外開放 HTTP 接收路由。

## 原子接收與重送

收據保存完整 envelope 綁定與原始 UTC ticks bigint，不能只存 PostgreSQL timestamptz（它會失去 100 ns 精度）。Payload 與 digest v2 校驗在持久化前完成；只允許已定義的心跳與盤點 schema，限制大小與時間窗口。

同一 registration / epoch 的 replay row 在交易內鎖定。相同 sequence 與相同完整 envelope 回原收據；內容不同或 request ID 改用另一 sequence 則衝突。新 sequence 可有空洞；不存在且落在 highSequence−128 以下的舊 sequence 拒絕。最新 128 sequence 範圍內收據不可清除；舊的原收據若仍保存，可安全回覆原結果。

只有首次接收且觀測時間足夠新的心跳才更新資料庫時間 LastSeen；離線累積的舊心跳仍可保存並取得收據，但不使設備顯示在線。重播或盤點不刷新 LastSeen。新盤點寫入不可變 history；投影只接受更新的 epoch / sequence，避免亂序資料覆蓋新資料。收據、replay high-water、history、projection 與 LastSeen 在同一交易內完成。Repository 提交成功後才能建立 ACK；提交結果不明時回 Unknown，不聲稱成功，讓原 envelope 重送調和。

已保存的完全相同 envelope 在重新驗證憑證與註冊後回原收據，再重送時不重新套用新訊息的 schema 或盤點年齡窗口。憑證輪替後，只要仍綁定相同註冊，便可調和前一張憑證送出的資料。

## 部署及啟用前

將兩個 AgentIngestion project 納入 Solution 後，`build/verify.ps1` 與 backend CI 會執行 23 項 PostgreSQL 測試。Fixture 僅接受 loopback 的 `console_test` 或 `console_ci`，若既有 `agent_private` schema 存在便拒絕開始；只清除該次隨機角色擁有的 schema。可使用 `AGENT_INGESTION_TEST_DB`，或沿用測試專用 `CONSOLE_TEST_DB`，連線字串不得提交至 Git。

驗證涵蓋專用登入權限、Web 登入拒絕、環境映射、憑證失效及輪替、重送／衝突／亂序窗口、100 ns digest、交易回復、取消及實際收集器→spool→repository 的合成資料串接。部署 SQL 首次建立專用 schema；provisioning 只允許同一環境的重跑，不能默默把已綁定登入移到另一環境。

程式與 SQL 先在隔離 PostgreSQL 及合成憑證 fingerprint 測試。正式 schema / role 部署與函式擁有者、grants、search_path、RLS 需另外實際檢查。撤除 function EXECUTE 或 DatabaseBinding 可立即停止接收；保留資料表供調和，不以刪表當作一般回復程序。

Enrollment 必須先建立並持久化本機 DeviceGuid，再將它綁到註冊 epoch；不能先讓 spool 自建 GUID 再假設等於伺服器註冊。尚需一次性 grant、CSR proof、受控 CA、renewal/revocation、Agent enrollment-aware 身分初始化、mTLS listener、受保護 spool 與簽章安裝包。沒有這些證據，不啟用正式宿主 composition。
