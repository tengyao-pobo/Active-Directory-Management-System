你是一名資深 Windows Enterprise、Active Directory、ASP.NET Core、React、Microsoft Graph、Exchange Online、Endpoint Management 與資安架構工程師。

請協助我從零設計並開發一套可正式投入企業內網使用的：

# IT Management Console

此系統不是單純的 Active Directory GUI，而是一套整合以下能力的企業內網 IT 管理平台：

* Active Directory
* Windows Endpoint Inventory
* Asset Management
* Device Health Monitoring
* Microsoft Entra ID
* Microsoft 365
* Exchange Online
* GPO
* Reporting
* Audit
* RBAC
* Helpdesk 快捷管理工具

請以「可長期維護、可跨公司部署、具備安全邊界、能實際投入企業環境」為設計標準。

不要只做 Demo。

---

# 1. 核心架構

整套系統分為三個主要元件：

1. IT Management Web Server
2. Endpoint Inventory Agent
3. Windows Management Helper

三個元件職責必須嚴格分離。

---

# 2. IT Management Web Server

這是整套系統核心。

建議技術：

Backend:

* ASP.NET Core
* .NET 10
* C#

Frontend:

* React
* TypeScript

Database:

* PostgreSQL

建議架構：

```text
Browser
   │
   ▼
React Frontend
   │
   ▼
ASP.NET Core API
   │
   ├── PostgreSQL
   ├── Active Directory Connector
   ├── Microsoft Graph Connector
   ├── Exchange Online Connector
   ├── GPO Connector
   ├── Inventory API
   ├── Health Engine
   ├── Reporting Engine
   ├── Audit Engine
   └── RBAC Engine
```

---

# 3. 部署方式

系統部署於企業內網。

例如管理主機：

```text
192.168.2.150
```

啟動後其他同網路使用者可以透過瀏覽器存取：

```text
https://192.168.2.150
```

但正式環境應優先使用內部 DNS：

```text
https://itmanage
```

或：

```text
https://itmanage.company.local
```

禁止將 IP Address 作為系統永久識別。

所有 Server / Endpoint 相關功能：

優先使用：

* DNS Name
* Hostname
* Device ID
* UUID
* Serial Number

IP 只作為動態網路屬性。

---

# 4. Server IP 變動

系統必須支援 Server IP 未來變動。

例如：

```text
192.168.2.150
↓
192.168.10.20
```

只要：

```text
itmanage.company.local
```

DNS 更新即可。

Endpoint Agent 不得寫死：

```text
https://192.168.2.150
```

應使用：

```text
https://itmanage.company.local
```

Server Settings 頁面應顯示：

* Hostname
* DNS Name
* Current IP
* Network Interface
* Agent API URL
* TLS Certificate
* Server Health

---

# 5. 跨公司設計

本平台不能綁死任何特定公司。

所有企業相關設定必須抽象成：

```text
Environment
```

例如：

```text
Company A

Active Directory
Enabled

Microsoft Graph
Enabled

Exchange Online
Enabled

Endpoint Agent
Enabled
```

未來換公司後只需要：

```text
Add Environment
↓
Detect AD
↓
Configure Agent
↓
Authorize Microsoft Graph
↓
Configure Exchange
```

不需要修改原始碼。

禁止把以下資訊 hard-code：

* Domain Name
* Tenant ID
* Client ID
* Exchange Organization
* Server IP
* OU
* Company Name
* AD Group
* API Secret
* Certificate

---

# 6. UI / UX

整套平台以：

# Dark Mode

作為主要視覺設計。

預設：

```text
Theme = Dark
```

整體風格：

* 深灰 / 黑灰背景
* 高資訊密度
* 企業級 IT Console
* 清楚的 Panel / Card
* 低對比 Border
* 避免過度動畫
* 強調資訊可讀性
* 強調操作效率

狀態顏色：

```text
正常     綠
警告     黃
異常     紅
未知     灰
資訊     藍
```

狀態除了顏色以外，也必須有文字或 Icon。

禁止只依賴顏色表示狀態。

---

# 7. 語言

預設語言：

# 繁體中文 zh-TW

同時支援：

# English en-US

使用完整 i18n 架構。

禁止將 UI 文字大量 hard-code 在 React Component。

建議：

```text
locales/
├── zh-TW.json
└── en-US.json
```

使用者可以在：

```text
Settings
→ Language
```

切換：

```text
繁體中文
English
```

使用者語言偏好需要保存。

沒有指定時：

```text
Default = zh-TW
```

---

# 8. 登入系統

平台一定要有 Authentication。

正式內網環境優先支援：

```text
Windows Integrated Authentication
Kerberos / Active Directory
```

例如：

```text
CORP\pobo
```

登入：

```text
https://itmanage
```

系統辨識目前 Windows 使用者。

也可以支援登入頁面模式作為 fallback。

必須保留：

```text
Emergency Local Owner Account
```

用途：

* AD 無法使用
* Kerberos 故障
* Connector 異常
* 緊急維修

此帳號不得作為日常帳號使用。

---

# 9. RBAC 權限系統

採：

```text
Role Based Access Control
```

預設角色：

```text
Owner
Admin
Manager
Member
Viewer
HR
```

中文：

```text
擁有者
管理員
主管
一般成員
檢視者
HR
```

Owner：

最高權限。

可以：

* Environment
* Connector
* RBAC
* 系統設定
* 所有 AD
* Exchange
* Entra
* GPO
* BitLocker
* Reporting
* Audit

只有 Owner 能：

* 轉移所有權
* 修改最高層安全設定
* 移除其他 Owner

Owner 建議僅 1～2 人。

Admin：

擁有日常 IT 管理權限。

但不能：

* 移除 Owner
* 轉移 Owner
* 修改最高級系統安全設定

Manager：

主要查看管理範圍內：

* 人員
* 資產
* 設備
* 報表
* 狀態

可以限制 Scope。

Member：

一般 IT / Helpdesk。

可以例如：

* 查看電腦
* Ping
* Reset Password
* Unlock
* Asset
* Inventory

Viewer：

唯讀。

不能修改任何資料。

HR：

主要操作：

* 人員
* Department
* 入職
* 離職
* 帳號是否建立
* 帳號是否停用
* MFA 完成狀態
* License 狀態
* 人員報表

HR 不得預設取得：

* GPO
* Domain Admin
* BitLocker Recovery Key
* RDP
* C$
* Local Administrators
* 高敏感 IT 設定

---

# 10. Permission

底層不要只看 Role。

建立細部 Permission。

例如：

```text
User.View
User.Create
User.Edit
User.Disable
User.Unlock
User.ResetPassword

Group.View
Group.Edit
Group.EditMembership

Computer.View
Computer.Inventory
Computer.Remote
Computer.OpenShare

BitLocker.ViewStatus
BitLocker.ViewRecoveryKey

GPO.View
GPO.Edit

Exchange.View
Exchange.Manage

Entra.View
Entra.Manage

Report.View
Report.Export

Audit.View

System.Manage
RBAC.Manage
```

Role 是 Permission 集合。

未來可以建立自訂角色，例如：

```text
Asset Manager
Security Auditor
Exchange Admin
Intern
Contractor
```

不需要修改程式。

---

# 11. Scope

除了 Role + Permission 之外，還要有 Scope。

支援：

```text
All
OU
Department
Group
Device Tag
```

例如：

```text
Finance Manager

Role:
Manager

Scope:
Finance
```

只能看到 Finance。

---

# 12. AD Group Mapping

可以將 AD Group 自動對應平台角色。

例如：

```text
CORP\IT-Admins
→ Admin

CORP\IT-Helpdesk
→ Member

CORP\HR
→ HR

CORP\IT-Viewers
→ Viewer
```

---

# 13. Active Directory 自動偵測

系統部署後可以偵測：

* Domain
* Forest
* Domain Controllers
* Current Domain
* DNS Domain
* NetBIOS Domain
* AD Site

提供：

```text
Detect Active Directory
```

---

# 14. Active Directory 使用者管理

User Management 支援：

* 搜尋使用者
* 查看詳細資訊
* 建立使用者
* 批次建立
* 批次修改
* 修改屬性
* Reset Password
* Unlock
* Enable
* Disable
* Account Expiration
* Password Expiration
* Password Never Expires
* Force Password Change
* Department
* Title
* Company
* Manager
* Email
* UPN
* OU
* Group Membership

---

# 15. 使用者範本

建立 User Template。

例如：

```text
財務一般員工
```

設定：

```text
Default OU
Default Department
Default Company
Default Groups
Default UPN Rule
Default Naming Rule
```

選配：

```text
Create Mailbox
Assign M365 License
```

範本不可綁死公司。

Environment 可以自己管理 Template。

---

# 16. 帳號停用

停用使用者時記錄：

* Disabled At
* Disabled By
* Disable Reason
* Scheduled Disable Time

可以支援：

```text
立即停用
```

以及：

```text
指定時間停用
```

---

# 17. Group 管理

支援：

* Group Search
* Member List
* Add Member
* Remove Member
* Batch Add
* Batch Remove

角色套用可一次加入多個 Group。

例如：

```text
Finance User
↓
Finance-Users
ERP-Users
VPN-Users
Printer-Finance
```

---

# 18. OU 管理

支援：

* Browse OU
* User Count
* Computer Count
* Move User
* Move Computer

危險操作需 Audit。

---

# 19. Protected Object

對高風險物件增加：

```text
Protected Object
```

例如：

* Domain Admin
* Enterprise Admin
* Administrator
* CEO
* Domain Controller
* Exchange Server
* Service Account
* VIP

批次操作預設排除。

---

# 20. Dry Run

所有批次修改先執行 Dry Run。

例如：

```text
將 47 名使用者加入 VPN-Users
```

先顯示：

```text
+ User01
+ User02
+ User03
...
```

確認後才 Execute。

---

# 21. Computers

建立完整 Computer 管理模組。

主要頁面：

```text
Computers
├── Overview
├── Health
├── Hardware
├── Software
├── Network
├── Security
├── AD
├── GPO
├── User
├── History
├── Notes
└── Audit
```

---

# 22. Endpoint Inventory Agent

Endpoint Agent 安裝在被管理 Windows PC。

形式：

```text
Windows Service
```

例如：

```text
IT Management Inventory Agent
```

Startup：

```text
Automatic
```

Agent 必須：

# READ ONLY

用途只限：

```text
裝置狀態
資產盤點
Heartbeat
盤點紀錄
立即重新盤點
```

禁止：

```text
PowerShell execution
CMD execution
Software installation
Software uninstall
File transfer
Restart
Shutdown
Registry modification
Firewall modification
BitLocker modification
Remote desktop
System setting changes
```

---

# 23. Agent 通訊

Endpoint 主動連線：

```text
Endpoint
↓
HTTPS 443
↓
Management Server
```

原則上不要求 Endpoint 開：

* WinRM
* SMB
* RPC
* WMI

Agent 需要安全 Registration。

建議：

```text
Initial Enrollment Token
↓
Device Registration
↓
Device Certificate
↓
Certificate-based Authentication
```

---

# 24. Agent Heartbeat

Agent 定期送 Heartbeat。

例如：

```text
Device ID
Hostname
Agent Version
Timestamp
```

定義：

```text
Online:
Heartbeat < 2 minutes

Stale:
2–15 minutes

Offline:
> 15 minutes

Never Connected:
Never registered
```

門檻必須 Configurable。

---

# 25. 立即同步資產

Web：

```text
[立即同步]
```

流程：

```text
Management Server
↓
Inventory Request
↓
Agent
↓
Read Local Information
↓
Upload Inventory
↓
Complete
```

只能要求重新盤點。

不得利用此功能執行任意命令。

---

# 26. Device Inventory

蒐集：

## 裝置資訊

* 主機名稱
* 序號
* 製造商
* 型號
* BIOS Version
* UUID

## 作業系統

* Windows Edition
* Windows Version
* Build
* Install Date
* Last Boot
* Pending Reboot

## Hardware

* CPU
* RAM
* DIMM configuration
* GPU
* Disk
* Disk Health
* Battery

## Network

* IPv4
* IPv6
* MAC
* Gateway
* DNS
* NIC
* Wi-Fi SSID

Wi-Fi SSID 必須允許由 Environment Policy 決定是否蒐集。

## Software

* Installed Applications
* Version
* Publisher
* Install Date
* Architecture

## Security

* BitLocker
* TPM
* Defender
* Firewall
* Secure Boot
* LAPS

## Identity

* Current User
* Last Logged-on User
* Domain
* Domain Join
* Entra Join

---

# 27. Installed Software

禁止主要使用：

```text
Win32_Product
```

避免 MSI consistency check 等問題。

主要使用：

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
```

以及：

```text
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
```

必要時補：

* MSIX
* AppX

---

# 28. Software Inventory Dashboard

支援：

```text
Chrome
315 devices

Adobe Reader
203 devices

SAP GUI
87 devices
```

點選軟體：

```text
Which devices installed it?
Version distribution
Publisher
Install Date
```

---

# 29. Inventory History

保存資產變更歷史。

例如：

```text
RAM
16GB → 32GB

Chrome
139 → 140

Windows Build
26100 → 26200

Disk Free
40% → 18%
```

硬體變更也需要記錄。

例如：

```text
SSD
Samsung 512GB
→ Kingston 1TB
```

---

# 30. Device Identity

禁止用 Hostname 當唯一識別。

優先：

```text
Internal Device ID
UUID
Serial Number
Agent Device ID
```

Hostname 只是 Attribute。

需要可以識別：

```text
Hostname Rename
```

而不是誤判成新設備。

---

# 31. Device Health

每台設備都需要狀態燈。

狀態：

```text
Healthy
Warning
Critical
Unknown
```

繁中：

```text
正常
注意
異常
未知
```

顏色：

```text
🟢
🟡
🔴
⚪
```

---

# 32. 狀態燈必須永久顯示

例如：

```text
Agent       🟢
Ping        🔴
WinRM       🔴
SMB         🟢
RDP         🟢
AD Trust    🟢
BitLocker   🟢
```

不能因為功能不可用就隱藏狀態。

---

# 33. Action Button

狀態燈與按鈕分開。

按鈕需要依 Availability 顯示：

```text
[一鍵遠端]         Enabled
[開啟檔案總管]     Enabled
[開啟 C$]          Enabled
[WinRM]             Disabled
[立即盤點]         Enabled
```

建議 Disabled 而不是完全 Hidden。

Hover Tooltip：

```text
WinRM 不可達，因此目前無法使用。
```

---

# 34. Health Checks

常見 Health Probe：

* Agent
* DNS
* Ping
* WinRM
* SMB
* RPC
* WMI / CIM
* RDP
* AD Trust
* DC Connectivity
* Kerberos
* Inventory Freshness
* GPO
* Windows Update
* Pending Reboot
* Disk Space
* Disk Health
* BitLocker
* TPM
* Defender
* Firewall
* Secure Boot
* Time Sync
* LAPS
* Entra
* Intune

注意：

Ping Fail != Offline

例如：

```text
Ping     🔴
Agent    🟢
```

設備仍可以：

```text
Managed / Online
```

Agent Heartbeat 是主要 Online 來源。

---

# 35. Health Score

每台設備有：

```text
Health Score
0–100
```

預設：

```text
>= 80
Green

60–79
Yellow

< 60
Red
```

Configurable。

評分可包含：

* Disk Health
* Battery
* Defender
* BitLocker
* TPM
* Secure Boot
* Windows Update
* Disk Space
* Agent
* AD Trust

---

# 36. Critical Override

即使 Score 很高，某些狀況仍直接 Critical。

例如：

```text
Disk SMART failure
Battery critical
Domain Trust broken
Agent extremely stale
Defender disabled
Critical disk space
```

Critical Rule 必須 Configurable。

---

# 37. Device Age

目前沒有可靠 Purchase Date。

不要用 Windows Install Date 當主要依據。

主要以：

```text
BIOS / Device Manufacturing Date
```

估算。

Fallback：

```text
Agent First Seen
```

Windows Install Date 只作為參考。

預設：

```text
0–3 years
Green

3–5 years
Yellow

>= 5 years
Red
```

門檻 Configurable。

Notebook 可以有不同 Policy。

---

# 38. Replacement Recommendation

不要單純只看 Age。

應組合：

```text
Age
Health
Disk
RAM
Windows Support
TPM
Repair History
```

產生：

```text
Replacement Priority

Low
Medium
High
```

例如：

```text
Age        6.1 years
Health     62
Windows    Unsupported
RAM        8GB

Priority   High
```

---

# 39. BitLocker

Computer → Security → BitLocker

顯示：

* Encryption Status
* Encryption Percentage
* Encryption Method
* Protector
* TPM Protector
* Recovery Key Escrow Status
* Recovery Source

Recovery Key Source：

```text
AD DS
Microsoft Entra ID
```

---

# 40. BitLocker Recovery Key

非常重要：

不得將 Recovery Key 永久保存到平台 Database。

流程：

```text
User clicks View Recovery Key
↓
RBAC Check
↓
Reason
↓
Fetch from AD / Graph
↓
Display
↓
Audit
```

權限：

```text
BitLocker.ViewStatus
BitLocker.ViewRecoveryKey
```

一般 Viewer 只能看到：

```text
Recovery Key Available
```

不能看到實際 Key。

---

# 41. Security

Computer Security：

```text
Security
├── BitLocker
├── TPM
├── Defender
├── Firewall
├── Secure Boot
├── LAPS
└── Compliance
```

---

# 42. Local Administrators

盤點：

```text
Local Administrators
```

例如：

```text
DOMAIN\Domain Admins
DOMAIN\IT-Admins
PC001\LocalAdmin
DOMAIN\User01
```

找出：

```text
Unexpected Local Admin
```

形成 Compliance。

---

# 43. Compliance

建立企業 Baseline。

例如：

```text
Firewall = Enabled
Defender = Healthy
BitLocker = Enabled
Recovery Key = Escrowed
Secure Boot = Enabled
TPM = Ready
Windows Build >= Required Build
Agent = Online
```

顯示：

```text
Compliance 92%
```

Dashboard：

```text
Compliant
Non-Compliant
Unknown
```

---

# 44. Windows Version / Lifecycle

檢查：

* Windows Edition
* Version
* Build
* Company Minimum Build

顯示：

```text
Supported
Warning
Unsupported
```

不要 hard-code EOL。

建立 Lifecycle Dataset / Configuration。

---

# 45. Computer Name Policy

允許 Environment 定義命名規則。

例如：

```text
PC-FIN-###
NB-HR-###
```

找出：

```text
DESKTOP-ABC123
USER-PC
WIN11TEST
```

標記 Naming Non-Compliance。

---

# 46. Retired / Ghost Devices

檢查：

* AD Computer Object
* Last Logon
* Agent Last Seen
* DNS
* Inventory

例如：

```text
AD Object exists
Agent 190 days offline
Last Logon 186 days ago
```

顯示：

```text
Suspected Retired Device
```

只能提出：

```text
Mark for Review
Add to Cleanup List
```

不要自動 Delete AD Object。

---

# 47. New Device Detection

當：

* AD 出現新 Computer Object
* Agent 第一次 Registration

建立：

```text
New Device
```

通知：

```text
Hostname
Model
Serial
OU
First Seen
```

---

# 48. Global Search

頂部建立全域搜尋。

搜尋：

* Display Name
* Username
* Email
* Hostname
* IP
* MAC
* Serial
* UUID
* Software
* Group
* OU

例如輸入：

```text
王小明
```

顯示：

```text
User
Current Computer
Recent Computers
Groups
Department
```

---

# 49. User ↔ Computer

必須支援雙向關聯。

User：

```text
王小明
↓
Current Computer
PC-FIN-023
```

Computer：

```text
PC-FIN-023
↓
Current User
王小明
```

並保存：

```text
Recent User History
```

---

# 50. Windows Management Helper

這是一個只安裝在 IT 管理員電腦的小型 Windows App。

它不是 Agent。

用途：

讓 Web Browser 可以啟動 Windows 本機工具。

例如：

```text
itmanage://rdp/PC-FIN-023
```

Helper：

```text
mstsc.exe /v:PC-FIN-023
```

---

# 51. Helper 支援功能

至少：

```text
RDP
Explorer UNC
C$
Computer Management
Event Viewer
Services
```

例如：

```text
[一鍵遠端]
```

↓

```text
mstsc /v:PC-FIN-023
```

---

# 52. 一鍵開啟檔案總管

提供：

```text
\\PC-FIN-023
```

按鈕：

```text
[開啟檔案總管]
```

Helper 執行：

```text
explorer.exe \\PC-FIN-023
```

---

# 53. C$

提供：

```text
\\PC-FIN-023\C$
```

按：

```text
[開啟 C$]
```

---

# 54. UNC Copy

增加：

```text
[複製 UNC]
```

例如：

```text
\\PC-FIN-023
```

以及：

```text
\\PC-FIN-023\C$
```

---

# 55. 快速診斷

按：

```text
[快速診斷]
```

顯示：

```text
DNS          🟢
Ping         🔴
Agent        🟢
WinRM        🔴
SMB          🟢
RDP          🟢
AD Trust     🟢
Disk         🟢
Reboot       🟡
Defender     🟢
BitLocker    🟢
```

同時提供簡短 Diagnosis。

---

# 56. GPO

不要重新實作整套 GPMC。

主要管理：

* GPO List
* Enabled
* Link
* OU Scope
* Security Filtering
* WMI Filtering
* Backup
* Restore
* Copy
* Report
* GPUpdate

後續可以加入 Policy Template。

---

# 57. Domain Controller Health

建立：

```text
Domain Controllers
```

每台 DC：

```text
DNS
LDAP
LDAPS
Kerberos
SYSVOL
NETLOGON
Replication
Time Sync
Disk
AD DS
```

顯示：

```text
DC01 🟢
DC02 🟡
DC03 🔴
```

---

# 58. Microsoft Graph Connector

Environment 可主動設定：

```text
Tenant ID
Client ID
Certificate / Credential
```

不得 hard-code。

支援：

* Users
* Devices
* MFA Registration
* License
* Sign-In
* Entra Join

---

# 59. MFA Dashboard

顯示：

```text
Total Users
MFA Registered
MFA Not Registered
MFA Capable
```

可以點：

```text
MFA Not Registered
```

看到人員列表。

---

# 60. Exchange Online

建立 Exchange Connector。

支援：

* Mailbox
* Shared Mailbox
* Alias
* Distribution Group
* Forwarding
* Auto Reply
* Mailbox Permission
* Send As
* Send on Behalf
* Mailbox Size

所有操作 Audit。

---

# 61. Offboarding Check

建立離職檢查。

例如：

```text
AD Account            Disabled
VPN Group             Still Member
M365 Sign-In          Blocked
M365 License          Still Assigned
Mailbox               Shared
Forwarding            Enabled
Company Device        1
```

先做 Check List。

不要第一版全部 Auto Execute。

---

# 62. User Health

顯示：

* Account Enabled
* Locked
* Password Expiry
* Last Sign-In
* MFA
* License
* Mailbox

找出：

```text
Disabled + Licensed
Inactive
Password Never Expires
Locked
Expired
Missing Department
Missing Manager
```

---

# 63. Critical Group Monitoring

監控：

```text
Domain Admins
Enterprise Admins
Schema Admins
```

如果 Member 變動：

```text
Domain Admins changed

+ User01
```

留下 Audit / Alert。

---

# 64. IT Notes

Computer 可以建立：

```text
IT Notes
```

例如：

```text
2026/08/21
更換 RAM

2026/09/03
確認藍屏問題已解除
```

---

# 65. Device Lifecycle Status

設備狀態：

```text
In Use
Spare
Repair
Replacement Planned
Retired
Disposed
Lost
```

繁中：

```text
使用中
備用
維修
待汰換
已汰換
報廢
遺失
```

---

# 66. Device Tags

支援：

```text
VIP
Finance
Shared
Meeting Room
Server Room
Critical
Test
Replacement
```

可以作為：

* Filter
* Scope
* Report
* Protection Rule

---

# 67. Saved Filters

允許保存 Filter：

```text
Finance Computers
Age > 5 Years
Health < 60
BitLocker Disabled
Agent Offline > 7 Days
Disk Space < 15%
MFA Missing
```

---

# 68. Favorites

支援常用：

```text
Computer
User
OU
Group
```

Favorites。

---

# 69. Dashboard

首頁至少包含：

```text
Active Directory

Users
Disabled
Locked
```

```text
Computers

Total
Online
Offline
Agent Missing
```

```text
Health

Healthy
Warning
Critical
Replacement Recommended
```

```text
Security

BitLocker Disabled
Recovery Key Missing
Defender Issues
Firewall Issues
```

```text
Microsoft 365

MFA Missing
License Issues
```

```text
Remote Management

WinRM Unavailable
SMB Unavailable
RDP Unavailable
AD Trust Broken
```

---

# 70. Priority Inbox

建立：

```text
需要處理
```

例如：

```text
Disk Health Failure
BitLocker Key Missing
AD Trust Broken
Age > 5 Years
Disk Space Low
Defender Issue
```

可直接點擊進 Filtered List。

---

# 71. Reporting Engine

不要每一份報表 hard-code。

建立：

```text
Report Definition
↓
Query
↓
Filter
↓
Columns
↓
Export
```

---

# 72. Reports

至少：

* AD User Report
* Disabled Accounts
* Password Expiry
* Inactive Users
* Inactive Computers
* Computer Inventory
* Hardware Inventory
* Software Inventory
* Software Version
* Group Membership
* Local Administrators
* BitLocker
* Recovery Key Coverage
* Defender
* Firewall
* MFA
* M365 License
* Exchange Mailbox
* GPO
* Device Health
* Device Age
* Replacement Recommendation
* Compliance

---

# 73. Excel Export

资产頁：

```text
[立即同步]
[匯出 Excel]
```

Excel 至少包含工作表：

```text
設備總表
硬體資訊
軟體清單
安全狀態
健康狀態
盤點歷史
建議汰換
```

---

# 74. Excel Filter Export

支援：

```text
全部
目前 Filter
OU
Department
Device Tag
Health < 60
Age >= 5 years
BitLocker Disabled
Agent Offline
```

---

# 75. Single Device Report

Computer：

```text
[產生設備報告]
```

產生：

```text
Basic Information
Hardware
Software
Security
Health
Age
History
IT Notes
```

支援：

```text
Excel
PDF
```

---

# 76. Audit Log

所有高風險操作必須 Audit。

至少：

```text
Operator
Target
Action
Before
After
Timestamp
Result
Reason
Source IP
```

包括：

* Login
* Login Failed
* Create User
* Disable User
* Reset Password
* Group Change
* GPO Change
* BitLocker Key View
* Exchange Change
* Entra Change
* RBAC Change
* Environment Change

---

# 77. BitLocker Audit

查看 Recovery Key 時至少記錄：

```text
Device
Operator
Reason
Timestamp
Result
Source
```

---

# 78. Session Security

記錄：

* Login Time
* Logout
* Source IP
* User Agent
* Session Timeout
* Failed Login

高敏感操作可以要求：

```text
Step-up Verification
```

---

# 79. Environment Settings

設定頁：

```text
Environment
├── General
├── Active Directory
├── Microsoft Graph
├── Exchange
├── Agent
├── Security
├── Health Policy
├── Asset Policy
├── Language
└── Reporting
```

---

# 80. Configurable Policies

禁止把門檻 hard-code。

例如：

```text
Health Green >= 80
Health Yellow >= 60
```

```text
Device Age Red >= 5
```

```text
Agent Offline > 15 min
```

都應該可以調整。

---

# 81. API / Secret Security

禁止：

* Secret commit Git
* Password hard-code
* Certificate Private Key hard-code

設定採：

```text
Environment Variable
Secret Store
Encrypted Configuration
Windows Certificate Store
```

提供：

```text
.env.example
appsettings.example.json
```

不能包含真實 Credentials。

---

# 82. Database

請設計合理 Schema。

至少考慮：

```text
Environments
Users
Roles
Permissions
RolePermissions
UserRoles
Scopes

DirectoryUsers
DirectoryGroups
DirectoryComputers
GroupMemberships

Devices
DeviceHardware
DeviceNetwork
DeviceSoftware
DeviceSecurity
DeviceInventorySnapshots
DeviceHealthChecks
DeviceHealthScores
DeviceNotes
DeviceTags

AgentRegistrations
AgentHeartbeats

AuditLogs

Reports
SavedFilters

ConnectorConfigurations
```

必要時自行最佳化 Normalize / Snapshot 架構。

---

# 83. Inventory Snapshot

不要每次覆蓋歷史。

應同時保存：

```text
Current State
```

和：

```text
Historical Snapshot
```

並能算 Difference。

---

# 84. API

建立清楚 REST API。

例如：

```text
/api/devices
/api/devices/{id}
/api/devices/{id}/inventory
/api/devices/{id}/health
/api/devices/{id}/history

/api/users
/api/groups
/api/ous

/api/reports

/api/audit

/api/connectors

/api/environments
```

遵循：

* DTO
* Validation
* Authorization
* Error Handling
* Pagination
* Filtering
* Sorting

---

# 85. Background Jobs

建立 Worker / Background Service。

負責：

* Health Check
* AD Sync
* Inventory Cleanup
* Report Generation
* Scheduled Tasks
* Connector Sync

不要將所有工作放在 HTTP Request 內同步執行。

---

# 86. Logging

使用 Structured Logging。

例如：

```text
Serilog
```

支援：

```text
Console
File
Database optional
```

不要把：

* Password
* Recovery Key
* Secret
* Access Token

寫入 Log。

---

# 87. Error Handling

Frontend 顯示友善錯誤。

例如：

不要只顯示：

```text
500 Internal Server Error
```

而是：

```text
WinRM 無法連線。

可能原因：
- TCP 5985 未開放
- WinRM Service 未啟動
- Firewall Blocking
```

技術細節留在 Admin Log。

---

# 88. Security Principle

採：

```text
Least Privilege
```

平台本身不要預設要求 Domain Admin。

不同功能使用對應權限。

敏感 Connector 必須有 Permission Scope。

---

# 89. Agent Security

Agent 必須：

* Signed
* TLS only
* Server Certificate Validation
* Device Identity
* Replay Protection
* Secure Registration
* Version Information

Agent 不得接受任意可執行內容。

---

# 90. Helper Security

Windows Helper 只能處理 allowlist protocol。

例如：

```text
itmanage://rdp/
itmanage://explorer/
itmanage://cshare/
itmanage://compmgmt/
itmanage://eventviewer/
```

禁止：

```text
itmanage://exec/<arbitrary command>
```

禁止任意 command execution。

---

# 91. 第一階段 V1

不要一次做完所有功能。

第一階段優先：

```text
Authentication
RBAC
Environment

Dashboard

Active Directory
├ Users
├ Groups
├ Computers
└ OU

Computer Detail

Endpoint Inventory Agent

Asset Inventory

Device Health

Device Age

BitLocker Status

Excel Export

Audit Log

Windows Helper

Global Search
```

---

# 92. V1 Computer Detail

至少完成：

```text
Overview
Health
Hardware
Software
Network
Security
AD
User
History
Notes
Audit
```

快捷按鈕：

```text
一鍵遠端
開啟檔案總管
開啟 C$
複製 UNC
Ping
快速診斷
立即盤點
查看 BitLocker Key
查看 AD
產生報告
```

Unavailable Button：

Disabled + Tooltip。

---

# 93. V2

加入：

```text
GPO
Microsoft Graph
Entra
MFA
Compliance
DC Health
Advanced Reporting
Saved Filters
Device Tags
Local Admin Compliance
```

---

# 94. V3

加入：

```text
Exchange Online
Onboarding
Offboarding
Advanced Workflow
Scheduled Reports
Approvals
Intune Integration
```

---

# 95. 專案結構

請建立乾淨的 Repository。

建議：

```text
src/
├── Server/
├── Web/
├── Agent/
├── Helper/
├── Shared/
└── Infrastructure/

tests/
├── Unit/
├── Integration/
└── Security/

docs/
├── architecture/
├── api/
├── deployment/
└── security/
```

你可以依 Clean Architecture / Modular Monolith 原則進一步最佳化。

不要過度 Microservice。

第一版優先 Modular Monolith。

---

# 96. Development Requirements

程式碼要求：

* 強型別
* Nullable enabled
* Async API
* Dependency Injection
* Clear Interfaces
* SOLID
* DTO separation
* Input Validation
* Central Error Handling
* Unit Tests
* Integration Tests
* Database Migration
* Seed Development Data
* Mock / Demo Mode

---

# 97. Demo Mode

建立：

```text
Demo Environment
```

使用假資料。

不能包含：

* 真實公司名稱
* 真實 IP
* 真實 User
* 真實 Tenant
* 真實 BitLocker Key
* 真實 Credentials

Demo Mode 可以用於 GitHub 展示。

---

# 98. 開發順序

請不要一次產生整套系統後才測試。

依照以下順序：

```text
Phase 1
Solution Architecture

Phase 2
Database + Authentication + RBAC

Phase 3
Frontend Shell + Dark Mode + i18n

Phase 4
AD Connector

Phase 5
Computer / User / Group UI

Phase 6
Inventory Agent

Phase 7
Inventory API

Phase 8
Health Engine

Phase 9
Windows Helper

Phase 10
Reporting

Phase 11
Audit

Phase 12
Security Review
```

每個 Phase：

1. Implement
2. Build
3. Test
4. Fix
5. Document
6. Commit-ready state

再進下一階段。

---

# 99. 請先完成 Architecture

開始寫大量程式碼之前，請先輸出：

1. Architecture Overview
2. Component Diagram
3. Data Flow
4. Security Boundary
5. Database Schema
6. Authentication Design
7. RBAC Design
8. Agent Protocol
9. Helper Protocol
10. API Structure
11. Project Directory
12. V1 Scope
13. Development Roadmap

確認設計一致後再開始實作。

---

# 100. 最終核心原則

這套平台的核心原則如下：

```text
Web First
Dark Mode First
Traditional Chinese First
English Supported

Environment Independent

Secure by Default
Least Privilege
Audit Everything Sensitive

Agent = Read Only
Helper = Local Launcher Only

Hostname / DNS First
IP is Dynamic

Status Always Visible
Actions Depend on Availability

Recovery Key Never Stored

Configurable Policies
Modular Architecture
Enterprise Maintainability
```

請始終維持上述架構原則。

如果在開發過程中發現某需求會破壞：

* Security Boundary
* Agent Read-only Principle
* RBAC
* Cross-company Portability
* Auditability
* Maintainability

不要直接實作。

請先指出問題，提供更安全、可維護的替代設計，再繼續開發。
