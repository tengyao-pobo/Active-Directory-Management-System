# Phase 2 API 契約

API-only milestone；沒有 React 登入頁。HTTPS canonical Origin 須與 Host、WebAuthn RP ID 一致。設定從 environment variables/secret store 注入；不接收 caller-supplied identity headers。

所有非 GET/HEAD/OPTIONS 請求需先 `GET /api/v1/session/csrf` 取得 token，保留 anti-forgery cookie，帶 `X-CSRF-TOKEN` 與精確 `Origin`。登入後重新取得與新身分綁定的 CSRF token。所有 cookie 為 Secure/HttpOnly/SameSite=Strict；不得放 localStorage。

## 登入與 Passkey

| Method / Path | 行為 |
|---|---|
| GET `/health/live` | 不需登入的最小存活結果 |
| GET `/api/v1/session/csrf` | anti-forgery cookie + `{token}` |
| POST `/api/v1/session/windows` | 已 provisioned SID 的 Kerberos bootstrap；不自動註冊/升 Owner |
| POST `/api/v1/session/passkeys/options` | `{token}`：離線工具簽發一次性 grant；回 WebAuthn creation options |
| POST `/api/v1/session/passkeys/complete` | authenticator attestation response；實際驗證後保存 public credential，仍不登入 |
| POST `/api/v1/session/emergency/options` | `{username,password}`：通過密碼後回 assertion options，仍不登入 |
| POST `/api/v1/session/assertion` | WebAuthn assertion；驗證密碼先行 ceremony / step-up ceremony、challenge、origin、UV、key、counter；成功才建立 session 或更新 step-up |
| POST `/api/v1/session/step-up/options` | 既有 session 的 fresh verification |
| GET `/api/v1/session/me` | 目前 principal 的 id/displayName |
| POST `/api/v1/session/logout` | 撤銷當前 session 並 append audit |

Passkey ceremony 保存在 DB，cookie 只持隨機 secret；單次使用，5 分鐘到期。重發 enrollment grant 會撤銷同 principal 的舊 grant 與尚未完成的 register ceremony。發出的 token 只能在受控工作站、10 分鐘內開始注册；私鑰由 authenticator 保存。

沒有失敗回退到 password-only login，也沒有本機帳號 Web 自助註冊。Passkey 增補需新的離線 grant；目前 recovery codes/自助刪 key UI 尚未開放。

## Environment / RBAC

`GET /api/v1/environments` 只回目前 active membership 的環境，最多 200 個。下列 path 均以前綴 `/api/v1/environments/{environmentId}` 開始：

| Method / Path | 行為 |
|---|---|
| GET `/access` | 目前 principal 在該 Environment 層級可用 permission；不等於所有資源的 capability |
| GET `/rbac` | Owner 的 roles/permissions/scopes/assignments/group mappings |
| GET `/audit?limit=50&cursor=...` | Audit.View；時間+UUID composite cursor，最多 200；cursor 需 URL encode |
| POST `/change-plans` | fresh step-up + Owner permission；回不可變 plan、hash、expiry、version |
| GET `/change-plans/{id}` | 合格核准者可讀確切 preview |
| POST `/change-plans/{id}/approval` | `{planHash}`；fresh step-up、不同 principal 及 OperatorId、Change.Approve |
| POST `/change-plans/{id}/execution` | requester fresh step-up；重新授權 requester/approver、版本/hash/expiry 檢查；同交易更新資料、Executed、Audit、Outbox |

建立 plan 範例（合成資料）：

```json
{
  "change": {
    "kind": "role.create",
    "name": "Asset Reader",
    "permissions": ["Computer.View", "Report.View"]
  },
  "expectedVersion": 1,
  "reason": "建立資產檢視角色"
}
```

固定 kind 與必要欄位：

- `environment.update`: name、canonicalDns、defaultLocale（zh-TW/en-US）。
- `role.create`: name、permissions；不可仿冒 built-in role 或加入 Owner-only permissions。
- `scope.create`: scopeKind（All=0、Department=1、Group=2、DeviceTag=3、OrganizationalUnit=4）、scopeValue、includeDescendants。
- `membership.add`: principalId；只能加入已由離線工具 provisioned 的 active principal。
- `assignment.add`: principalId、roleId、scopeId；不可指向 Owner。
- `assignment.remove`: assignmentId；不可移除 Owner。
- `group-mapping.add`: groupSid、roleId、scopeId；不可指向 Owner。此階段只保存設定，真實 AD 解析在 Connector 階段驗收。

沒有任意 JSON patch、SQL、LDAP、script、secret 或外部命令 payload。Environment version 隨每次設定變更遞增，會使既有舊計畫失效；此做法較保守但避免 stale approvals。現在只有 DB-local mutations，不提供外部 Connector execution。

scope 與 permission 必須在同一 assignment 成立；Unknown protection 拒絕寫入，保護對象不得藉 Owner 繞過。OperatorId 是穩定人員識別，由離線 provisioning 維護且資料庫禁止直接變更；同一人的 Windows 與 local 帳號使用相同 OperatorId。

錯誤使用 ProblemDetails 穩定 title/code 與 traceId。403=拒絕/需 step-up、404=未知或不可見資源、409=核准/版本競爭、412=預覽版本過期、429=登入節流、503=服務不可用。DTO 模型驗證還會回 400；技術 exception 不回傳。
