# Delivery profile activation boundary (proposal; inactive)

Profile 4 is not ready to activate. The history SQL and catalog checks are staged artifacts. Neither a passing catalog audit nor the delivery pool's closed external audit proves that every existing execution path is closed between installation and history validation.

## Authority and transaction boundary

The installer assigns functions to separate NOLOGIN definers. A restricted application table owner cannot perform these ownership transfers without additional authority over those roles. Retaining role memberships conflicts with the exact capability profile. Existing installers also require expected owner = CURRENT_USER, so the privileged executor versus final restricted owner must be resolved explicitly; a test-only ownership transfer is not a production installation procedure. A second physical LOGIN cannot inspect uncommitted installation DDL, so a privileged installer transaction and a physically authenticated owner audit cannot share one transaction.

The intended design therefore requires two durable phases:

1. The reviewed privileged installation transaction takes the exclusive profile advisory lock, installs the exact candidate profile and commits a database-enforced PendingHistoryAudit state. All execution, queue, status and delivery entrypoints must reject that state before operational data access. New delivery pair grants should be deferred where the complete installation contract permits it.
2. A separate physical restricted owner LOGIN takes the same exclusive lock and the history audit's nine relation locks, attests the maintenance structure, validates complete history visibility and row consistency, and atomically records Ready with a final audit. Failure leaves PendingHistoryAudit committed and all runtime entrypoints closed.

For reinstallation of an already-active profile, the physical owner must first commit Ready generation N to PendingHistoryAudit generation N+1 with a new nonce under the exclusive profile lock. Installation and a fresh owner audit follow. An identical Pending generation/nonce/digest may be retried; a different Pending tuple must fail. Never blindly overwrite it with ON CONFLICT.

A C# readiness flag, service shutdown, cooperative maintenance convention, or closed delivery pool alone cannot enforce this boundary against direct SQL calls. The state must be bound to the exact installation generation; a previous successful audit must never approve a later installation.

After phase 1 commits, recovery is fail-closed repair/retry or an explicitly designed downgrade. It is no longer a single-transaction rollback to profile 3. The existing rollback-only upgrade fixture still proves only pre-commit rollback behavior.

## Required runtime inventory

The following current SQL entrypoints acquire the shared profile advisory lock and call the execution audit. Their pending-state checks must occur under that lock and before their operational helpers:

| Capability | Entrypoints |
| --- | --- |
| Execution | read_execution_record, read_and_lock_plan_context, authorize_and_store_candidate, record_execution_result, quarantine_execution |
| Queue | claim_next, defer_claim, complete_claim |
| Status | read_grant_status_receipt, append_grant_status_observation |
| Delivery | read_grant_delivery, acknowledge_grant_delivery |

The complete activation review must also inventory directly granted helper functions, audit entrypoints and API planning paths. This table is a source inventory of the existing twelve wrappers, not proof that all possible direct paths are gated. Runtime and definer identities must never receive an owner maintenance bypass.

## Required evidence before consumption

- Exact singleton state relation, constraints, ownership, ACLs and transition semantics; runtime roles have no direct state-table privileges.
- Pinned gate and transition guard ABI, owner, configuration, ACL and body, with the actual Ready transition inside the history DO rather than a standalone ready setter; separate owner maintenance structural attestation while Pending.
- Physical runtime LOGINs reject both audits and direct production wrappers after privileged installation commits Pending.
- Physical restricted owner validation commits Ready only for the current installation generation; malformed history leaves Pending.
- An active runtime transaction holding the shared profile lock blocks phase 1. Phase 2 cannot approve a concurrent replacement installation.
- Failure, retry, repeated installation, nonce mismatch and privilege/structure drift remain closed, with verified cleanup and no retained installer memberships.

The accompanying unconsumed enrollment-profile4-readiness.sql currently stages only the singleton relation and transition guard. A disposable physical-owner test checks shape, invalid transitions, exclusive-lock requirements and direct runtime denial. The owner is the database trust root and can alter its objects: the guard alone cannot prove a history scan ran. The independent source manifest and owner-only ready predicate are now staged separately. The manifest uses a versioned header and ordered filename/SHA-256 pairs over LF-normalized UTF-8 sources: the six journal/status structure slices, history-row query and readiness schema. These roots exclude the generated predicate and composed audits, preventing circular hashing. This is a history-attestation contract manifest, not a digest of all installed profile DDL. Every reviewed install/reinstall must close with a new generation/nonce even when these eight roots are unchanged; ordinary audits must still attest all live functions, bindings, identities and privileges. The predicate supplements live catalog checks; it is not trusted until its exact ABI/body/ACL and table metadata are attested. Maintenance audit separation and actual history transition remain pending. No runtime gate or installer consumption is established by this foundation.
