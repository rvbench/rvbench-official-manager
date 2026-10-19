# v1 lifecycle — 2026-10-17 implementation baseline

User approved implementation with K3 .100 manager + func/correctness worker,
K3 .18 performance-only worker and K1 .167 deployment.
No authentication; unrestricted worker enrollment; validate schema, ownership and leases.

queued -> reserved(assignment, no execution ownership) -> dispatched(lease) -> accepted -> running -> terminal.
func runs compiler/JIT validation only. Evaluator kinds remain correctness/performance.
No work is reassigned after uncertain dispatch or active lease expiration.
Claim retries use the same request_id and replay the same still-valid assignment.
Persist before network delivery. Worker terminal + outbox are one transaction.
Late results reconcile only to the original assignment; never overwrite another attempt.
Cancellation: queued/unaccepted only. Running jobs return 409 and must finish cleanup.
Standalone worker jobs are fully supported without manager. Push/pull share admission and executor.
Large stdout/evidence live under worker job directories; API exposes bounded logs and hashed artifacts.
