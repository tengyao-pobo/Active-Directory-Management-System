-- Fail closed while public profile4 catalog attestation is unfinished.
-- This is a temporary build resource, NOT a completed privilege audit.
-- Do not activate delivery pools until exact catalog-only attestation, the pinned
-- internal audit, and PostgreSQL role/environment/upgrade tests are complete.
SELECT false AS is_valid;
