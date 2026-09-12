\set ON_ERROR_STOP on
-- Unconsumed owner transaction; input literals are substituted outside the dollar-quoted DO.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL row_security=on;
SET LOCAL lock_timeout='15s';
CREATE TEMP TABLE profile4_history_expected (
 singleton boolean PRIMARY KEY CHECK(singleton),
 generation bigint NOT NULL CHECK(generation>0),
 installation_nonce uuid NOT NULL CHECK(installation_nonce<>'00000000-0000-0000-0000-000000000000'::uuid),
 attestation_manifest_sha256 bytea NOT NULL CHECK(octet_length(attestation_manifest_sha256)=32)
) ON COMMIT DROP;
INSERT INTO pg_temp.profile4_history_expected VALUES (
 true,:'expected_generation'::bigint,:'expected_installation_nonce'::uuid,decode(:'expected_manifest_sha256','hex'));
\ir audit-enrollment-profile4-history-transition.sql
COMMIT;
