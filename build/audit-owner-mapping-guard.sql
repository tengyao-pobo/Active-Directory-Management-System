-- Profile4 catalog slice. The enclosing profile separately pins RLS and caller identity.
WITH owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), target AS (
 SELECT function.*,language.lanname FROM pg_catalog.pg_proc function
 JOIN pg_catalog.pg_language language ON language.oid=function.prolang
 WHERE function.oid=pg_catalog.to_regprocedure('public.guard_owner_mapping()')
)
SELECT COALESCE((SELECT
 (SELECT count(*)=1 FROM owner_role)
 AND target.proowner=(SELECT oid FROM owner_role) AND target.lanname='plpgsql'
 AND target.prokind='f' AND NOT target.prosecdef AND NOT target.proisstrict AND NOT target.proleakproof
 AND target.prosupport=0 AND target.provolatile='v' AND target.proparallel='u'
 AND NOT target.proretset AND target.prorettype='pg_catalog.trigger'::regtype AND target.pronargs=0
 AND target.proargtypes::text='' AND target.proallargtypes IS NULL AND target.proargnames IS NULL AND target.proargmodes IS NULL
 AND target.pronargdefaults=0 AND target.proargdefaults IS NULL AND target.provariadic=0 AND target.probin IS NULL AND target.prosqlbody IS NULL
 AND target.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::text[]
 AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
   pg_catalog.regexp_replace(target.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')='b806f3a21438f9426cf600093bbf337c488db381aede0c038afb61351837d6af'
 AND (SELECT count(*)=1 AND bool_and(acl.grantee=target.proowner AND acl.grantor=target.proowner
   AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
   FROM pg_catalog.aclexplode(COALESCE(target.proacl,pg_catalog.acldefault('f',target.proowner))) acl)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc extra WHERE extra.pronamespace=target.pronamespace
   AND extra.proname=target.proname AND extra.oid<>target.oid)
 AND (SELECT count(*)=1 AND bool_and(relation.relowner=(SELECT oid FROM owner_role))
   FROM pg_catalog.pg_class relation WHERE relation.oid=pg_catalog.to_regclass('public."GroupMappings"'))
 AND (SELECT count(*)=1 AND bool_and(trigger.tgrelid=pg_catalog.to_regclass('public."GroupMappings"')
   AND trigger.tgfoid=target.oid AND trigger.tgname='no_owner_mapping' AND trigger.tgtype=23
   AND trigger.tgenabled='O' AND NOT trigger.tgisinternal AND trigger.tgconstraint=0
   AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred AND trigger.tgnargs=0
   AND trigger.tgattr::text='' AND trigger.tgargs=''::bytea AND trigger.tgqual IS NULL
   AND trigger.tgoldtable IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgparentid=0
   AND trigger.tgconstrrelid=0 AND trigger.tgconstrindid=0)
   FROM pg_catalog.pg_trigger trigger WHERE trigger.tgfoid=target.oid
     OR (trigger.tgrelid=pg_catalog.to_regclass('public."GroupMappings"') AND NOT trigger.tgisinternal))
 FROM target),false) AS is_valid;
