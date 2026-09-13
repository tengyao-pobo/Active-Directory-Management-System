-- Shared by the forward migration and the staged delivery upgrade.
-- CREATE OR REPLACE preserves owner and trigger dependency; PUBLIC is explicitly revoked.
-- Treat this released migration resource as immutable; later repairs need a new resource.
CREATE OR REPLACE FUNCTION public.guard_owner_mapping() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public."Roles"
        WHERE "EnvironmentId"=NEW."EnvironmentId" AND "Id"=NEW."RoleId" AND "BuiltInKind" IS DISTINCT FROM 'Owner') THEN
        RAISE EXCEPTION 'Directory group role target is not eligible' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION public.guard_owner_mapping() FROM PUBLIC;
