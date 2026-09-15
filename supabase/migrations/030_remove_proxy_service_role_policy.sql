-- 030_remove_proxy_service_role_policy.sql
--
-- Migration 029 removed every direct service_role privilege from tenant
-- tables. Remove the now-unused bootstrap policy from proxy tokens as well so
-- a later accidental grant cannot re-open a global service-role path.

DROP POLICY IF EXISTS proxy_access_tokens_service_role
  ON secretvault.proxy_access_tokens;
