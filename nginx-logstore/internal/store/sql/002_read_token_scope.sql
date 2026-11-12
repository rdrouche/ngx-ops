-- #89 : un jeton `read` peut être limité à une instance (instance_id optionnel).
-- write : instance_id obligatoire ; admin : jamais limité.
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scope_check
    CHECK ((role <> 'write' OR instance_id IS NOT NULL) AND (role <> 'admin' OR instance_id IS NULL));
