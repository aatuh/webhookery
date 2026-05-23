INSERT INTO provider_adapters(id, name, state)
VALUES ('pad_generic_jwt', 'generic-jwt', 'active')
ON CONFLICT (name) DO NOTHING;

INSERT INTO adapter_versions(id, adapter_id, name, version, config_hash, state)
VALUES ('adv_generic_jwt_v1', 'pad_generic_jwt', 'generic-jwt', 'builtin-v1', 'builtin:generic-jwt:v1', 'active')
ON CONFLICT (name, version) DO NOTHING;
