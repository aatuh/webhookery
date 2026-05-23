DELETE FROM adapter_versions WHERE name='generic-jwt' AND version='builtin-v1';
DELETE FROM provider_adapters WHERE name='generic-jwt';
