--  Remove refreshToken table and expiresAt column from tokens table.
--  (commented out to avoid accidentally running this in production...)

-- DROP TABLE refreshTokens;
-- ALTER TABLE tokens DROP COLUMN expiresAt;

-- UPDATE dbMetadata SET value = '3' WHERE name = 'schema-patch-level';
