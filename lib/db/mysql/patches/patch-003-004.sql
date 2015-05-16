-- Add refreshTokens

CREATE TABLE refreshTokens (
  token BINARY(32) PRIMARY KEY,
  clientId BINARY(8) NOT NULL,
  INDEX tokens_client_id(clientId),
  FOREIGN KEY (clientId) REFERENCES clients(id) ON DELETE CASCADE,
  userId BINARY(16) NOT NULL,
  INDEX tokens_user_id(userId),
  email VARCHAR(256) NOT NULL,
  scope VARCHAR(256) NOT NULL,
  createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB CHARACTER SET utf8 COLLATE utf8_unicode_ci;

-- At expiresAt column for access tokens

ALTER TABLE tokens ADD COLUMN expiresAt TIMESTAMP;

UPDATE dbMetadata SET value = '4' WHERE name = 'schema-patch-level';
