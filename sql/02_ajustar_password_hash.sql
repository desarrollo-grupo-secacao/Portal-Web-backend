-- Ejecutar SOLO si password_hash es menor de VARCHAR(255).
-- El backend usa bcrypt; VARCHAR(255) deja margen para migraciones futuras.
ALTER TABLE dbo.Usuario
ALTER COLUMN password_hash VARCHAR(255) NOT NULL;
