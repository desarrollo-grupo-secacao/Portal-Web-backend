-- Validaciones basicas para las tablas usadas por el backend.

SELECT
  c.TABLE_SCHEMA,
  c.TABLE_NAME,
  c.COLUMN_NAME,
  c.DATA_TYPE,
  c.CHARACTER_MAXIMUM_LENGTH,
  c.IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS AS c
WHERE c.TABLE_SCHEMA = 'dbo'
  AND c.TABLE_NAME IN ('Rol', 'Usuario')
ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION;

-- password_hash debe tener espacio suficiente para bcrypt (60 chars).
SELECT
  COLUMN_NAME,
  DATA_TYPE,
  CHARACTER_MAXIMUM_LENGTH
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'dbo'
  AND TABLE_NAME = 'Usuario'
  AND COLUMN_NAME = 'password_hash';

-- Ver usuarios/roles sin exponer contraseñas.
SELECT
  u.id_usuario,
  u.nombre,
  u.correo,
  u.activo,
  u.intentos_fallidos,
  u.bloqueado_hasta,
  r.id_rol,
  r.nombre AS rol
FROM dbo.Usuario AS u
INNER JOIN dbo.Rol AS r
  ON r.id_rol = u.id_rol;
