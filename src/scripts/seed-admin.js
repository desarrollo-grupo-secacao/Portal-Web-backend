require('dotenv').config();

const bcrypt = require('bcryptjs');
const { sql, getPool } = require('../config/db');

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Falta variable requerida: ${name}`);
  return value;
}

async function main() {
  const name = process.env.ADMIN_NAME || 'admin';
  const email = required('ADMIN_EMAIL').trim().toLowerCase();
  const password = required('ADMIN_PASSWORD');
  const roleName = process.env.ADMIN_ROLE_NAME || 'admin';

  if (password.length < 12) {
    throw new Error('ADMIN_PASSWORD debe tener al menos 12 caracteres.');
  }

  const pool = await getPool();

  let role = await pool
    .request()
    .input('nombre', sql.VarChar(100), roleName)
    .query(`
      SELECT TOP (1) id_rol, nombre
      FROM dbo.Rol
      WHERE LOWER(nombre) = LOWER(@nombre);
    `);

  let idRol;

  if (role.recordset.length > 0) {
    idRol = role.recordset[0].id_rol;
    await pool
      .request()
      .input('id_rol', sql.BigInt, idRol)
      .query('UPDATE dbo.Rol SET activo = 1 WHERE id_rol = @id_rol;');
  } else {
    const inserted = await pool
      .request()
      .input('nombre', sql.VarChar(100), roleName)
      .input('descripcion', sql.VarChar(255), 'Rol administrador')
      .query(`
        INSERT INTO dbo.Rol (nombre, descripcion, activo)
        OUTPUT INSERTED.id_rol
        VALUES (@nombre, @descripcion, 1);
      `);
    idRol = inserted.recordset[0].id_rol;
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const existing = await pool
    .request()
    .input('correo', sql.VarChar(320), email)
    .query(`
      SELECT TOP (1) id_usuario
      FROM dbo.Usuario
      WHERE LOWER(correo) = LOWER(@correo);
    `);

  if (existing.recordset.length > 0) {
    const idUsuario = existing.recordset[0].id_usuario;

    await pool
      .request()
      .input('id_usuario', sql.BigInt, idUsuario)
      .input('id_rol', sql.BigInt, idRol)
      .input('nombre', sql.VarChar(150), name)
      .input('correo', sql.VarChar(320), email)
      .input('password_hash', sql.VarChar(255), passwordHash)
      .query(`
        UPDATE dbo.Usuario
        SET id_rol = @id_rol,
            nombre = @nombre,
            correo = @correo,
            password_hash = @password_hash,
            activo = 1,
            intentos_fallidos = 0,
            bloqueado_hasta = NULL,
            fecha_cambio_password = SYSUTCDATETIME()
        WHERE id_usuario = @id_usuario;
      `);

    console.log(`Usuario administrador actualizado. id_usuario=${idUsuario}`);
  } else {
    const inserted = await pool
      .request()
      .input('id_rol', sql.BigInt, idRol)
      .input('nombre', sql.VarChar(150), name)
      .input('correo', sql.VarChar(320), email)
      .input('password_hash', sql.VarChar(255), passwordHash)
      .query(`
        INSERT INTO dbo.Usuario (
          id_rol,
          nombre,
          correo,
          password_hash,
          activo,
          intentos_fallidos,
          bloqueado_hasta,
          fecha_cambio_password,
          fecha_creacion
        )
        OUTPUT INSERTED.id_usuario
        VALUES (
          @id_rol,
          @nombre,
          @correo,
          @password_hash,
          1,
          0,
          NULL,
          SYSUTCDATETIME(),
          SYSUTCDATETIME()
        );
      `);

    console.log(
      `Usuario administrador creado. id_usuario=${inserted.recordset[0].id_usuario}`
    );
  }

  console.log(`Rol usado: ${roleName} (id_rol=${idRol})`);
  console.log('La contraseña no se imprime. En SQL queda solamente el hash bcrypt.');
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
