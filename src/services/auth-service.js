const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sql, getPool } = require('../config/db');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

async function findUser(identifier) {
  const pool = await getPool();
  const request = pool.request();
  request.input('identifier', sql.VarChar(320), identifier);

  const result = await request.query(`
    SELECT TOP (1)
      u.id_usuario,
      u.id_rol,
      u.nombre,
      u.correo,
      u.password_hash,
      u.activo,
      u.intentos_fallidos,
      u.bloqueado_hasta,
      u.fecha_cambio_password,
      u.fecha_creacion,
      r.nombre AS rol_nombre,
      r.activo AS rol_activo
    FROM dbo.Usuario AS u
    INNER JOIN dbo.Rol AS r
      ON r.id_rol = u.id_rol
    WHERE LOWER(u.correo) = LOWER(@identifier)
       OR LOWER(u.nombre) = LOWER(@identifier);
  `);

  return result.recordset[0] || null;
}

async function registerFailedAttempt(user) {
  const nextAttempts = Number(user.intentos_fallidos || 0) + 1;
  const pool = await getPool();
  const request = pool.request();
  request.input('id_usuario', sql.BigInt, user.id_usuario);
  request.input('intentos', sql.Int, nextAttempts);

  if (nextAttempts >= MAX_FAILED_ATTEMPTS) {
    await request.query(`
      UPDATE dbo.Usuario
      SET intentos_fallidos = @intentos,
          bloqueado_hasta = DATEADD(MINUTE, ${LOCK_MINUTES}, SYSUTCDATETIME())
      WHERE id_usuario = @id_usuario;
    `);
  } else {
    await request.query(`
      UPDATE dbo.Usuario
      SET intentos_fallidos = @intentos
      WHERE id_usuario = @id_usuario;
    `);
  }

  return nextAttempts;
}

async function clearFailedAttempts(idUsuario) {
  const pool = await getPool();
  const request = pool.request();
  request.input('id_usuario', sql.BigInt, idUsuario);
  await request.query(`
    UPDATE dbo.Usuario
    SET intentos_fallidos = 0,
        bloqueado_hasta = NULL
    WHERE id_usuario = @id_usuario;
  `);
}

function isLocked(user) {
  if (!user.bloqueado_hasta) return false;
  return new Date(user.bloqueado_hasta).getTime() > Date.now();
}

function createToken(user) {
  if (!process.env.JWT_SECRET) {
    throw new Error('Falta JWT_SECRET.');
  }

  return jwt.sign(
    {
      role: user.rol_nombre,
      name: user.nombre,
      email: user.correo
    },
    process.env.JWT_SECRET,
    {
      subject: String(user.id_usuario),
      expiresIn: process.env.JWT_EXPIRES_IN || '8h'
    }
  );
}

async function authenticate(identifier, password) {
  const user = await findUser(identifier);

  // Respuesta generica para no revelar si la cuenta existe.
  if (!user) {
    return { ok: false, status: 401, message: 'Usuario o contraseña incorrectos.' };
  }

  if (!user.activo || !user.rol_activo) {
    return { ok: false, status: 403, message: 'La cuenta no esta habilitada.' };
  }

  if (isLocked(user)) {
    return {
      ok: false,
      status: 423,
      message: 'Cuenta temporalmente bloqueada. Intenta nuevamente mas tarde.'
    };
  }

  const passwordOk = await bcrypt.compare(password, user.password_hash);

  if (!passwordOk) {
    await registerFailedAttempt(user);
    return { ok: false, status: 401, message: 'Usuario o contraseña incorrectos.' };
  }

  await clearFailedAttempts(user.id_usuario);

  const token = createToken(user);

  return {
    ok: true,
    token,
    user: {
      id: String(user.id_usuario),
      role: user.rol_nombre,
      name: user.nombre,
      email: user.correo
    }
  };
}

module.exports = { authenticate };
