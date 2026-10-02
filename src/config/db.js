const sql = require('mssql');

let poolPromise;

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Falta variable de entorno requerida: ${name}`);
  }
  return value;
}

function getDbConfig() {
  return {
    server: required('DB_SERVER'),
    port: Number(process.env.DB_PORT || 1433),
    database: required('DB_NAME'),
    user: required('DB_USER'),
    password: required('DB_PASSWORD'),
    options: {
      encrypt: String(process.env.DB_ENCRYPT || 'true').toLowerCase() === 'true',
      trustServerCertificate:
        String(process.env.DB_TRUST_SERVER_CERTIFICATE || 'false').toLowerCase() === 'true'
    },
    pool: {
      max: 10,
      min: 0,
      idleTimeoutMillis: 30000
    },
    requestTimeout: 30000,
    connectionTimeout: 15000
  };
}

function getPool() {
  if (!poolPromise) {
    poolPromise = new sql.ConnectionPool(getDbConfig()).connect();
  }
  return poolPromise;
}

module.exports = { sql, getPool };
