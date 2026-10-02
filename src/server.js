require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRouter = require('./routes/auth');
const { getPool } = require('./config/db');

const app = express();
const port = Number(process.env.PORT || 8080);

const allowedOrigins = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(
  cors({
    origin(origin, callback) {
      // Permite herramientas sin Origin (curl/Postman) y origenes configurados.
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Origen CORS no permitido.'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);

app.get('/api/health', async (req, res, next) => {
  try {
    const pool = await getPool();
    await pool.request().query('SELECT 1 AS ok;');
    return res.json({ status: 'ok', database: 'connected' });
  } catch (error) {
    return next(error);
  }
});

app.use('/api/auth', authRouter);

app.use((req, res) => {
  return res.status(404).json({ message: 'Ruta no encontrada.' });
});

app.use((error, req, res, next) => {
  console.error(error);
  const message =
    process.env.NODE_ENV === 'production'
      ? 'Error interno del servidor.'
      : error.message;
  return res.status(500).json({ message });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`FUNTA API escuchando en puerto ${port}`);
});
