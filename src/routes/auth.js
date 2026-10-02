const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticate } = require('../services/auth-service');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { message: 'Demasiados intentos. Intenta nuevamente mas tarde.' }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const identifier = String(req.body?.identifier || '').trim();
    const password = String(req.body?.password || '');

    if (!identifier || !password) {
      return res.status(400).json({ message: 'Usuario/correo y contraseña son requeridos.' });
    }

    if (identifier.length > 320 || password.length > 256) {
      return res.status(400).json({ message: 'Solicitud invalida.' });
    }

    const result = await authenticate(identifier, password);

    if (!result.ok) {
      return res.status(result.status).json({ message: result.message });
    }

    return res.json({ token: result.token, user: result.user });
  } catch (error) {
    return next(error);
  }
});

router.get('/me', requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

module.exports = router;
