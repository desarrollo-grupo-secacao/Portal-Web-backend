const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Token requerido.' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch (error) {
    return res.status(401).json({ message: 'Token invalido o expirado.' });
  }
}

function requireRole(...roles) {
  const allowed = roles.map((r) => r.toLowerCase());
  return (req, res, next) => {
    const role = String(req.user?.role || '').toLowerCase();
    if (!allowed.includes(role)) {
      return res.status(403).json({ message: 'No autorizado para este recurso.' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireRole };
