// src/middleware/auth.js
// VULNERABIL: Verificare token slaba, fara validare corecta
const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];

  // VULNERABILITATE: Accepta token-ul direct din header fara "Bearer " prefix check
  if (!token) {
    return res.status(401).json({ error: 'Token lipsa' });
  }

  try {
    // VULNERABILITATE: Secretul e slab si hardcodat
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

module.exports = authMiddleware;
