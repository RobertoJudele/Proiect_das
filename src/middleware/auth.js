
const jwt = require('jsonwebtoken');

const db = require('../db');

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token lipsa sau format incorect (necesita Bearer)' });
  }

  const token = authHeader.split(' ')[1];


  const isBlacklisted = db.prepare('SELECT id FROM token_blacklist WHERE token = ?').get(token);
  if (isBlacklisted) {
    return res.status(401).json({ error: 'Token invalidat (te rugam sa te autentifici din nou)' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid sau expirat' });
  }
}

module.exports = authMiddleware;
