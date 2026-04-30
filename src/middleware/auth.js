
const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Token lipsa' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

module.exports = authMiddleware;
