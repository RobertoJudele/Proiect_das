
const express = require('express');
const router = express.Router();
const db = require('../db');

const authMiddleware = require('../middleware/auth');

router.get('/', authMiddleware, (req, res) => {
  if (req.user.role !== 'MANAGER') {
    return res.status(403).json({ error: 'Doar managerii pot accesa logurile de audit' });
  }

  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC').all();
  res.json(logs);
});

function logAction(userId, action, resource, resourceId, ipAddress) {
  db.prepare(
    'INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, action, resource, resourceId, ipAddress);
}

module.exports = router;
module.exports.logAction = logAction;
