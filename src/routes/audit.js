// src/routes/audit.js
// ============================================================
// ATENTIE: VARIANTA v1 - COMPLET NESECURIZATA (intentionat)
// Vulnerabilitati prezente:
//   1. Audit log-urile sunt accesibile fara autentificare
//   2. Orice user (nu doar MANAGER) poate vedea tot audit log-ul
//   3. Nu exista audit logging real (actiunile nu sunt loggate automat)
// ============================================================

const express = require('express');
const router = express.Router();
const db = require('../db');

// -------------------------------------------------------
// GET /api/audit
// VULNERABILITATE: Endpoint public - nu necesita autentificare
// Oricine poate vedea toate actiunile din sistem
// -------------------------------------------------------
const authMiddleware = require('../middleware/auth');

router.get('/', authMiddleware, (req, res) => {
  if (req.user.role !== 'MANAGER') {
    return res.status(403).json({ error: 'Doar managerii pot accesa logurile de audit' });
  }
  
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC').all();
  res.json(logs);
});

// Helper exportat pentru a loga actiuni (nefolosit intentionat in v1)
function logAction(userId, action, resource, resourceId, ipAddress) {
  // In v1 aceasta functie exista dar nu e apelata niciodata
  db.prepare(
    'INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, action, resource, resourceId, ipAddress);
}

module.exports = router;
module.exports.logAction = logAction;
