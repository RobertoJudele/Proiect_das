// src/routes/tickets.js
// ============================================================
// ATENTIE: VARIANTA v1 - COMPLET NESECURIZATA (intentionat)
// Vulnerabilitati prezente:
//   1. IDOR - oricine poate vedea/modifica orice ticket
//   2. Fara verificare de proprietate (owner_id ignorat)
//   3. XSS posibil - description nu e sanitizata
//   4. Fara validare input
// ============================================================

const express = require('express');
const router = express.Router();
const db = require('../db');
const authMiddleware = require('../middleware/auth');

// -------------------------------------------------------
// GET /api/tickets
// VULNERABILITATE IDOR: Returneaza TOATE ticket-urile tuturor utilizatorilor
// Un ANALYST poate vedea ticket-urile altor ANALYST-i sau ale MANAGER-ilor
// -------------------------------------------------------
router.get('/', authMiddleware, (req, res) => {
  // VULNERABILITATE: Nu filtram dupa owner_id => IDOR
  const tickets = db.prepare('SELECT * FROM tickets').all();
  res.json(tickets);
});

// -------------------------------------------------------
// GET /api/tickets/:id
// VULNERABILITATE IDOR: Oricine poate accesa orice ticket dupa ID
// -------------------------------------------------------
router.get('/:id', authMiddleware, (req, res) => {
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
  }
  // VULNERABILITATE: Nu verificam ca ticket.owner_id === req.user.userId
  res.json(ticket);
});

// -------------------------------------------------------
// POST /api/tickets
// VULNERABILITATE: Description poate contine XSS (HTML/JS netratat)
// -------------------------------------------------------
router.post('/', authMiddleware, (req, res) => {
  const { title, description, severity } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'Titlul este obligatoriu' });
  }

  // VULNERABILITATE: description nu e sanitizata => XSS posibil
  const result = db.prepare(
    'INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)'
  ).run(title, description || '', severity || 'LOW', req.user.userId);

  res.status(201).json({
    message: 'Ticket creat',
    ticketId: result.lastInsertRowid
  });
});

// -------------------------------------------------------
// PUT /api/tickets/:id
// VULNERABILITATE IDOR: Oricine poate modifica orice ticket
// -------------------------------------------------------
router.put('/:id', authMiddleware, (req, res) => {
  const { title, description, severity, status } = req.body;
  const ticketId = req.params.id;

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
  }

  // VULNERABILITATE: Nu verificam owner_id sau rol
  db.prepare(
    "UPDATE tickets SET title = ?, description = ?, severity = ?, status = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(
    title || ticket.title,
    description || ticket.description,
    severity || ticket.severity,
    status || ticket.status,
    ticketId
  );

  res.json({ message: 'Ticket actualizat' });
});

// -------------------------------------------------------
// DELETE /api/tickets/:id
// VULNERABILITATE IDOR: Oricine poate sterge orice ticket
// -------------------------------------------------------
router.delete('/:id', authMiddleware, (req, res) => {
  const ticketId = req.params.id;

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
  }

  // VULNERABILITATE: Orice user autentificat poate sterge orice ticket
  db.prepare('DELETE FROM tickets WHERE id = ?').run(ticketId);
  res.json({ message: 'Ticket sters' });
});

module.exports = router;
