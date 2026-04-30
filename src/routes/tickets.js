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
const { body, validationResult } = require('express-validator');
const db = require('../db');
const authMiddleware = require('../middleware/auth');

// -------------------------------------------------------
// GET /api/tickets
// VULNERABILITATE IDOR: Returneaza TOATE ticket-urile tuturor utilizatorilor
// Un ANALYST poate vedea ticket-urile altor ANALYST-i sau ale MANAGER-ilor
// -------------------------------------------------------
router.get('/', authMiddleware, (req, res) => {
  let tickets;
  if (req.user.role === 'MANAGER') {
    tickets = db.prepare('SELECT * FROM tickets').all();
  } else {
    tickets = db.prepare('SELECT * FROM tickets WHERE owner_id = ?').all(req.user.userId);
  }
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
  
  if (req.user.role !== 'MANAGER' && ticket.owner_id !== req.user.userId) {
    return res.status(403).json({ error: 'Acces interzis' });
  }

  res.json(ticket);
});

// -------------------------------------------------------
// POST /api/tickets
// VULNERABILITATE: Description poate contine XSS (HTML/JS netratat)
// -------------------------------------------------------
router.post('/', 
  authMiddleware, 
  [
    body('title').notEmpty().withMessage('Titlul este obligatoriu').escape(),
    body('description').optional().escape(),
    body('severity').optional().isIn(['LOW', 'MED', 'HIGH']).withMessage('Severitate invalida')
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { title, description, severity } = req.body;

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
router.put('/:id', 
  authMiddleware,
  [
    body('title').optional().escape(),
    body('description').optional().escape()
  ], 
  (req, res) => {
    const { title, description, severity, status } = req.body;
    const ticketId = req.params.id;

    const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
    if (!ticket) {
      return res.status(404).json({ error: 'Ticket negasit' });
    }

    if (req.user.role !== 'MANAGER' && ticket.owner_id !== req.user.userId) {
      return res.status(403).json({ error: 'Acces interzis' });
    }

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

  if (req.user.role !== 'MANAGER' && ticket.owner_id !== req.user.userId) {
    return res.status(403).json({ error: 'Acces interzis' });
  }

  db.prepare('DELETE FROM tickets WHERE id = ?').run(ticketId);
  res.json({ message: 'Ticket sters' });
});

module.exports = router;
