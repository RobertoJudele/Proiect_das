

const express = require('express');
const router = express.Router();
const db = require('../db');
const authMiddleware = require('../middleware/auth');

router.get('/', authMiddleware, (req, res) => {
  const tickets = db.prepare('SELECT * FROM tickets').all();
  res.json(tickets);
});

router.get('/:id', authMiddleware, (req, res) => {
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
  }
  res.json(ticket);
});

router.post('/', authMiddleware, (req, res) => {
  const { title, description, severity } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'Titlul este obligatoriu' });
  }

  const result = db.prepare(
    'INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)'
  ).run(title, description || '', severity || 'LOW', req.user.userId);

  res.status(201).json({
    message: 'Ticket creat',
    ticketId: result.lastInsertRowid
  });
});

router.put('/:id', authMiddleware, (req, res) => {
  const { title, description, severity, status } = req.body;
  const ticketId = req.params.id;

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
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

router.delete('/:id', authMiddleware, (req, res) => {
  const ticketId = req.params.id;

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket negasit' });
  }

  db.prepare('DELETE FROM tickets WHERE id = ?').run(ticketId);
  res.json({ message: 'Ticket sters' });
});

module.exports = router;
