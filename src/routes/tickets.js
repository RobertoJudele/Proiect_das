const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const db = require('../db');
const authMiddleware = require('../middleware/auth');
const { logAction } = require('./audit');

router.get('/', authMiddleware, (req, res) => {
  let tickets;
  if (req.user.role === 'MANAGER') {
    tickets = db.prepare('SELECT * FROM tickets').all();
  } else {
    tickets = db.prepare('SELECT * FROM tickets WHERE owner_id = ?').all(req.user.userId);
  }
  res.json(tickets);
});

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

    logAction(req.user.userId, 'CREATE_TICKET', 'TICKET', result.lastInsertRowid, req.ip);

    res.status(201).json({
      message: 'Ticket creat',
      ticketId: result.lastInsertRowid
    });
  });

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

    logAction(req.user.userId, 'UPDATE_TICKET', 'TICKET', ticketId, req.ip);

    res.json({ message: 'Ticket actualizat' });
  });

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
  logAction(req.user.userId, 'DELETE_TICKET', 'TICKET', ticketId, req.ip);
  res.json({ message: 'Ticket sters' });
});

module.exports = router;
