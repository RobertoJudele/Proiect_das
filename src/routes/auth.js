
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { logAction } = require('./audit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'test' ? 100 : 5,
  message: { error: 'Prea multe incercari de autentificare, te rugam sa incerci mai tarziu.' }
});

if (process.env.NODE_ENV === 'test') {
  router.post('/reset-limiter', (req, res) => {
    loginLimiter.resetKey(req.ip);
    res.json({ message: 'Limiter resetat' });
  });
}

router.post('/register',
  [
    body('email').isEmail().withMessage('Email invalid'),
    body('password').isStrongPassword({ minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }).withMessage('Parola trebuie sa contina cel putin 8 caractere, o litera mica, o litera mare, un numar si un simbol')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email, password, role } = req.body;

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(409).json({ error: 'Email-ul este deja inregistrat' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      const userRole = role === 'MANAGER' ? 'MANAGER' : 'ANALYST';

      const result = db.prepare(
        'INSERT INTO users (email, password, role) VALUES (?, ?, ?)'
      ).run(email, hashedPassword, userRole);

      res.status(201).json({
        message: 'Cont creat cu succes',
        userId: result.lastInsertRowid
      });
    } catch (err) {
      res.status(500).json({ error: 'Eroare la crearea contului' });
    }
  });

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
      return res.status(401).json({ error: 'Email sau parola incorecte' });
    }

    if (user.locked) {
      return res.status(403).json({ error: 'Contul este blocat' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Email sau parola incorecte' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '1h' }
    );

    logAction(user.id, 'LOGIN', 'USER', user.id, req.ip);

    res.json({
      message: 'Autentificare reusita',
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Eroare la autentificare' });
  }
});

router.post('/logout', (req, res) => {
  const token = req.headers['authorization'];
  if (token) {
    const actualToken = token.startsWith('Bearer ') ? token.split(' ')[1] : token;
    db.prepare('INSERT INTO token_blacklist (token) VALUES (?)').run(actualToken);
    
    try {
      const decoded = jwt.decode(actualToken);
      if (decoded && decoded.userId) {
        logAction(decoded.userId, 'LOGOUT', 'USER', decoded.userId, req.ip);
      }
    } catch (e) {}
  }
  res.json({ message: 'Deconectat cu succes' });
});

router.post('/forgot-password',
  body('email').isEmail().withMessage('Email invalid'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email } = req.body;
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);

    if (!user) {
      return res.json({ message: 'Daca email-ul exista, un link de resetare a fost trimis.' });
    }

    const resetToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, resetToken, expiresAt);

    res.json({
      message: 'Daca email-ul exista, un link de resetare a fost trimis.',
      resetToken
    });
  });

router.post('/reset-password',
  [
    body('token').notEmpty().withMessage('Token-ul este obligatoriu'),
    body('newPassword').isStrongPassword({ minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }).withMessage('Parola trebuie sa contina cel putin 8 caractere, o litera mica, o litera mare, un numar si un simbol')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { token, newPassword } = req.body;

    const resetRecord = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(token);
    if (!resetRecord) {
      return res.status(400).json({ error: 'Token invalid sau expirat' });
    }

    if (new Date(resetRecord.expires_at) < new Date()) {
      db.prepare('DELETE FROM reset_tokens WHERE id = ?').run(resetRecord.id);
      return res.status(400).json({ error: 'Token expirat' });
    }

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 12);
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, resetRecord.user_id);
      db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(token);
      res.json({ message: 'Parola a fost resetata cu succes' });
    } catch (err) {
      res.status(500).json({ error: 'Eroare la resetarea parolei' });
    }
  });

module.exports = router;
