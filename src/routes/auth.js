// src/routes/auth.js
// ============================================================
// ATENTIE: VARIANTA v1 - COMPLET NESECURIZATA (intentionat)
// Aceasta versiune contine urmatoarele vulnerabilitati:
//   1. Parole stocate in clar (plain text) - fara hash
//   2. User enumeration - mesaje de eroare diferite
//   3. Fara rate limiting - brute-force posibil
//   4. SQL Injection pe login (query concatenat)
//   5. Token JWT fara expiry
//   6. Logout nu invalideaza token-ul
//   7. Reset token = Math.random() (slab si predictibil)
//   8. Reset token reutilizabil (nu se sterge dupa folosire)
// ============================================================

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db');

// Rate limiting pentru login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute
  max: process.env.NODE_ENV === 'test' ? 100 : 5, // max 5 incercari pe IP in prod, 100 in teste
  message: { error: 'Prea multe incercari de autentificare, te rugam sa incerci mai tarziu.' }
});

if (process.env.NODE_ENV === 'test') {
  router.post('/reset-limiter', (req, res) => {
    loginLimiter.resetKey(req.ip);
    res.json({ message: 'Limiter resetat' });
  });
}

// -------------------------------------------------------
// POST /api/auth/register
// VULNERABILITATE 1: Parola stocata in CLAR in baza de date
// VULNERABILITATE: Fara validare input (email format, lungime parola)
// -------------------------------------------------------
router.post('/register', 
  [
    body('email').isEmail().withMessage('Email invalid'),
    body('password').isLength({ min: 8 }).withMessage('Parola trebuie sa aiba cel putin 8 caractere')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email, password, role } = req.body;

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      // Returnam un mesaj generic chiar si aici pentru a preveni in masura posibila user enum
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

// -------------------------------------------------------
// POST /api/auth/login
// VULNERABILITATE 2: User enumeration prin mesaje diferite
// VULNERABILITATE 3: Fara rate limiting - brute-force nelimitat
// VULNERABILITATE 4: SQL Injection - query construit prin concatenare
// VULNERABILITATE 5: Token JWT fara expiry (nu expira niciodata)
// -------------------------------------------------------
router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // Mesaj generic
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

    res.json({
      message: 'Autentificare reusita',
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Eroare la autentificare' });
  }
});

// -------------------------------------------------------
// POST /api/auth/logout
// VULNERABILITATE 6: Logout-ul nu face nimic real
// Token-ul ramane valid la infinit dupa logout
// -------------------------------------------------------
router.post('/logout', (req, res) => {
  const token = req.headers['authorization'];
  if (token) {
    const actualToken = token.startsWith('Bearer ') ? token.split(' ')[1] : token;
    db.prepare('INSERT INTO token_blacklist (token) VALUES (?)').run(actualToken);
  }
  res.json({ message: 'Deconectat cu succes' });
});

// -------------------------------------------------------
// POST /api/auth/forgot-password
// VULNERABILITATE 7: Token de resetare = Math.random() (slab si predictibil)
// -------------------------------------------------------
router.post('/forgot-password', 
  body('email').isEmail().withMessage('Email invalid'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { email } = req.body;
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    
    // Mesaj generic pentru prevenirea enumerarii userilor
    if (!user) {
      return res.json({ message: 'Daca email-ul exista, un link de resetare a fost trimis.' });
    }

    const resetToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, resetToken, expiresAt);

    res.json({
      message: 'Daca email-ul exista, un link de resetare a fost trimis.',
      resetToken // In mod normal acest token nu e returnat, ci trimis pe email
    });
});

// -------------------------------------------------------
// POST /api/auth/reset-password
// VULNERABILITATE 8: Token-ul de reset NU se sterge dupa folosire (reutilizabil)
// VULNERABILITATE: Fara expiry pe token
// -------------------------------------------------------
router.post('/reset-password', 
  [
    body('token').notEmpty().withMessage('Token-ul este obligatoriu'),
    body('newPassword').isLength({ min: 8 }).withMessage('Parola trebuie sa aiba cel putin 8 caractere')
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
      db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(token); // Token single use

      res.json({ message: 'Parola a fost resetata cu succes' });
    } catch (err) {
      res.status(500).json({ error: 'Eroare la resetarea parolei' });
    }
});

module.exports = router;
