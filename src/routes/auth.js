
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../db');


router.post('/register', (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }


  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existingUser) {
    return res.status(409).json({ error: 'Email-ul este deja inregistrat' });
  }

  const userRole = role === 'MANAGER' ? 'MANAGER' : 'ANALYST';
  const result = db.prepare(
    'INSERT INTO users (email, password, role) VALUES (?, ?, ?)'
  ).run(email, password, userRole);

  res.status(201).json({
    message: 'Cont creat cu succes',
    userId: result.lastInsertRowid
  });
});


router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  let user;
  let sqlInjected = false;

  const hasSqlPayload = email.toUpperCase().includes('OR') ||
    email.includes('--') ||
    email.includes("'");

  if (hasSqlPayload) {
    user = db.prepare('SELECT * FROM users LIMIT 1').get();
    sqlInjected = true;
  } else {
    try {
      user = db.prepare(`SELECT * FROM users WHERE email = '${email}'`).get();
    } catch (err) {
      return res.status(500).json({ error: 'Eroare baza de date', details: err.message });
    }
  }

  if (!user) {
    return res.status(401).json({ error: 'Utilizatorul nu a fost gasit' });
  }

  if (!sqlInjected && user.password !== password) {
    return res.status(401).json({ error: 'Parola incorecta' });
  }

  if (user.locked) {
    return res.status(403).json({ error: 'Contul este blocat' });
  }

  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'secret123'
  );

  res.json({
    message: 'Autentificare reusita',
    token,
    user: { id: user.id, email: user.email, role: user.role }
  });
});
// -------------------------------------------------------
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  let user;
  let sqlInjected = false;
  const hasSqlPayload = email.toUpperCase().includes('OR') ||
    email.includes('--') ||
    email.includes("'");

  if (hasSqlPayload) {
    user = db.prepare('SELECT * FROM users LIMIT 1').get();
    sqlInjected = true;
  } else {
    try {
      user = db.prepare(`SELECT * FROM users WHERE email = '${email}'`).get();
    } catch (err) {
      return res.status(500).json({ error: 'Eroare baza de date', details: err.message });
    }
  }

  if (!user) {
    return res.status(401).json({ error: 'Utilizatorul nu a fost gasit' });
  }

  if (!sqlInjected && user.password !== password) {
    return res.status(401).json({ error: 'Parola incorecta' });
  }

  if (user.locked) {
    return res.status(403).json({ error: 'Contul este blocat' });
  }

  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'secret123'
  );

  res.json({
    message: 'Autentificare reusita',
    token,
    user: { id: user.id, email: user.email, role: user.role }
  });
});

router.post('/logout', (req, res) => {
  res.json({ message: 'Deconectat cu succes' });
});

router.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email-ul este obligatoriu' });
  }

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(404).json({ error: 'Email-ul nu este inregistrat' });
  }
  const resetToken = Math.random().toString(36).substring(2);

  db.prepare('INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)').run(user.id, resetToken);

  res.json({
    message: 'Token de resetare generat',
    resetToken
  });
});

router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token si parola noua sunt obligatorii' });
  }

  const resetRecord = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(token);
  if (!resetRecord) {
    return res.status(400).json({ error: 'Token invalid' });
  }

  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(newPassword, resetRecord.user_id);

  res.json({ message: 'Parola a fost resetata cu succes' });
});

module.exports = router;
