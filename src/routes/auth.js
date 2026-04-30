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
const db = require('../db');

// -------------------------------------------------------
// POST /api/auth/register
// VULNERABILITATE 1: Parola stocata in CLAR in baza de date
// VULNERABILITATE: Fara validare input (email format, lungime parola)
// -------------------------------------------------------
router.post('/register', (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  // Verifica daca userul exista deja
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existingUser) {
    return res.status(409).json({ error: 'Email-ul este deja inregistrat' });
  }

  // VULNERABILITATE 1: Parola salvata direct, fara bcrypt sau alt hash
  const userRole = role === 'MANAGER' ? 'MANAGER' : 'ANALYST';
  const result = db.prepare(
    'INSERT INTO users (email, password, role) VALUES (?, ?, ?)'
  ).run(email, password, userRole);

  res.status(201).json({
    message: 'Cont creat cu succes',
    userId: result.lastInsertRowid
  });
});

// -------------------------------------------------------
// POST /api/auth/login
// VULNERABILITATE 2: User enumeration prin mesaje diferite
// VULNERABILITATE 3: Fara rate limiting - brute-force nelimitat
// VULNERABILITATE 4: SQL Injection - query construit prin concatenare
// VULNERABILITATE 5: Token JWT fara expiry (nu expira niciodata)
// -------------------------------------------------------
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
  }

  // VULNERABILITATE 4: SQL Injection - nu folosim parametri, ci concatenam string-uri
  // Exemplu de atac: email = "' OR '1'='1" sau "' OR 1=1 --"
  // Query-ul vulnerabil devine: SELECT * FROM users WHERE email = '' OR '1'='1'
  // => conditia e intotdeauna TRUE => returneaza primul user din tabel
  let user;
  let sqlInjected = false;

  // Detectam daca email-ul contine payload SQL (apostrof, OR, --)
  // NOTA: aceasta detectie NU ar trebui sa existe - fix-ul corect e sa folosim
  // parametri (?), nu sa filtram input-ul. Aceasta e vulnerabilitatea.
  const hasSqlPayload = email.toUpperCase().includes('OR') ||
    email.includes('--') ||
    email.includes("'");

  if (hasSqlPayload) {
    // Simulam comportamentul unui DB real vulnerabil:
    // SELECT * FROM users WHERE email = '' OR '1'='1'
    // => returneaza primul rand (oricare user existent)
    user = db.prepare('SELECT * FROM users LIMIT 1').get();
    sqlInjected = true;
  } else {
    try {
      // Query vulnerabil: email-ul e inserat direct in string (fara parametri)
      user = db.prepare(`SELECT * FROM users WHERE email = '${email}'`).get();
    } catch (err) {
      return res.status(500).json({ error: 'Eroare baza de date', details: err.message });
    }
  }

  // VULNERABILITATE 2: Mesaje diferite => user enumeration
  if (!user) {
    return res.status(401).json({ error: 'Utilizatorul nu a fost gasit' }); // <-- dezvaluie ca user-ul nu exista
  }

  // VULNERABILITATE 1 & 4: Daca e SQL injection, sarim verificarea parolei
  if (!sqlInjected && user.password !== password) {
    return res.status(401).json({ error: 'Parola incorecta' }); // <-- dezvaluie ca user-ul exista dar parola e gresita
  }

  if (user.locked) {
    return res.status(403).json({ error: 'Contul este blocat' });
  }

  // VULNERABILITATE 5: JWT fara expiry (expiresIn lipseste)
  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'secret123'
    // lipseste: expiresIn
  );

  res.json({
    message: 'Autentificare reusita',
    token,
    user: { id: user.id, email: user.email, role: user.role }
  });
});

// -------------------------------------------------------
// POST /api/auth/logout
// VULNERABILITATE 6: Logout-ul nu face nimic real
// Token-ul ramane valid la infinit dupa logout
// -------------------------------------------------------
router.post('/logout', (req, res) => {
  // VULNERABILITATE 6: Nu existe niciun blacklist, token-ul nu se invalideaza
  // Clientul primeste un raspuns de succes dar token-ul continua sa functioneze
  res.json({ message: 'Deconectat cu succes' });
});

// -------------------------------------------------------
// POST /api/auth/forgot-password
// VULNERABILITATE 7: Token de resetare = Math.random() (slab si predictibil)
// -------------------------------------------------------
router.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email-ul este obligatoriu' });
  }

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) {
    // Dezvaluie ca email-ul nu exista (user enumeration)
    return res.status(404).json({ error: 'Email-ul nu este inregistrat' });
  }

  // VULNERABILITATE 7: Token slab - Math.random() este predictibil
  // Nu are expiry, nu are unicitate garantata
  const resetToken = Math.random().toString(36).substring(2);

  db.prepare('INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)').run(user.id, resetToken);

  // In productie ar trimite email; aici returnam token-ul direct (si mai rau)
  res.json({
    message: 'Token de resetare generat',
    resetToken // VULNERABILITATE: token-ul e trimis in raspuns direct (in loc de email)
  });
});

// -------------------------------------------------------
// POST /api/auth/reset-password
// VULNERABILITATE 8: Token-ul de reset NU se sterge dupa folosire (reutilizabil)
// VULNERABILITATE: Fara expiry pe token
// -------------------------------------------------------
router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token si parola noua sunt obligatorii' });
  }

  const resetRecord = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(token);
  if (!resetRecord) {
    return res.status(400).json({ error: 'Token invalid' });
  }

  // VULNERABILITATE: Fara verificare expiry - token-ul e valid pentru totdeauna

  // VULNERABILITATE 1: Noua parola salvata tot in clar
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(newPassword, resetRecord.user_id);

  // VULNERABILITATE 8: Token-ul NU se sterge => poate fi refolosit
  // Linia corecta ar fi: db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(token);

  res.json({ message: 'Parola a fost resetata cu succes' });
});

module.exports = router;
