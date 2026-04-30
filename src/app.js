// src/app.js
// Aplicatia Express - v1 VULNERABILA
require('dotenv').config();
const express = require('express');

const authRoutes   = require('./routes/auth');
const ticketRoutes = require('./routes/tickets');
const auditRoutes  = require('./routes/audit');

const app = express();

app.use(express.json());

// Servim frontend-ul static din folderul public/ (cale absoluta)
const path = require('path');
const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
app.use(express.static(PUBLIC_DIR));

// Servim index.html pentru ruta radacina (fallback explicit)
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});


// Rute
app.use('/api/auth',    authRoutes);
app.use('/api/tickets', ticketRoutes);
app.use('/api/audit',   auditRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: 'v1-vulnerable' });
});

// Handler pentru rute inexistente
app.use((req, res) => {
  res.status(404).json({ error: 'Ruta negasita' });
});

module.exports = app;
