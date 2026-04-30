// tests/attacks.test.js
// ============================================================
// Teste care DEMONSTREAZA vulnerabilitatile din v1
// Fiecare test probeaza un atac specific care REUSESTE in v1
// In v2-secure, aceste atacuri vor ESUA (asta dovedim fix-ul)
// ============================================================

const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');

beforeEach(async () => {
  db.exec('DELETE FROM users; DELETE FROM reset_tokens; DELETE FROM audit_logs; DELETE FROM tickets;');
  await request(app).post('/api/auth/reset-limiter').send();
});

afterAll(() => {
  db.close();
});

// ─────────────────────────────────────────────
// ATAC 1: SQL Injection pe Login
// ─────────────────────────────────────────────
describe('[ATAC 1] SQL Injection pe /api/auth/login', () => {
  test('payload SQL injection bypaseaza autentificarea fara parola', async () => {
    // Cream un user victima in baza de date
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'victima@example.com', password: 'parolaSigura123' });

    // ATAC: email = "' OR '1'='1" (clasic SQL injection payload)
    // Query-ul vulnerabil devine:
    //   SELECT * FROM users WHERE email = '' OR '1'='1'
    // Aceasta conditie e intotdeauna TRUE => returneaza primul user
    // Serverul nostru detecteaza apostroful/OR si simuleaza comportamentul DB vulnerabil
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "' OR '1'='1", password: 'orice' });

    // In v2 (secure): atacul ESUAZA, primim 401 (Unauthorized)
    expect(res.status).toBe(401);
    expect(res.body.token).toBeUndefined();

    console.log('[ATAC 1 ESUAT] SQL Injection blocat! Nu s-a primit token.');
  });

  test('[ATAC 1b] apostroful in email expune erori de DB (information disclosure)', async () => {
    // Un simplu apostrof poate rupe query-ul si returna erori interne
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "test'broken", password: 'x' });

    // In v2: primim eroare 401 (eroare de auth generica, ca si cum userul nu exista) - SQL injection nu sparge aplicatia
    expect(res.status).toBe(401);
    console.log('[ATAC 1b blocat] Apostrof in email => status:', res.status, '| body:', JSON.stringify(res.body));
  });
});

// ─────────────────────────────────────────────
// ATAC 2: User Enumeration
// ─────────────────────────────────────────────
describe('[ATAC 2] User Enumeration prin mesaje de eroare diferite', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'existent@example.com', password: 'parola123' });
  });

  test('mesaj diferit pentru user inexistent vs parola gresita', async () => {
    const resUserInexistent = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nuexista@example.com', password: 'parolaFalsa' });

    const resParolaGresita = await request(app)
      .post('/api/auth/login')
      .send({ email: 'existent@example.com', password: 'gresita' });

    // In v2: ambele returneaza exact acelasi mesaj
    expect(resUserInexistent.body.error).toBe('Email sau parola incorecte');
    expect(resParolaGresita.body.error).toBe('Email sau parola incorecte');
    expect(resUserInexistent.body.error).toBe(resParolaGresita.body.error);

    console.log('[ATAC 2 BLOCAT] User enumeration nu mai e posibil!');
  });
});

// ─────────────────────────────────────────────
// ATAC 3: Brute Force (fara rate limiting)
// ─────────────────────────────────────────────
describe('[ATAC 3] Brute Force - fara rate limiting', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'tinta@example.com', password: 'parolaCorecta' });
  });

  test('poate incerca parole nelimitat fara a fi blocat', async () => {
    let tokenGasit = null;

    // Rulam 100 de incercari gresite pentru a atinge limita (in test mode limit = 100)
    for (let i = 0; i < 100; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ email: 'tinta@example.com', password: 'parolaGresita' + i });
    }

    // Incercarea 101 ar trebui sa dea eroare 429
    const resFinal = await request(app)
      .post('/api/auth/login')
      .send({ email: 'tinta@example.com', password: 'parolaCorecta' });
    
    expect(resFinal.status).not.toBe(200); 

    console.log('[ATAC 3 BLOCAT] Brute force oprit de Rate Limiting!');
  });
});

// ─────────────────────────────────────────────
// ATAC 4: Token JWT reutilizabil dupa Logout
// ─────────────────────────────────────────────
describe('[ATAC 4] Token reutilizabil dupa logout (Session Fixation)', () => {
  test('token-ul ramane valid dupa logout', async () => {
    // Inregistrare + Login
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'session@example.com', password: 'parola123' });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'session@example.com', password: 'parola123' });

    const token = loginRes.body.token;

    // Logout (acum cu token, altfel nu e procesat)
    await request(app)
      .post('/api/auth/logout')
      .set('authorization', 'Bearer ' + token)
      .send();

    // In v2: Token-ul e blacklistat
    const ticketRes = await request(app)
      .get('/api/tickets')
      .set('authorization', 'Bearer ' + token);

    expect(ticketRes.status).toBe(401);
    console.log('[ATAC 4 BLOCAT] Token-ul este invalid dupa logout!');
  });
});

// ─────────────────────────────────────────────
// ATAC 5: Reset Token Reutilizabil
// ─────────────────────────────────────────────
describe('[ATAC 5] Reset Token reutilizabil (token nu se sterge)', () => {
  test('acelasi token de reset poate fi folosit de mai multe ori', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'reset_vuln@example.com', password: 'parolaOriginala' });

    const forgotRes = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset_vuln@example.com' });

    const resetToken = forgotRes.body.resetToken;

    // Prima resetare
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua1' });

    // In v2: Token-ul de reset e sters dupa folosire, a doua incercare e 400
    const secondReset = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua2' });

    expect(secondReset.status).toBe(400); 
    console.log('[ATAC 5 BLOCAT] Token-ul de reset a fost invalidat dupa prima utilizare!');
  });
});

// ─────────────────────────────────────────────
// ATAC 6: IDOR - Acces la ticket-urile altui user
// ─────────────────────────────────────────────
describe('[ATAC 6] IDOR - acces neautorizat la resursele altui user', () => {
  test('user B poate vedea si modifica ticket-ul creat de user A', async () => {
    // User A se inregistreaza si creeaza un ticket
    await request(app).post('/api/auth/register')
      .send({ email: 'userA@example.com', password: 'parolaA123' });
    const loginA = await request(app).post('/api/auth/login')
      .send({ email: 'userA@example.com', password: 'parolaA123' });
    const tokenA = loginA.body.token;

    const ticketRes = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + tokenA)
      .send({ title: 'Ticket secret al lui A', description: 'Date confidentiale', severity: 'HIGH' });
    const ticketId = ticketRes.body.ticketId;

    // User B se inregistreaza si acceseaza ticket-ul lui A
    await request(app).post('/api/auth/register')
      .send({ email: 'userB@example.com', password: 'parolaB123' });
    const loginB = await request(app).post('/api/auth/login')
      .send({ email: 'userB@example.com', password: 'parolaB123' });
    const tokenB = loginB.body.token;

    // IDOR blocat: User B incearca sa acceseze ticket-ul lui A => 403
    const getRes = await request(app)
      .get(`/api/tickets/${ticketId}`)
      .set('authorization', 'Bearer ' + tokenB);

    expect(getRes.status).toBe(403);
    console.log('[ATAC 6 BLOCAT] IDOR Read restrictionat!');

    // IDOR blocat: User B incearca sa stearga ticket-ul lui A => 403
    const deleteRes = await request(app)
      .delete(`/api/tickets/${ticketId}`)
      .set('authorization', 'Bearer ' + tokenB);

    expect(deleteRes.status).toBe(403);
    console.log('[ATAC 6 BLOCAT] IDOR Delete restrictionat!');
  });
});

// ─────────────────────────────────────────────
// ATAC 7: Audit Log accesibil fara autentificare
// ─────────────────────────────────────────────
describe('[ATAC 7] Audit Log public - fara autentificare', () => {
  test('oricine poate accesa audit log-ul fara token', async () => {
    const res = await request(app)
      .get('/api/audit');
    // Nu trimitem niciun token, dar trebuie sa primim 401 in v2
    expect(res.status).toBe(401);
    console.log('[ATAC 7 BLOCAT] Audit log securizat - cere autentificare!');
  });
});
