// tests/attacks.test.js
// ============================================================
// Teste care DEMONSTREAZA vulnerabilitatile din v1
// Fiecare test probeaza un atac specific care REUSESTE in v1
// In v2-secure, aceste atacuri vor ESUA (asta dovedim fix-ul)
// ============================================================

const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');

beforeEach(() => {
  db.exec('DELETE FROM users; DELETE FROM reset_tokens; DELETE FROM audit_logs; DELETE FROM tickets;');
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

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();

    console.log('[ATAC 1 REUSIT] SQL Injection a functionat! Token primit:', res.body.token ? 'DA' : 'NU');
    console.log('  User accesat prin injection:', res.body.user?.email);
  });

  test('[ATAC 1b] apostroful in email expune erori de DB (information disclosure)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "test'broken", password: 'x' });

    expect([401, 500]).toContain(res.status);
    console.log('[ATAC 1b] Apostrof in email => status:', res.status, '| body:', JSON.stringify(res.body));
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
      .send({ email: 'nuexista@example.com', password: 'parola' });

    const resParolaGresita = await request(app)
      .post('/api/auth/login')
      .send({ email: 'existent@example.com', password: 'gresita' });

    // DEMONSTRATIE: mesajele sunt DIFERITE => atacatorul stie ce email-uri exista
    expect(resUserInexistent.body.error).toBe('Utilizatorul nu a fost gasit');
    expect(resParolaGresita.body.error).toBe('Parola incorecta');
    expect(resUserInexistent.body.error).not.toBe(resParolaGresita.body.error);

    console.log('[ATAC 2 REUSIT] User enumeration posibil!');
    console.log('  Email inexistent:', resUserInexistent.body.error);
    console.log('  Parola gresita:  ', resParolaGresita.body.error);
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
    const paroleDeTestat = ['pass1', 'pass2', 'pass3', 'pass4', 'pass5', 'parolaCorecta'];
    let tokenGasit = null;

    for (const parola of paroleDeTestat) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'tinta@example.com', password: parola });

      if (res.status === 200) {
        tokenGasit = res.body.token;
        console.log(`[ATAC 3 REUSIT] Parola gasita prin brute force: "${parola}"`);
        break;
      }
    }

    // In v1: brute force reuseste, niciun cont blocat
    expect(tokenGasit).not.toBeNull();

    // Verifica ca userul NU e blocat dupa multiple incercari
    const user = db.prepare('SELECT locked FROM users WHERE email = ?').get('tinta@example.com');
    expect(user.locked).toBe(0);
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

    // Logout
    await request(app)
      .post('/api/auth/logout')
      .send();

    // Token-ul ar trebui sa fie invalid dupa logout
    // In v1: token-ul INCA FUNCTIONEAZA (vulnerabil)
    const ticketRes = await request(app)
      .get('/api/tickets')
      .set('authorization', token);

    expect(ticketRes.status).toBe(200); // In v1: acces permis chiar dupa logout!
    console.log('[ATAC 4 REUSIT] Token-ul ramane valid dupa logout!');
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

    // A doua resetare cu ACELASI token (ar trebui sa esueze, dar in v1 reuseste)
    const secondReset = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua2' });

    expect(secondReset.status).toBe(200); // In v1: TOKEN REUTILIZAT CU SUCCES!
    console.log('[ATAC 5 REUSIT] Token-ul de reset a fost reutilizat!');
  });
});

// ─────────────────────────────────────────────
// ATAC 6: IDOR - Acces la ticket-urile altui user
// ─────────────────────────────────────────────
describe('[ATAC 6] IDOR - acces neautorizat la resursele altui user', () => {
  test('user B poate vedea si modifica ticket-ul creat de user A', async () => {
    // User A se inregistreaza si creeaza un ticket
    await request(app).post('/api/auth/register')
      .send({ email: 'userA@example.com', password: 'parolaA' });
    const loginA = await request(app).post('/api/auth/login')
      .send({ email: 'userA@example.com', password: 'parolaA' });
    const tokenA = loginA.body.token;

    const ticketRes = await request(app)
      .post('/api/tickets')
      .set('authorization', tokenA)
      .send({ title: 'Ticket secret al lui A', description: 'Date confidentiale', severity: 'HIGH' });
    const ticketId = ticketRes.body.ticketId;

    // User B se inregistreaza si acceseaza ticket-ul lui A
    await request(app).post('/api/auth/register')
      .send({ email: 'userB@example.com', password: 'parolaB' });
    const loginB = await request(app).post('/api/auth/login')
      .send({ email: 'userB@example.com', password: 'parolaB' });
    const tokenB = loginB.body.token;

    // IDOR: User B poate accesa ticket-ul lui A
    const getRes = await request(app)
      .get(`/api/tickets/${ticketId}`)
      .set('authorization', tokenB);

    expect(getRes.status).toBe(200);
    expect(getRes.body.title).toBe('Ticket secret al lui A');
    console.log('[ATAC 6 REUSIT] IDOR: User B a accesat ticket-ul lui User A!');

    // IDOR: User B poate sterge ticket-ul lui A
    const deleteRes = await request(app)
      .delete(`/api/tickets/${ticketId}`)
      .set('authorization', tokenB);

    expect(deleteRes.status).toBe(200);
    console.log('[ATAC 6 REUSIT] IDOR: User B a sters ticket-ul lui User A!');
  });
});

// ─────────────────────────────────────────────
// ATAC 7: Audit Log accesibil fara autentificare
// ─────────────────────────────────────────────
describe('[ATAC 7] Audit Log public - fara autentificare', () => {
  test('oricine poate accesa audit log-ul fara token', async () => {
    const res = await request(app)
      .get('/api/audit');
    // Nu trimitem niciun token, dar primim 200
    expect(res.status).toBe(200);
    console.log('[ATAC 7 REUSIT] Audit log accesibil public, fara autentificare!');
  });
});
