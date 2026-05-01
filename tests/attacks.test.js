
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

describe('[ATAC 1] SQL Injection pe /api/auth/login', () => {
  test('payload SQL injection bypaseaza autentificarea fara parola', async () => {

    await request(app)
      .post('/api/auth/register')
      .send({ email: 'victima@example.com', password: 'parolaSigura123' });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "' OR '1'='1", password: 'orice' });

    expect(res.status).toBe(401);
    expect(res.body.token).toBeUndefined();

    console.log('[ATAC 1 ESUAT] SQL Injection blocat! Nu s-a primit token.');
  });

  test('[ATAC 1b] apostroful in email expune erori de DB (information disclosure)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "test'broken", password: 'x' });

    expect(res.status).toBe(401);
    console.log('[ATAC 1b blocat] Apostrof in email => status:', res.status, '| body:', JSON.stringify(res.body));
  });
});

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

    expect(resUserInexistent.body.error).toBe('Email sau parola incorecte');
    expect(resParolaGresita.body.error).toBe('Email sau parola incorecte');
    expect(resUserInexistent.body.error).toBe(resParolaGresita.body.error);

    console.log('[ATAC 2 BLOCAT] User enumeration nu mai e posibil!');
  });
});
describe('[ATAC 3] Brute Force - fara rate limiting', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'tinta@example.com', password: 'parolaCorecta' });
  });

  test('poate incerca parole nelimitat fara a fi blocat', async () => {
    let tokenGasit = null;

    for (let i = 0; i < 100; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ email: 'tinta@example.com', password: 'parolaGresita' + i });
    }

    const resFinal = await request(app)
      .post('/api/auth/login')
      .send({ email: 'tinta@example.com', password: 'parolaCorecta' });

    expect(resFinal.status).not.toBe(200);

    console.log('[ATAC 3 BLOCAT] Brute force oprit de Rate Limiting!');
  });
});
describe('[ATAC 4] Token reutilizabil dupa logout (Session Fixation)', () => {
  test('token-ul ramane valid dupa logout', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'session@example.com', password: 'parola123' });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'session@example.com', password: 'parola123' });

    const token = loginRes.body.token;

    await request(app)
      .post('/api/auth/logout')
      .set('authorization', 'Bearer ' + token)
      .send();

    const ticketRes = await request(app)
      .get('/api/tickets')
      .set('authorization', 'Bearer ' + token);

    expect(ticketRes.status).toBe(401);
    console.log('[ATAC 4 BLOCAT] Token-ul este invalid dupa logout!');
  });
});

describe('[ATAC 5] Reset Token reutilizabil (token nu se sterge)', () => {
  test('acelasi token de reset poate fi folosit de mai multe ori', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'reset_vuln@example.com', password: 'parolaOriginala' });

    const forgotRes = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset_vuln@example.com' });

    const resetToken = forgotRes.body.resetToken;

    await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua1' });
    const secondReset = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua2' });

    expect(secondReset.status).toBe(400);
    console.log('[ATAC 5 BLOCAT] Token-ul de reset a fost invalidat dupa prima utilizare!');
  });
});

describe('[ATAC 6] IDOR - acces neautorizat la resursele altui user', () => {
  test('user B poate vedea si modifica ticket-ul creat de user A', async () => {
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

    await request(app).post('/api/auth/register')
      .send({ email: 'userB@example.com', password: 'parolaB123' });
    const loginB = await request(app).post('/api/auth/login')
      .send({ email: 'userB@example.com', password: 'parolaB123' });
    const tokenB = loginB.body.token;

    const getRes = await request(app)
      .get(`/api/tickets/${ticketId}`)
      .set('authorization', 'Bearer ' + tokenB);

    expect(getRes.status).toBe(403);
    console.log('[ATAC 6 BLOCAT] IDOR Read restrictionat!');

    const deleteRes = await request(app)
      .delete(`/api/tickets/${ticketId}`)
      .set('authorization', 'Bearer ' + tokenB);

    expect(deleteRes.status).toBe(403);
    console.log('[ATAC 6 BLOCAT] IDOR Delete restrictionat!');
  });
});


describe('[ATAC 7] Audit Log public - fara autentificare', () => {
  test('oricine poate accesa audit log-ul fara token', async () => {
    const res = await request(app)
      .get('/api/audit');
    expect(res.status).toBe(401);
    console.log('[ATAC 7 BLOCAT] Audit log securizat - cere autentificare!');
  });
});
