
const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');


beforeEach(async () => {
  db.exec('DELETE FROM users; DELETE FROM reset_tokens; DELETE FROM audit_logs;');
  await request(app).post('/api/auth/reset-limiter').send();
});

afterAll(() => {
  db.close();
});


describe('POST /api/auth/register', () => {
  test('inregistrare cu succes', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'test@example.com', password: 'parola123' });

    expect(res.status).toBe(201);
    expect(res.body.message).toMatch(/succes/i);
    expect(res.body.userId).toBeDefined();
  });

  test('email duplicat returneaza 409', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'duplic@example.com', password: 'parola123' });

    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'duplic@example.com', password: 'altaparola' });

    expect(res.status).toBe(409);
  });

  test('fara email returneaza 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ password: 'parola123' });

    expect(res.status).toBe(400);
  });

  test('fara parola returneaza 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'test@example.com' });

    expect(res.status).toBe(400);
  });

  test('[SECURE] parola NU este stocata in clar in baza de date', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'vuln@example.com', password: 'parolaSecreta' });

    const user = db.prepare('SELECT password FROM users WHERE email = ?').get('vuln@example.com');
    expect(user.password).not.toBe('parolaSecreta');
    expect(user.password.startsWith('$2b$')).toBe(true);
  });
});


describe('POST /api/auth/login', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'user@example.com', password: 'parola123' });
  });

  test('login cu succes returneaza token', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@example.com', password: 'parola123' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe('user@example.com');
  });

  test('parola gresita returneaza 401', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@example.com', password: 'gresita' });

    expect(res.status).toBe(401);
  });

  test('email inexistent returneaza 401', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'inexistent@example.com', password: 'orice' });

    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth/logout', () => {
  test('logout returneaza succes', async () => {
    const res = await request(app)
      .post('/api/auth/logout')
      .send();

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/deconectat/i);
  });
});
describe('POST /api/auth/forgot-password', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'reset@example.com', password: 'parola123' });
  });

  test('genereaza token de resetare pentru email valid', async () => {
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.resetToken).toBeDefined();
  });

  test('email inexistent returneaza 200 generic pentru a preveni enumeration', async () => {
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'nu_exista@example.com' });

    expect(res.status).toBe(200); /
    expect(res.body.message).toMatch(/Daca email-ul exista/i);
  });
});

describe('POST /api/auth/reset-password', () => {
  let resetToken;

  beforeEach(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'reset2@example.com', password: 'parolaVeche' });

    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset2@example.com' });

    resetToken = res.body.resetToken;
  });

  test('reset parola cu token valid', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, newPassword: 'parolaNoua' });

    expect(res.status).toBe(200);

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'reset2@example.com', password: 'parolaNoua' });

    expect(loginRes.status).toBe(200);
  });

  test('token invalid returneaza 400', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: 'token_fals', newPassword: 'parolaNoua' });

    expect(res.status).toBe(400);
  });
});
