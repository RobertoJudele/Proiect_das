
const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');

let token;
let userId;

beforeEach(async () => {
  db.exec('DELETE FROM users; DELETE FROM tickets; DELETE FROM audit_logs;');
  await request(app).post('/api/auth/reset-limiter').send();
  await request(app)
    .post('/api/auth/register')
    .send({ email: 'ticket_user@example.com', password: 'parola123' });

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'ticket_user@example.com', password: 'parola123' });

  if (loginRes.status !== 200) {
    console.error('LOGIN FAILED:', loginRes.status, loginRes.body);
  }

  token = loginRes.body.token;
  userId = loginRes.body.user.id;
});

afterAll(() => {
  db.close();
});

describe('POST /api/tickets', () => {
  test('creeaza ticket cu succes', async () => {
    const res = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'Bug critic', description: 'Descriere bug', severity: 'HIGH' });

    expect(res.status).toBe(201);
    expect(res.body.ticketId).toBeDefined();
  });

  test('fara titlu returneaza 400', async () => {
    const res = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ description: 'Fara titlu' });

    expect(res.status).toBe(400);
  });

  test('fara token returneaza 401', async () => {
    const res = await request(app)
      .post('/api/tickets')
      .send({ title: 'Ticket' });

    expect(res.status).toBe(401);
  });
});

describe('GET /api/tickets', () => {
  test('returneaza lista de tickets', async () => {
    await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'Ticket 1' });

    const res = await request(app)
      .get('/api/tickets')
      .set('authorization', 'Bearer ' + token);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });
});

describe('GET /api/tickets/:id', () => {
  test('returneaza ticket dupa id', async () => {
    const createRes = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'Ticket specific' });

    const res = await request(app)
      .get(`/api/tickets/${createRes.body.ticketId}`)
      .set('authorization', 'Bearer ' + token);

    expect(res.status).toBe(200);
    expect(res.body.title).toBe('Ticket specific');
  });

  test('id inexistent returneaza 404', async () => {
    const res = await request(app)
      .get('/api/tickets/99999')
      .set('authorization', 'Bearer ' + token);

    expect(res.status).toBe(404);
  });
});

describe('PUT /api/tickets/:id', () => {
  test('actualizeaza ticket cu succes', async () => {
    const createRes = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'Titlu vechi', severity: 'LOW' });

    const res = await request(app)
      .put(`/api/tickets/${createRes.body.ticketId}`)
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'Titlu nou', status: 'IN_PROGRESS' });

    expect(res.status).toBe(200);
  });
});

describe('DELETE /api/tickets/:id', () => {
  test('sterge ticket cu succes', async () => {
    const createRes = await request(app)
      .post('/api/tickets')
      .set('authorization', 'Bearer ' + token)
      .send({ title: 'De sters' });

    const res = await request(app)
      .delete(`/api/tickets/${createRes.body.ticketId}`)
      .set('authorization', 'Bearer ' + token);

    expect(res.status).toBe(200);

    const getRes = await request(app)
      .get(`/api/tickets/${createRes.body.ticketId}`)
      .set('authorization', 'Bearer ' + token);

    expect(getRes.status).toBe(404);
  });
});
