# Proiect #2 – Break the Login

## v1-vulnerable — Varianta NESECURIZATA 

## Stack tehnic
- **Runtime**: Node.js
- **Framework**: Express.js
- **Baza de date**: SQLite (via `better-sqlite3`)
- **Autentificare**: JWT (jsonwebtoken)
- **Teste**: Jest + Supertest

## Vulnerabilitati demonstrate

| # | Vulnerabilitate | Endpoint | Impact |
|---|---|---|---|
| 1 | Parole stocate in clar (plain text) | `/register`, `/reset-password` | Compromitere completa la breach DB |
| 2 | User enumeration | `/login` | Atacatorul stie ce email-uri exista |
| 3 | Fara rate limiting (brute-force) | `/login` | Ghicire parola prin incercari repetate |
| 4 | SQL Injection | `/login` | Bypass autentificare fara parola |
| 5 | JWT fara expiry | `/login` | Token valid pe viata |
| 6 | Logout nu invalideaza token-ul | `/logout` | Session hijacking dupa logout |
| 7 | Reset token slab (Math.random) | `/forgot-password` | Token predictibil si reutilizabil |
| 8 | Reset token nereutilizabil | `/reset-password` | Acelasi token reseteza parola de N ori |
| 9 | IDOR pe tickets | `/tickets/:id` | Oricine acceseaza resursele altora |
| 10 | Audit log public | `/audit` | Fara autentificare pe endpoint sensibil |

## Instalare si rulare

```bash
npm install
npm start        # Porneste serverul pe http://localhost:3000
npm test         # Ruleaza toate testele (29 teste)
npm run test:attacks  # Ruleaza doar demonstratia de atacuri (verbose)
```

## API Endpoints

### Auth
| Method | Path | Descriere |
|---|---|---|
| POST | `/api/auth/register` | Inregistrare (parola in clar) |
| POST | `/api/auth/login` | Login (vulnerabil la SQLi, fara rate limit) |
| POST | `/api/auth/logout` | Logout (nu invalideaza token-ul) |
| POST | `/api/auth/forgot-password` | Reset token slab |
| POST | `/api/auth/reset-password` | Reset parola (token reutilizabil) |

### Tickets
| Method | Path | Descriere |
|---|---|---|
| GET | `/api/tickets` | Lista toate ticket-urile (IDOR) |
| GET | `/api/tickets/:id` | Ticket dupa ID (IDOR) |
| POST | `/api/tickets` | Creeaza ticket |
| PUT | `/api/tickets/:id` | Modifica orice ticket (IDOR) |
| DELETE | `/api/tickets/:id` | Sterge orice ticket (IDOR) |

### Audit
| Method | Path | Descriere |
|---|---|---|
| GET | `/api/audit` | Audit log (public, fara auth!) |

### Health
| Method | Path | Descriere |
|---|---|---|
| GET | `/health` | Status server |

## Structura proiect

```
src/
  app.js              ← Express app setup
  db.js               ← SQLite initializare + tabele
  middleware/
    auth.js           ← Verificare JWT (slaba)
  routes/
    auth.js           ← Autentificare (vulnerabila)
    tickets.js        ← CRUD tickets (IDOR)
    audit.js          ← Audit log (public)
tests/
  auth.test.js        ← Teste flux autentificare
  attacks.test.js     ← Demonstratie atacuri (7 atacuri)
  tickets.test.js     ← Teste CRUD tickets
server.js             ← Pornire server
```
