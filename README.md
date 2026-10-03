# Secure Login Form — HW2B (OWASP Juice Shop Security Assignment)

A small login form that mimics [OWASP Juice Shop](https://owasp-juice.shop/)'s
login page, built to demonstrate layered input validation and secure
password handling. Built for a web security course assignment analyzing
Juice Shop's vulnerabilities and applying the mitigations to a real form.

## What this is

- **`public/`** — the actual login form: `index.html`, `style.css`, `script.js`.
  - Client-side validation (empty-field check, `@` in email, 8+ character
    password) for immediate user feedback.
  - All dynamic text is written with `textContent`, never `innerHTML`, so
    user input can't be parsed as markup.
- **`server.js`** — an Express backend that re-validates everything the
  client already checked (client-side validation is a UX nicety, not a
  security boundary), hashes/compares passwords with `bcrypt`, uses a
  constant-time-ish dummy-hash comparison to avoid leaking which emails
  exist, and rate-limits login attempts.
- **`vulnerable-demo/vulnerable-login.html`** — a deliberately broken
  version of the form (reflected XSS via `innerHTML`) kept *only* to
  document the Part 3 exploit and its fix. Do not model real code on it.

## Why it's structured this way

This maps to the three vulnerability classes Juice Shop demonstrates:

| Juice Shop issue | Mitigation here |
|---|---|
| SQL injection on login (`' OR 1=1--`) | No string-built queries; lookups are by key, and a real DB would use parameterized queries / an ORM |
| Reflected/stored XSS (e.g. search bar) | Output via `textContent`; see `vulnerable-demo` for the broken version and fix |
| Weak/plaintext password storage, no rate limiting | `bcrypt` hashing (12 salt rounds) + `express-rate-limit` on `/login` |

## Running it

```bash
npm install
npm start
```

Then open **http://localhost:3001**. A demo account is seeded on startup:

- email: `demo@example.com`
- password: `CorrectHorse123!`

To see the vulnerable version, just open
`vulnerable-demo/vulnerable-login.html` directly in a browser (no server
needed) and try entering `<img src=x onerror=alert('XSS')>` in the email
field.

## Disclaimer

Built for coursework to practice identifying and fixing common web
vulnerabilities. Not intended for production use.
