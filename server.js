// server.js
// Minimal Express backend demonstrating the server-side half of the
// security measures described in Part 1 (secure registration/login design)
// and required by Part 2 (server-side validation, not just client-side).
//
// Run: npm install && npm start

const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 12;

app.use(helmet());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Throttle login attempts to blunt brute-force / credential-stuffing —
// mitigation for the "authentication bypass via unlimited guesses"
// scenario from Part 1.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many attempts. Try again later." },
});

// --- In-memory "database" -----------------------------------------------
// A real app uses a parameterized query / ORM (e.g. `db.query("SELECT * FROM
// users WHERE email = ?", [email])`) so user input is always sent as a bound
// parameter, never concatenated into SQL text. That's what defeats the
// classic Juice Shop login bypass: `' OR 1=1--`. This demo uses a plain
// object instead of a real DB, but the *lookup* is still done the safe way:
// as a key lookup, never as a string built from user input.
const users = new Map();

async function seedDemoUser() {
  const passwordHash = await bcrypt.hash("CorrectHorse123!", SALT_ROUNDS);
  users.set("demo@example.com", { email: "demo@example.com", passwordHash });
}
seedDemoUser();

// --- Validation helpers ---------------------------------------------------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

function validateCredentials(email, password) {
  if (typeof email !== "string" || typeof password !== "string") {
    return "Invalid request.";
  }
  if (!EMAIL_RE.test(email)) {
    return "Enter a valid email address.";
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

// --- Routes ----------------------------------------------------------------
app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};

  // Server-side validation: the client-side check in script.js can be
  // bypassed entirely (disabled JS, curl, Burp, etc.), so every rule is
  // re-enforced here. This is the fix for the Part 3 bypass.
  const validationError = validateCredentials(email, password);
  if (validationError) {
    return res.status(400).json({ message: validationError });
  }

  const user = users.get(email);

  // Compare against a bcrypt hash — plaintext passwords are never stored or
  // compared directly. bcrypt.compare() is constant-time-ish and salted,
  // which also prevents rainbow-table attacks and timing leaks.
  const passwordMatches = user
    ? await bcrypt.compare(password, user.passwordHash)
    : await bcrypt.compare(password, "$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinval"); // dummy hash so timing looks the same whether or not the user exists

  if (!user || !passwordMatches) {
    // Deliberately generic — doesn't reveal whether the email or the
    // password was wrong (prevents user-enumeration).
    return res.status(401).json({ message: "Invalid email or password." });
  }

  return res.status(200).json({ message: `Welcome back!` });
});

app.listen(PORT, () => {
  console.log(`Secure login demo running at http://localhost:${PORT}`);
});
