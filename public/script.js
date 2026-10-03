// script.js — client-side validation for the login form.
// IMPORTANT: this is a *first line of defense* for UX only. It must never be
// trusted as the real security boundary — the server re-validates everything
// (see server.js). This is the exact gap Part 3 of the assignment exploits
// in the deliberately-unpatched version (see /vulnerable-demo).

const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const emailError = document.getElementById("email-error");
const passwordError = document.getElementById("password-error");
const serverMessage = document.getElementById("server-message");

const MIN_PASSWORD_LENGTH = 8;

function isValidEmail(value) {
  // Minimal check the assignment asks for: contains "@" and something on
  // both sides of it. (Full RFC 5322 validation is intentionally left to
  // the server / a real email-verification step.)
  const trimmed = value.trim();
  const atIndex = trimmed.indexOf("@");
  return atIndex > 0 && atIndex < trimmed.length - 1;
}

function isValidPassword(value) {
  return value.length >= MIN_PASSWORD_LENGTH;
}

function setError(el, message) {
  // textContent, never innerHTML — user-controlled strings must not be
  // parsed as HTML. This is the fix for the XSS bug documented in Part 3.
  el.textContent = message;
}

function validateForm() {
  let valid = true;

  if (!emailInput.value.trim()) {
    setError(emailError, "Email is required.");
    valid = false;
  } else if (!isValidEmail(emailInput.value)) {
    setError(emailError, "Enter a valid email address.");
    valid = false;
  } else {
    setError(emailError, "");
  }

  if (!passwordInput.value) {
    setError(passwordError, "Password is required.");
    valid = false;
  } else if (!isValidPassword(passwordInput.value)) {
    setError(passwordError, `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    valid = false;
  } else {
    setError(passwordError, "");
  }

  return valid;
}

// Validate as the user types/leaves a field, not just on submit.
emailInput.addEventListener("blur", validateForm);
passwordInput.addEventListener("blur", validateForm);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setError(serverMessage, "");

  if (!validateForm()) {
    return;
  }

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailInput.value.trim(),
        password: passwordInput.value,
      }),
    });

    const data = await response.json();

    // Server message is rendered as text only — never trust a server (or
    // attacker-controlled) string enough to inject it as markup.
    setError(serverMessage, data.message || "");
  } catch (err) {
    setError(serverMessage, "Something went wrong. Please try again.");
  }
});
