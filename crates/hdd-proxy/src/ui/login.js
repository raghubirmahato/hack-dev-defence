// Login screen: talks to the documented public endpoints only (R-27).
"use strict";

(function () {
  const form = document.getElementById("login-form");
  const errorBox = document.getElementById("login-error");
  const submit = document.getElementById("login-submit");
  const setupHint = document.getElementById("setup-hint");
  const usernameInput = document.getElementById("login-username");
  const passwordInput = document.getElementById("login-password");

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  async function offerSetupWhenOpen() {
    try {
      const response = await fetch("/api/setup-status", { headers: { Accept: "application/json" } });
      if (!response.ok) {
        return;
      }
      const status = await response.json();
      if (status && status.setup_required && status.loopback) {
        setupHint.hidden = false;
      }
    } catch (error) {
      // The hint is optional: an unreachable API is reported by the sign-in attempt itself.
    }
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    errorBox.hidden = true;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (username.length === 0 || password.length === 0) {
      showError("Enter your username and password.");
      return;
    }
    submit.disabled = true;
    submit.textContent = "Signing in…";
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username: username, password: password }),
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
      if (response.ok) {
        window.location.assign("/app");
        return;
      }
      if (response.status === 429) {
        showError("Too many failed attempts. Wait a minute and try again.");
      } else if (payload && payload.error && payload.error.message) {
        showError(payload.error.message);
      } else {
        showError("Sign in failed (HTTP " + response.status + ").");
      }
    } catch (error) {
      showError("The HDD control panel could not be reached. Check that the proxy is running.");
    } finally {
      submit.disabled = false;
      submit.textContent = "Sign in";
    }
  });

  offerSetupWhenOpen();
})();
