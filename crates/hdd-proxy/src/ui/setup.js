// First-run setup screen: creates the owner account through POST /api/setup (Addendum 2 item 1).
"use strict";

(function () {
  const form = document.getElementById("setup-form");
  const errorBox = document.getElementById("setup-error");
  const submit = document.getElementById("setup-submit");
  const stepTwo = document.getElementById("setup-step-two");
  const usernameInput = document.getElementById("setup-username");
  const emailInput = document.getElementById("setup-email");
  const passwordInput = document.getElementById("setup-password");
  const confirmInput = document.getElementById("setup-confirm");
  const checklist = document.getElementById("password-checklist");

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function passwordProblems(username, password) {
    const problems = [];
    if (password.length < 12) {
      problems.push("at least 12 characters");
    }
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (pattern) {
      return pattern.test(password);
    }).length;
    if (classes < 3) {
      problems.push("at least three of upper case, lower case, digits and symbols");
    }
    if (username.length > 0 && password.toLowerCase().indexOf(username.toLowerCase()) !== -1) {
      problems.push("does not contain the username");
    }
    return problems;
  }

  function updateChecklist() {
    if (!checklist) {
      return;
    }
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const rules = {
      length: password.length >= 12,
      classes: [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (pattern) {
        return pattern.test(password);
      }).length >= 3,
      username: username.length === 0 || password.toLowerCase().indexOf(username.toLowerCase()) === -1,
    };
    Array.prototype.forEach.call(checklist.querySelectorAll("[data-rule]"), function (item) {
      const ok = rules[item.getAttribute("data-rule")] === true;
      item.textContent = (ok ? "✓ " : "• ") + item.textContent.replace(/^[✓•]\s*/, "");
      item.style.color = ok ? "var(--ok)" : "";
    });
  }

  async function checkAvailability() {
    try {
      const response = await fetch("/api/setup-status", { headers: { Accept: "application/json" } });
      if (!response.ok) {
        return;
      }
      const status = await response.json();
      if (!status.setup_required) {
        showError("An account already exists. The first-run setup page is closed; sign in instead.");
        submit.disabled = true;
        return;
      }
      if (!status.loopback) {
        showError("First-run setup is only available from the machine running HDD. Open this page on that machine.");
        submit.disabled = true;
      }
    } catch (error) {
      showError("The HDD control panel could not be reached. Check that the proxy is running.");
      submit.disabled = true;
    }
  }

  passwordInput.addEventListener("input", updateChecklist);
  usernameInput.addEventListener("input", updateChecklist);

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    errorBox.hidden = true;
    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    if (username.length < 3) {
      showError("The username must be at least 3 characters.");
      return;
    }
    if (email.indexOf("@") < 1 || email.indexOf("@") === email.length - 1) {
      showError("Enter a valid email address.");
      return;
    }
    const problems = passwordProblems(username, password);
    if (problems.length > 0) {
      showError("The password needs " + problems.join("; ") + ".");
      return;
    }
    if (password !== confirmInput.value) {
      showError("The password confirmation does not match.");
      return;
    }
    submit.disabled = true;
    submit.textContent = "Creating owner account…";
    try {
      const response = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username: username, email: email, password: password }),
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
      if (!response.ok) {
        if (payload && payload.error && payload.error.message) {
          showError(payload.error.message);
        } else {
          showError("Setup failed (HTTP " + response.status + ").");
        }
        submit.disabled = false;
        submit.textContent = "Create owner account";
        return;
      }
      form.hidden = true;
      checklist.hidden = true;
      stepTwo.hidden = false;
      const heading = stepTwo.querySelector("h2");
      if (heading) {
        heading.setAttribute("tabindex", "-1");
        heading.focus();
      }
    } catch (error) {
      showError("The HDD control panel could not be reached. Check that the proxy is running.");
      submit.disabled = false;
      submit.textContent = "Create owner account";
    }
  });

  updateChecklist();
  checkAvailability();
})();
