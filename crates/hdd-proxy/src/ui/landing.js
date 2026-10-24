// Landing page: adapts the call-to-action to the visitor (signed in, first run, or neither). It only calls documented
// public paths and falls back to the static "Sign in" links when the API cannot be reached.
"use strict";

(function () {
  const navCta = document.getElementById("nav-cta");
  const heroCta = document.getElementById("hero-cta");
  const setupNote = document.getElementById("setup-note");

  async function getJson(path) {
    const response = await fetch(path, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    return { ok: response.ok, body: response.ok ? await response.json() : null };
  }

  async function adapt() {
    try {
      const me = await getJson("/api/me");
      if (me.ok && me.body && me.body.username) {
        navCta.textContent = "Open dashboard";
        navCta.setAttribute("href", "/app");
        heroCta.textContent = "Open the dashboard";
        heroCta.setAttribute("href", "/app");
        return;
      }
    } catch (error) {
      // Not signed in or unreachable: fall through to the setup check.
    }
    try {
      const status = await getJson("/api/setup-status");
      if (status.ok && status.body && status.body.setup_required) {
        if (status.body.loopback) {
          setupNote.hidden = false;
        }
        heroCta.textContent = "Create the owner account";
        heroCta.setAttribute("href", "/setup");
        navCta.textContent = "Get started";
        navCta.setAttribute("href", "/setup");
      }
    } catch (error) {
      // The static links already lead to the sign-in page.
    }
  }

  adapt();
})();
