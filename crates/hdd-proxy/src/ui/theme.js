// Theme: light by default; the toggle switches to dark and the choice is kept in localStorage when the browser allows it
// (the page works the same without it).
"use strict";

(function () {
  const KEY = "hdd-theme";
  const root = document.documentElement;

  function stored() {
    try {
      const value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch (error) {
      return null;
    }
  }

  function effective() {
    return stored() || "light";
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    const button = document.getElementById("theme-toggle");
    if (button) {
      const dark = theme === "dark";
      button.setAttribute("aria-pressed", dark ? "true" : "false");
      const label = button.lastChild;
      if (label && label.nodeType === 3) {
        label.textContent = dark ? "Light mode" : "Dark mode";
      }
    }
  }

  const saved = stored();
  if (saved) {
    root.setAttribute("data-theme", saved);
  }

  document.addEventListener("DOMContentLoaded", function () {
    apply(effective());
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.addEventListener("click", function () {
        const next = effective() === "dark" ? "light" : "dark";
        try {
          window.localStorage.setItem(KEY, next);
        } catch (error) {
          // Not persisted: the choice still applies to this page.
        }
        apply(next);
      });
    }
  });
})();
