// HDD control panel — vanilla JavaScript, no framework, no CDN (COLLAB.md Addendum 1).
// Every action goes through the documented API paths (api.rs), under the same session or API token (R-27).
// The UI never invents numbers or rows: loading, empty, error and "not protected" states are all explicit.
"use strict";

(function () {
  const ROUTES = ["overview", "events", "bans", "sites", "console", "block-preview", "account", "users", "about"];
  const FIELD_KINDS = ["password", "username", "numeric_id", "search", "free_text", "filename", "header", "cookie", "unknown"];
  const VECTORS = ["path", "query", "form_body", "json_body", "multipart_field", "multipart_filename", "header", "cookie"];

  // Honest empty-state copy shared by the renderers: an empty table means nothing was recorded, never a sample row.
  const EMPTY_STATES = {
    events: "No events yet",
    bans: "No bans",
    sites: "No sites configured",
    rules: "No custom rules",
    tokens: "No API tokens",
    sessions: "No active sessions",
  };

  const state = {
    me: null,
    sites: [],
    events: { events: [], counters: {}, sites: [] },
    bans: [],
    account: null,
    pollTimer: null,
    pollBusy: false,
    banTimer: null,
    redirecting: false,
    drawerCleanup: null,
  };

  // ---------------------------------------------------------------- DOM helpers

  function $(id) {
    return document.getElementById(id);
  }

  function elem(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function append(parent) {
    for (let index = 1; index < arguments.length; index += 1) {
      const child = arguments[index];
      if (child !== null && child !== undefined) {
        parent.appendChild(child);
      }
    }
    return parent;
  }

  function chip(text, variant) {
    return elem("span", "chip" + (variant ? " " + variant : ""), text);
  }

  function emptyBlock(title, text, actionLabel, action) {
    const box = elem("div", "empty");
    box.appendChild(elem("h3", null, title));
    box.appendChild(elem("p", null, text));
    if (actionLabel && action) {
      const button = elem("button", "btn", actionLabel);
      button.type = "button";
      button.addEventListener("click", action);
      const row = elem("div", "form-actions");
      row.appendChild(button);
      box.appendChild(row);
    }
    return box;
  }

  // Keep the static empty-state blocks in sync with the shared honest copy.
  function setEmptyHeading(node, title) {
    if (!node) {
      return;
    }
    const heading = node.querySelector("h3");
    if (heading) {
      heading.textContent = title;
    }
  }

  function dd(dl, term, value) {
    dl.appendChild(elem("dt", null, term));
    const detail = elem("dd");
    if (value instanceof Node) {
      detail.appendChild(value);
    } else {
      detail.textContent = value === null || value === undefined ? "—" : String(value);
    }
    dl.appendChild(detail);
  }

  function labelFor(text, control, hint) {
    const label = elem("label", null, text);
    if (hint) {
      label.appendChild(elem("span", "hint", hint));
    }
    label.appendChild(control);
    return label;
  }

  function selectOf(values, labels, selected) {
    const select = elem("select");
    values.forEach(function (value, index) {
      const option = elem("option", null, labels[index] || value);
      option.value = value;
      if (value === selected) {
        option.selected = true;
      }
      select.appendChild(option);
    });
    return select;
  }

  // ---------------------------------------------------------------- API access

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  async function api(path, options) {
    const init = options || {};
    init.credentials = "same-origin";
    init.headers = Object.assign({ Accept: "application/json" }, init.headers || {});
    if (init.body !== undefined && typeof init.body !== "string") {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(init.body);
    }
    const response = await fetch(path, init);
    if (response.status === 401 && path !== "/api/login") {
      goToLogin();
      throw new ApiError("Your session ended. Sign in again.", 401);
    }
    let payload = null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.indexOf("json") !== -1) {
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
    }
    if (!response.ok) {
      const message =
        payload && payload.error && payload.error.message
          ? payload.error.message
          : "The request failed (HTTP " + response.status + ").";
      throw new ApiError(message, response.status);
    }
    return payload;
  }

  function goToLogin() {
    if (state.redirecting) {
      return;
    }
    state.redirecting = true;
    window.location.assign("/login");
  }

  // ---------------------------------------------------------------- feedback

  function showError(message) {
    const box = $("global-error");
    box.textContent = message;
    box.hidden = false;
  }

  function clearError() {
    const box = $("global-error");
    box.textContent = "";
    box.hidden = true;
  }

  function setStatus(message) {
    const region = $("global-status");
    if (region) {
      region.textContent = "";
      window.setTimeout(function () {
        region.textContent = message;
      }, 10);
    }
  }

  function setFieldError(id, message) {
    const node = $(id);
    if (node) {
      node.textContent = message || "";
    }
  }

  // ---------------------------------------------------------------- formatting

  function fmtTime(value) {
    if (!value) {
      return "—";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    return date.toLocaleString();
  }

  function fmtSeconds(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    if (total >= 3600) {
      return Math.floor(total / 3600) + "h " + Math.floor((total % 3600) / 60) + "m";
    }
    if (total >= 60) {
      return Math.floor(total / 60) + "m " + (total % 60) + "s";
    }
    return total + "s";
  }

  function modeChip(mode) {
    if (mode === "block") {
      return chip("block", "ok");
    }
    if (mode === "monitor") {
      return chip("monitor", "warn");
    }
    return chip("off", "danger");
  }

  function actionChip(action) {
    if (action === "block") {
      return chip("block", "danger");
    }
    if (action === "would_block") {
      return chip("would_block", "warn");
    }
    return chip("allow", "muted");
  }

  function protectionChip(site) {
    if (site.protection === "blocking_locked") {
      return chip("Protected · block + lockdown verified", "ok");
    }
    if (site.protection === "blocking_unverified") {
      return chip("Blocking · origin NOT verified (not protected)", "danger");
    }
    if (site.protection === "monitoring") {
      return chip("Monitoring only · nothing is blocked", "warn");
    }
    return chip("Protection OFF · pass-through", "danger");
  }

  function isOwner() {
    return state.me !== null && state.me.role === "owner";
  }

  // ---------------------------------------------------------------- dialogs

  function makeDialog(className) {
    const dialog = document.createElement("dialog");
    if (className) {
      dialog.className = className;
    }
    document.body.appendChild(dialog);
    dialog.addEventListener("close", function () {
      dialog.remove();
    });
    return dialog;
  }

  function closeDialog(dialog) {
    if (dialog.open) {
      dialog.close();
    } else {
      dialog.remove();
    }
  }

  function confirmDialog(options) {
    return new Promise(function (resolve) {
      const dialog = makeDialog("");
      if (options.danger) {
        dialog.classList.add("danger-dialog");
      }
      const heading = elem("h2", null, options.title);
      heading.id = "confirm-dialog-title";
      dialog.setAttribute("aria-labelledby", heading.id);
      const lead = elem("p", "dialog-lead", options.lead);
      const form = elem("form", "stack");
      const input = elem("input");
      input.type = "text";
      input.autocomplete = "off";
      input.id = "confirm-dialog-input";
      input.spellcheck = false;
      const label = labelFor(options.fieldLabel || "Type to confirm", input);
      label.setAttribute("for", input.id);
      const error = elem("p", "field-error");
      error.setAttribute("role", "alert");
      error.hidden = true;
      const actions = elem("div", "dialog-actions");
      const cancel = elem("button", "btn", options.cancelLabel || "Cancel");
      cancel.type = "button";
      const confirm = elem("button", "btn " + (options.danger ? "danger" : "primary"), options.confirmLabel || "Confirm");
      confirm.type = "submit";
      append(actions, cancel, confirm);
      append(form, label, error, actions);
      append(dialog, heading, lead, form);
      let settled = false;
      function finish(value) {
        if (settled) {
          return;
        }
        settled = true;
        closeDialog(dialog);
        resolve(value);
      }
      cancel.addEventListener("click", function () {
        finish(null);
      });
      dialog.addEventListener("cancel", function (event) {
        event.preventDefault();
        finish(null);
      });
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        const value = input.value.trim();
        if (options.expected !== undefined && value !== options.expected) {
          error.textContent = "Type " + options.expected + " exactly to confirm.";
          error.hidden = false;
          input.focus();
          return;
        }
        if (options.validate) {
          const problem = options.validate(value);
          if (problem) {
            error.textContent = problem;
            error.hidden = false;
            input.focus();
            return;
          }
        }
        finish(value);
      });
      dialog.showModal();
      input.focus();
    });
  }

  function infoDialog(options) {
    return new Promise(function (resolve) {
      const dialog = makeDialog("");
      const heading = elem("h2", null, options.title);
      heading.id = "info-dialog-title";
      dialog.setAttribute("aria-labelledby", heading.id);
      const lead = elem("p", "dialog-lead", options.lead || "");
      append(dialog, heading, lead);
      const body = elem("div", "stack");
      if (options.value) {
        const value = elem("p", "mono", options.value);
        value.style.overflowWrap = "anywhere";
        value.style.background = "var(--bg-soft)";
        value.style.padding = "0.6rem";
        value.style.borderRadius = "6px";
        body.appendChild(value);
        const copyRow = elem("div", "form-actions");
        const copy = elem("button", "btn", "Copy to clipboard");
        copy.type = "button";
        copy.addEventListener("click", function () {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(options.value).then(function () {
              setStatus("Copied to clipboard.");
            });
          }
        });
        copyRow.appendChild(copy);
        body.appendChild(copyRow);
      }
      if (options.notes) {
        const list = elem("ul", "checklist");
        options.notes.forEach(function (note) {
          list.appendChild(elem("li", null, note));
        });
        body.appendChild(list);
      }
      dialog.appendChild(body);
      const actions = elem("div", "dialog-actions");
      const close = elem("button", "btn primary", options.closeLabel || "Close");
      close.type = "button";
      close.addEventListener("click", function () {
        closeDialog(dialog);
      });
      actions.appendChild(close);
      dialog.appendChild(actions);
      dialog.addEventListener("cancel", function (event) {
        event.preventDefault();
        closeDialog(dialog);
      });
      dialog.addEventListener("close", function () {
        resolve();
      });
      dialog.showModal();
      close.focus();
    });
  }

  // ---------------------------------------------------------------- router

  function currentRoute() {
    const hash = window.location.hash || "#/overview";
    const name = hash.replace(/^#\/?/, "").split("?")[0];
    return ROUTES.indexOf(name) === -1 ? "overview" : name;
  }

  function stopTimers() {
    if (state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    if (state.banTimer) {
      window.clearInterval(state.banTimer);
      state.banTimer = null;
    }
  }

  function showRoute() {
    const route = currentRoute();
    const sections = document.querySelectorAll(".screen");
    for (let index = 0; index < sections.length; index += 1) {
      const section = sections[index];
      section.hidden = section.id !== "screen-" + route;
    }
    const links = document.querySelectorAll(".main-nav a");
    for (let index = 0; index < links.length; index += 1) {
      const link = links[index];
      if (link.getAttribute("data-route") === route) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    }
    stopTimers();
    closeEventDrawer();
    clearError();
    const loaders = {
      overview: loadOverview,
      events: loadEvents,
      bans: loadBans,
      sites: loadSites,
      console: initConsole,
      "block-preview": loadBlockPreview,
      account: loadAccount,
      users: loadUsers,
      about: loadAbout,
    };
    const loader = loaders[route];
    if (loader) {
      loader().catch(function (error) {
        showError(error.message);
      });
    }
    window.scrollTo(0, 0);
  }

  // ---------------------------------------------------------------- overview

  function counterCard(value, label, hint) {
    const card = elem("div", "counter");
    card.appendChild(elem("span", "counter-value", value));
    card.appendChild(elem("span", "counter-label", label));
    if (hint) {
      card.appendChild(elem("span", "counter-label", hint));
    }
    return card;
  }

  function renderCounters() {
    const container = $("overview-counters");
    clear(container);
    const counters = state.events.counters || {};
    const windowSeconds = Number(counters.window_seconds || 0);
    const windowLabel = windowSeconds === 3600 ? "Last hour" : "Window " + fmtSeconds(windowSeconds);
    const hasCounters = typeof counters.requests === "number";
    if (!hasCounters) {
      container.appendChild(counterCard("—", "Counters unavailable", "The events API returned no counters."));
      return;
    }
    container.appendChild(counterCard(counters.requests, windowLabel + " · requests"));
    container.appendChild(counterCard(counters.blocked, windowLabel + " · blocked"));
    container.appendChild(counterCard(counters.would_block, windowLabel + " · would block"));
    container.appendChild(counterCard(counters.banned_ips, "Active bans"));
  }

  function renderOverviewBanner() {
    const banner = $("overview-banner");
    clear(banner);
    if (state.sites.length === 0) {
      return;
    }
    const offSites = state.sites.filter(function (site) {
      return site.mode === "off";
    });
    if (offSites.length > 0) {
      const alert = elem("div", "alert warn");
      alert.setAttribute("role", "alert");
      alert.appendChild(
        elem(
          "p",
          null,
          "Protection OFF for " +
            offSites
              .map(function (site) {
                return site.host;
              })
              .join(", ") +
            ": requests pass through without inspection."
        )
      );
      banner.appendChild(alert);
      return;
    }
    const unverified = state.sites.filter(function (site) {
      return site.protection !== "blocking_locked";
    });
    if (unverified.length > 0) {
      const alert = elem("div", "alert warn");
      const hosts = unverified
        .map(function (site) {
          return site.host;
        })
        .join(", ");
      alert.appendChild(elem("strong", null, "Not protected yet: " + hosts));
      alert.appendChild(
        elem(
          "p",
          null,
          "A site is only protected when block mode is on and the origin lockdown check has passed (R-34). Monitoring does not block, and blocking without a verified lockdown can be bypassed."
        )
      );
      const next = elem("p");
      const link = elem("a", null, "Open Sites to run the lockdown check");
      link.setAttribute("href", "#/sites");
      next.appendChild(link);
      alert.appendChild(next);
      banner.appendChild(alert);
    }
  }

  function renderChecklist() {
    const box = $("overview-checklist");
    clear(box);
    if (state.sites.length === 0) {
      return;
    }
    const counters = (state.events && state.events.counters) || {};
    const items = [
      { done: state.sites.length > 0, text: "Add a site to protect" },
      {
        done: state.sites.some(function (site) {
          return site.mode === "block";
        }),
        text: "Switch a site to block mode",
        link: ["#/sites", "Open Sites"],
      },
      {
        done: state.sites.every(function (site) {
          return site.protection === "blocking_locked";
        }),
        text: "Verify the origin lockdown",
        link: ["#/sites", "Run the check"],
      },
      {
        done: Number(counters.blocked || 0) > 0,
        text: "See HDD block an attack",
        link: ["#/console", "Try the Test console"],
      },
    ];
    const finished = items.every(function (item) {
      return item.done;
    });
    if (finished) {
      return;
    }
    const card = elem("div", "card");
    const header = elem("header");
    header.appendChild(elem("h2", null, "Get protected in four steps"));
    card.appendChild(header);
    const list = elem("ul", "todo-list");
    items.forEach(function (item) {
      const row = elem("li", item.done ? "done" : "");
      row.appendChild(elem("span", "tick", item.done ? "\u2713" : ""));
      row.appendChild(elem("span", null, item.text));
      if (!item.done && item.link) {
        const anchor = elem("a", null, item.link[1]);
        anchor.setAttribute("href", item.link[0]);
        row.appendChild(anchor);
      }
      list.appendChild(row);
    });
    card.appendChild(list);
    box.appendChild(card);
  }

  function renderSiteCard(site, detailed) {
    const card = elem("article", "card");
    const header = elem("header");
    header.appendChild(elem("h3", null, site.host));
    header.appendChild(modeChip(site.mode));
    header.appendChild(protectionChip(site));
    card.appendChild(header);
    const dl = elem("dl", "dl");
    dd(dl, "Origin", site.origin);
    dd(dl, "Mode", site.mode);
    dd(dl, "Strictness", site.strictness);
    dd(dl, "Requests since start", String(site.requests));
    dd(dl, "Blocked since start", String(site.blocked));
    if (detailed) {
      dd(dl, "Bans", site.ban_enabled ? "enabled · TTL ladder " + (site.ttl_ladder_seconds || []).join(" / ") + " s" : "disabled");
      dd(dl, "Upstream Host", site.upstream_host || "not overridden");
      dd(dl, "Origin secret header", site.origin_secret_header ? site.origin_secret_header + (site.origin_secret_configured ? " (value configured)" : " (value MISSING)") : "not configured");
      dd(dl, "Lockdown verified", site.lockdown_verified ? "yes" : "no");
      dd(dl, "Field hints", (site.field_hints || []).length > 0 ? site.field_hints.map(function (hint) {
        return hint.field + " → " + hint.kind;
      }).join(", ") : "none");
    }
    card.appendChild(dl);
    const actions = elem("div", "form-actions");
    actions.style.marginTop = "0.7rem";
    actions.appendChild(modeButtons(site));
    if (detailed) {
      const setupButton = elem("button", "btn small", "Connection setup");
      setupButton.type = "button";
      setupButton.addEventListener("click", function () {
        showConnectionSetup(site);
      });
      actions.appendChild(setupButton);
      if (isOwner()) {
        const removeButton = elem("button", "btn small danger", "Remove site");
        removeButton.type = "button";
        removeButton.addEventListener("click", function () {
          requestSiteRemoval(site);
        });
        actions.appendChild(removeButton);
      }
    }
    card.appendChild(actions);
    if (detailed) {
      const strictnessRow = elem("div", "form-actions");
      strictnessRow.style.marginTop = "0.7rem";
      const strictnessLabel = elem("label", null, "Edit strictness");
      const strictnessSelect = selectOf(["balanced", "paranoid"], ["balanced", "paranoid"], site.strictness);
      strictnessLabel.appendChild(strictnessSelect);
      strictnessRow.appendChild(strictnessLabel);
      const save = elem("button", "btn small", "Save strictness");
      save.type = "button";
      if (!isOwner()) {
        strictnessSelect.disabled = true;
        save.disabled = true;
        save.title = "Viewer role is read-only";
      }
      save.addEventListener("click", function () {
        api("/api/sites/" + encodeURIComponent(site.host) + "/strictness", {
          method: "POST",
          body: { strictness: strictnessSelect.value },
        })
          .then(function () {
            setStatus("Strictness saved for " + site.host + ".");
            return loadSites();
          })
          .catch(function (error) {
            showError(error.message);
          });
      });
      strictnessRow.appendChild(save);
      card.appendChild(strictnessRow);
      const rulesHeading = elem("h4", null, "Custom rules");
      rulesHeading.style.margin = "1rem 0 0.3rem";
      card.appendChild(rulesHeading);
      const rules = site.rules || [];
      if (rules.length === 0) {
        card.appendChild(elem("p", "preview-note", EMPTY_STATES.rules + ". Built-in rule families still apply."));
      } else {
        const list = elem("ul", "checklist");
        rules.forEach(function (rule) {
          const item = elem("li");
          item.appendChild(elem("span", "mono", rule.id + " · " + rule.description + " · " + (rule.regex ? "regex /" + rule.regex + "/" : "contains " + (rule.contains || "")) + " · " + rule.action + (rule.vector ? " · " + rule.vector : "")));
          if (isOwner()) {
            const remove = elem("button", "btn small danger", "Delete");
            remove.type = "button";
            remove.style.marginLeft = "0.5rem";
            remove.addEventListener("click", function () {
              confirmDialog({
                title: "Delete rule " + rule.id + "?",
                lead: "The rule stops applying immediately. This cannot be undone.",
                fieldLabel: "Type delete to confirm",
                expected: "delete",
                confirmLabel: "Delete rule",
                danger: true,
              }).then(function (answer) {
                if (answer === null) {
                  return;
                }
                return api("/api/sites/" + encodeURIComponent(site.host) + "/rules/delete", {
                  method: "POST",
                  body: { id: rule.id },
                }).then(function () {
                  setStatus("Rule " + rule.id + " deleted.");
                  return loadSites();
                });
              }).catch(function (error) {
                showError(error.message);
              });
            });
            item.appendChild(remove);
          }
          list.appendChild(item);
        });
        card.appendChild(list);
      }
      if (isOwner()) {
        card.appendChild(customRuleForm(site));
      }
    }
    return card;
  }

  function modeButtons(site) {
    const group = elem("div", "btn-group");
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", "Protection mode for " + site.host);
    [["off", "Off"], ["monitor", "Monitor"], ["block", "Block"]].forEach(function (pair) {
      const button = elem("button", "btn small", pair[1]);
      button.type = "button";
      button.setAttribute("aria-pressed", site.mode === pair[0] ? "true" : "false");
      if (!isOwner()) {
        button.disabled = true;
        button.title = "Viewer role is read-only";
      }
      button.addEventListener("click", function () {
        requestModeChange(site, pair[0]);
      });
      group.appendChild(button);
    });
    return group;
  }

  function requestSiteRemoval(site) {
    confirmDialog({
      title: "Remove " + site.host + " from HDD?",
      lead:
        "HDD stops inspecting and forwarding requests for this site, and visitors will get the neutral not-found page. " +
        "Your origin server is not changed and your website keeps running. Past events stay in the log. If you pasted the HDD lock into your app, it keeps refusing visitors who do not come through HDD until you delete the HDD_ORIGIN_SECRET variable in Vercel (Settings → Environment Variables) and redeploy; then the site is open to everyone again. You can add the site again later.",
      fieldLabel: "Type the site host to confirm",
      expected: site.host,
      confirmLabel: "Remove site",
      danger: true,
    })
      .then(function (answer) {
        if (answer === null) {
          return null;
        }
        return api("/api/sites/" + encodeURIComponent(site.host) + "/delete", {
          method: "POST",
          body: { confirm: site.host },
        }).then(function () {
          setStatus("Site " + site.host + " removed from HDD. Your origin was not changed. To open the app to everyone again, delete HDD_ORIGIN_SECRET in your host and redeploy.");
          return loadSites();
        });
      })
      .catch(function (error) {
        showError(error.message);
      });
  }

  function bindUnblockForm() {
    const form = $("unblock-form");
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      const ip = $("unblock-ip").value.trim();
      setFieldError("unblock-validation", "");
      if (ip.length === 0) {
        setFieldError("unblock-validation", "Enter the IP address to unblock.");
        $("unblock-ip").focus();
        return;
      }
      if (!isOwner()) {
        setFieldError("unblock-validation", "Only an owner can unblock an IP address.");
        return;
      }
      api("/api/bans/" + encodeURIComponent(ip) + "/delete", { method: "POST", body: {} })
        .then(function () {
          $("unblock-ip").value = "";
          setStatus("Unblocked " + ip + ".");
          return loadBans();
        })
        .catch(function (error) {
          setFieldError(
            "unblock-validation",
            error.status === 404 ? ip + " is not banned right now." : error.message
          );
        });
    });
  }

  function requestModeChange(site, mode) {
    if (!isOwner() || site.mode === mode) {
      return;
    }
    const confirmOff = function () {
      if (mode !== "off") {
        return Promise.resolve({ mode: mode });
      }
      return confirmDialog({
        title: "Turn protection off for " + site.host + "?",
        lead: "Switching to off makes HDD forward every request without inspecting it: the site loses attack protection until you switch it back. The honest state will be shown in red on the overview.",
        fieldLabel: "Type off to confirm",
        expected: "off",
        confirmLabel: "Turn protection off",
        danger: true,
      }).then(function (answer) {
        if (answer === null) {
          return null;
        }
        return { mode: "off", confirm: "off" };
      });
    };
    confirmOff().then(function (body) {
      if (body === null) {
        return;
      }
      return api("/api/sites/" + encodeURIComponent(site.host) + "/mode", { method: "POST", body: body })
        .then(function () {
          setStatus("Mode for " + site.host + " set to " + mode + ".");
          return currentRoute() === "sites" ? loadSites() : loadOverview();
        });
    }).catch(function (error) {
      showError(error.message);
    });
  }

  function renderLiveFeed() {
    const list = $("overview-feed");
    clear(list);
    const blocked = (state.events.events || []).filter(function (event) {
      return event.action === "block";
    });
    if (blocked.length === 0) {
      const item = elem("li");
      item.style.borderLeftColor = "var(--border)";
      item.appendChild(elem("p", null, "No blocked requests yet. This feed shows only requests HDD actually blocked in block mode."));
      list.appendChild(item);
      return;
    }
    blocked.slice(0, 12).forEach(function (event) {
      const item = elem("li");
      const line = elem("div", "feed-line");
      line.appendChild(actionChip(event.action));
      if (event.rule_id) {
        line.appendChild(elem("strong", null, " " + (event.category || "") + (event.subtype ? " / " + event.subtype : "")));
        line.appendChild(elem("span", "hint", " · " + event.rule_id + " · " + (event.vector || "") + (event.field ? " · field " + event.field : "")));
      } else if (isBanBlock(event)) {
        line.appendChild(elem("strong", null, " Sender is banned"));
        line.appendChild(elem("span", "hint", " · request refused by an active ban"));
      }
      item.appendChild(line);
      if (event.rule_id && event.evidence) {
        item.appendChild(elem("code", null, "evidence: " + event.evidence));
      }
      item.appendChild(elem("div", "feed-meta", fmtTime(event.time) + " · " + event.site + " · " + event.client_ip + " · Ray ID " + event.ray_id));
      list.appendChild(item);
    });
  }

  async function refreshLive() {
    if (state.pollBusy || document.hidden || currentRoute() !== "overview") {
      return;
    }
    state.pollBusy = true;
    const status = $("overview-live-status");
    try {
      const response = await api("/api/events");
      state.events = response || { events: [], counters: {}, sites: [] };
      renderCounters();
      renderLiveFeed();
      status.textContent = "Live · updated " + new Date().toLocaleTimeString();
      status.className = "chip ok";
    } catch (error) {
      status.textContent = "Live feed paused: " + error.message;
      status.className = "chip warn";
    } finally {
      state.pollBusy = false;
    }
  }

  async function loadOverview() {
    const results = await Promise.all([api("/api/sites"), api("/api/events")]);
    const sitesResponse = results[0] || { sites: [] };
    state.sites = sitesResponse.sites || [];
    state.events = results[1] || { events: [], counters: {}, sites: [] };
    renderOverviewBanner();
    renderChecklist();
    renderCounters();
    renderLiveFeed();
    const container = $("overview-sites");
    clear(container);
    if (state.sites.length === 0) {
      container.appendChild(
        emptyBlock(
          EMPTY_STATES.sites,
          "HDD forwards nothing until a site exists. Add your domain and origin on the Sites screen; until then there is no protection to show.",
          isOwner() ? "Add a site" : null,
          function () {
            window.location.hash = "#/sites";
          }
        )
      );
    } else {
      state.sites.forEach(function (site) {
        container.appendChild(renderSiteCard(site, false));
      });
    }
    const status = $("overview-live-status");
    status.textContent = "Live · polling every 2 seconds";
    status.className = "chip ok";
    state.pollTimer = window.setInterval(refreshLive, 2000);
  }

  // ---------------------------------------------------------------- events

  function populateSiteFilter(select, value) {
    clear(select);
    const all = elem("option", null, "All sites");
    all.value = "";
    select.appendChild(all);
    const sites = state.events.sites || [];
    sites.forEach(function (host) {
      const option = elem("option", null, host);
      option.value = host;
      if (host === value) {
        option.selected = true;
      }
      select.appendChild(option);
    });
  }

  function eventMatches(event, site, action, search) {
    if (site && event.site !== site) {
      return false;
    }
    if (action && event.action !== action) {
      return false;
    }
    if (search) {
      const needle = search.toLowerCase();
      const haystack = [event.site, event.client_ip, event.method, event.path, event.rule_id, event.category, event.subtype, event.vector, event.field, event.field_kind, event.evidence, event.ray_id, event.action]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (haystack.indexOf(needle) === -1) {
        return false;
      }
    }
    return true;
  }

  function openEventDrawer(event) {
    closeEventDrawer();
    const drawer = elem("aside", "drawer");
    drawer.setAttribute("role", "dialog");
    drawer.setAttribute("aria-modal", "true");
    drawer.setAttribute("aria-labelledby", "event-drawer-title");
    const close = elem("button", "btn small drawer-close", "Close");
    close.type = "button";
    const heading = elem("h2", null, "Why this request was " + (event.action === "allow" ? "allowed" : "flagged"));
    heading.id = "event-drawer-title";
    let explanation;
    if (event.action === "block") {
      explanation = "HDD refused this request in block mode: the SQL-injection detector matched rule family " + (event.subtype || "unknown") + " (rule " + (event.rule_id || "unknown") + ") in the " + (event.vector || "unknown") + " vector, field " + (event.field || "unknown") + " (inferred kind " + (event.field_kind || "unknown") + "). The evidence below is redacted and capped before it is stored.";
    } else if (event.action === "would_block") {
      explanation = "Monitor mode: the detector would have blocked this request (rule family " + (event.subtype || "unknown") + ", rule " + (event.rule_id || "unknown") + "), but HDD forwarded it because the site is monitoring only. The site is not protected while it is not in block mode.";
    } else {
      explanation = "This request was allowed: no rule family matched the inspected values. The row is recorded for the live counters and the audit trail.";
    }
    drawer.appendChild(close);
    drawer.appendChild(heading);
    drawer.appendChild(elem("p", "dialog-lead", explanation));
    const dl = elem("dl", "dl");
    dd(dl, "Time", fmtTime(event.time));
    dd(dl, "Site", event.site);
    dd(dl, "Mode at decision", event.mode);
    dd(dl, "Client IP", event.client_ip);
    dd(dl, "Method", event.method);
    dd(dl, "Path", event.path);
    dd(dl, "Action", actionChip(event.action));
    dd(dl, "Category", event.category || "—");
    dd(dl, "Rule family", event.subtype || "—");
    dd(dl, "Rule ID", event.rule_id || "—");
    dd(dl, "Vector", event.vector || "—");
    dd(dl, "Field", event.field || "—");
    dd(dl, "Field kind", event.field_kind || "—");
    dd(dl, "Evidence (redacted)", event.evidence || "—");
    dd(dl, "Ray ID", event.ray_id);
    dd(dl, "Config revision", String(event.config_revision));
    drawer.appendChild(dl);
    document.body.appendChild(drawer);
    close.focus();
    const onKey = function (keyboardEvent) {
      if (keyboardEvent.key === "Escape") {
        closeEventDrawer();
      }
    };
    state.drawerCleanup = function () {
      document.removeEventListener("keydown", onKey);
    };
    document.addEventListener("keydown", onKey);
    close.addEventListener("click", closeEventDrawer);
  }

  function closeEventDrawer() {
    const drawer = document.querySelector(".drawer");
    if (drawer) {
      drawer.remove();
    }
    if (state.drawerCleanup) {
      state.drawerCleanup();
      state.drawerCleanup = null;
    }
  }

  function isBanBlock(event) {
    return event.action === "block" && !event.rule_id && String(event.evidence || "").indexOf("temporary ban active") === 0;
  }

  function renderEvents() {
    const site = $("event-site").value;
    const action = $("event-action").value;
    const search = $("event-search").value.trim();
    const all = state.events.events || [];
    const rows = all.filter(function (event) {
      return eventMatches(event, site, action, search);
    });
    const body = $("events-body");
    clear(body);
    setEmptyHeading($("events-empty"), EMPTY_STATES.events);
    const hasRows = rows.length > 0;
    $("events-empty").hidden = hasRows;
    $("events-table").hidden = !hasRows;
    $("events-count").textContent =
      all.length === 0
        ? "No events recorded yet."
        : "Showing " + rows.length + " of " + all.length + " recorded events.";
    rows.forEach(function (event) {
      const row = elem("tr");
      const timeCell = elem("td", "nowrap");
      timeCell.title = event.time;
      timeCell.appendChild(elem("div", null, fmtTime(event.time)));
      timeCell.appendChild(elem("div", "hint", event.site));
      row.appendChild(timeCell);
      const actionCell = elem("td");
      actionCell.appendChild(actionChip(event.action));
      row.appendChild(actionCell);
      row.appendChild(elem("td", "mono", event.client_ip));
      const what = elem("td");
      if (event.rule_id) {
        what.appendChild(elem("div", null, (event.category || "") + (event.subtype ? " / " + event.subtype : "")));
        what.appendChild(elem("div", "hint mono", event.rule_id));
      } else if (isBanBlock(event)) {
        what.appendChild(elem("div", null, "Sender is banned"));
        what.appendChild(elem("div", "hint", "request refused by an active ban"));
      } else {
        what.appendChild(elem("div", "hint", event.action === "allow" ? "Nothing suspicious" : "—"));
      }
      row.appendChild(what);
      const where = elem("td");
      if (event.vector) {
        where.appendChild(elem("div", null, event.vector));
        where.appendChild(elem("div", "hint mono", event.field || ""));
      } else {
        where.appendChild(elem("span", "hint", event.method && event.path ? event.method + " " + event.path : "—"));
      }
      row.appendChild(where);
      const evidence = elem("td");
      const code = elem("code", "evidence", event.evidence || "—");
      evidence.appendChild(code);
      row.appendChild(evidence);
      const detailCell = elem("td");
      const detail = elem("button", "btn small", "Details");
      detail.type = "button";
      detail.addEventListener("click", function () {
        openEventDrawer(event);
      });
      detail.setAttribute("aria-label", "Details for event " + event.ray_id);
      detailCell.appendChild(detail);
      row.appendChild(detailCell);
      body.appendChild(row);
    });
  }

  async function loadEvents() {
    state.events = (await api("/api/events")) || { events: [], counters: {}, sites: [] };
    populateSiteFilter($("event-site"), "");
    renderEvents();
  }

  // ---------------------------------------------------------------- bans

  function startBanCountdown() {
    if (state.banTimer) {
      window.clearInterval(state.banTimer);
    }
    state.banTimer = window.setInterval(function () {
      const nodes = document.querySelectorAll("[data-expires-at]");
      for (let index = 0; index < nodes.length; index += 1) {
        const node = nodes[index];
        const expiresAt = Number(node.getAttribute("data-expires-at"));
        const remaining = expiresAt - Date.now() / 1000;
        node.textContent = remaining <= 0 ? "expired" : fmtSeconds(remaining);
      }
    }, 1000);
  }

  function renderBans() {
    const body = $("bans-body");
    clear(body);
    setEmptyHeading($("bans-empty"), EMPTY_STATES.bans);
    const bans = state.bans;
    const hasBans = bans.length > 0;
    $("bans-empty").hidden = hasBans;
    $("bans-table").hidden = !hasBans;
    $("bans-caption").textContent = hasBans ? bans.length + " active ban(s), soonest expiry first" : "No active bans";
    bans.forEach(function (ban) {
      const row = elem("tr");
      row.appendChild(elem("td", "mono", ban.ip));
      row.appendChild(elem("td", null, ban.site || "all sites"));
      row.appendChild(elem("td", null, ban.reason));
      row.appendChild(elem("td", "mono", ban.rule_id || "—"));
      row.appendChild(elem("td", "num", String(ban.step)));
      const expiry = elem("td", "num mono");
      const expiresAtValue = ban.expires_at ? Date.parse(ban.expires_at) / 1000 : 0;
      expiry.setAttribute("data-expires-at", String(expiresAtValue));
      expiry.textContent = fmtSeconds(ban.remaining_seconds);
      row.appendChild(expiry);
      row.appendChild(elem("td", "nowrap", fmtTime(ban.expires_at)));
      const actions = elem("td");
      if (isOwner()) {
        const unban = elem("button", "btn small danger", "Unban");
        unban.type = "button";
        unban.addEventListener("click", function () {
          confirmDialog({
            title: "Unban " + ban.ip + "?",
            lead: "The client can reach the site again immediately. Only do this if you are sure the request was not an attack.",
            fieldLabel: "Type unban to confirm",
            expected: "unban",
            confirmLabel: "Unban client",
            danger: true,
          }).then(function (answer) {
            if (answer === null) {
              return;
            }
            return api("/api/bans/" + encodeURIComponent(ban.ip) + "/delete", { method: "POST", body: {} }).then(function () {
              setStatus("Unbanned " + ban.ip + ".");
              return loadBans();
            });
          }).catch(function (error) {
            showError(error.message);
          });
        });
        actions.appendChild(unban);
      } else {
        actions.appendChild(elem("span", "preview-note", "viewer: read-only"));
      }
      row.appendChild(actions);
      body.appendChild(row);
    });
  }

  async function loadBans() {
    const response = await api("/api/bans");
    state.bans = (response && response.bans) || [];
    renderBans();
    startBanCountdown();
  }

  // ---------------------------------------------------------------- sites

  function customRuleForm(site) {
    const details = elem("details");
    details.style.marginTop = "0.8rem";
    const summary = elem("summary", null, "Add a custom rule (for a vulnerability found on the day)");
    details.appendChild(summary);
    const form = elem("form", "stack");
    form.style.marginTop = "0.6rem";
    const description = elem("input");
    description.type = "text";
    description.maxLength = 200;
    description.required = true;
    const matchType = selectOf(["contains", "regex"], ["contains (literal text)", "regex (linear-time)"], "contains");
    const pattern = elem("input");
    pattern.type = "text";
    pattern.required = true;
    pattern.spellcheck = false;
    const vector = selectOf(["", ...VECTORS], ["any vector", ...VECTORS], "");
    const action = selectOf(["block", "allow"], ["block", "allow"], "block");
    append(
      form,
      labelFor("Rule description", description, "Shown in the event log so the block is explainable (R-24)."),
      labelFor("Match type", matchType),
      labelFor("Pattern", pattern, "A regex is compiled and validated before it is saved."),
      labelFor("Vector", vector),
      labelFor("Action", action)
    );
    const error = elem("p", "field-error");
    error.setAttribute("role", "alert");
    error.hidden = true;
    form.appendChild(error);
    const row = elem("div", "form-actions");
    const submit = elem("button", "btn primary", "Add rule");
    submit.type = "submit";
    row.appendChild(submit);
    form.appendChild(row);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      const descriptionValue = description.value.trim();
      const patternValue = pattern.value;
      if (descriptionValue.length === 0) {
        error.textContent = "A description is required so the event log can explain the rule.";
        error.hidden = false;
        return;
      }
      if (patternValue.length === 0) {
        error.textContent = "A pattern is required.";
        error.hidden = false;
        return;
      }
      if (matchType.value === "regex") {
        try {
          new RegExp(patternValue);
        } catch (regexError) {
          error.textContent = "The regular expression is not valid: " + regexError.message;
          error.hidden = false;
          return;
        }
      }
      error.hidden = true;
      const rule = {
        id: "C-" + Date.now().toString(36).toUpperCase(),
        description: descriptionValue,
        action: action.value,
        vector: vector.value === "" ? null : vector.value,
      };
      if (matchType.value === "regex") {
        rule.regex = patternValue;
      } else {
        rule.contains = patternValue;
      }
      api("/api/sites/" + encodeURIComponent(site.host) + "/rules", { method: "POST", body: { rule: rule } })
        .then(function () {
          setStatus("Custom rule " + rule.id + " added to " + site.host + ".");
          return loadSites();
        })
        .catch(function (apiError) {
          error.textContent = apiError.message;
          error.hidden = false;
        });
    });
    details.appendChild(form);
    return details;
  }

  async function loadSites() {
    const response = await api("/api/sites");
    state.sites = (response && response.sites) || [];
    const list = $("sites-list");
    clear(list);
    const hasSites = state.sites.length > 0;
    $("sites-empty").hidden = hasSites;
    const addButton = $("add-site-btn");
    addButton.hidden = !isOwner();
    if (!hasSites) {
      if (!isOwner()) {
        list.appendChild(emptyBlock("No sites configured", "No site is configured. Ask an owner to add one."));
      }
      return;
    }
    state.sites.forEach(function (site) {
      list.appendChild(renderSiteCard(site, true));
    });
  }

  function showConnectionSetup(site) {
    const dialog = makeDialog("wide");
    const heading = elem("h2", null, "Connection setup for " + site.host);
    heading.id = "connection-dialog-title";
    dialog.setAttribute("aria-labelledby", heading.id);
    const lead = elem(
      "p",
      "dialog-lead",
      "Generated from this site's real host and origin. Follow the steps, then use Check lockdown and Verify protection on the Sites screen; the site is not protected until both pass."
    );
    const controls = elem("div", "form-actions");
    const methodLabel = elem("label", null, "Connection method");
    const method = selectOf(["dns", "cloudflare", "nginx", "vercel"], ["DNS + Caddy", "Cloudflare tunnel/proxy", "nginx/Apache", "Vercel / serverless"], "dns");
    methodLabel.appendChild(method);
    const loadButton = elem("button", "btn primary", "Load instructions");
    loadButton.type = "button";
    append(controls, methodLabel, loadButton);
    const output = elem("div");
    append(dialog, heading, lead, controls, output);
    const closeRow = elem("div", "dialog-actions");
    const close = elem("button", "btn", "Close");
    close.type = "button";
    close.addEventListener("click", function () {
      closeDialog(dialog);
    });
    closeRow.appendChild(close);
    dialog.appendChild(closeRow);
    dialog.addEventListener("cancel", function (event) {
      event.preventDefault();
      closeDialog(dialog);
    });
    function load() {
      clear(output);
      output.appendChild(elem("p", "preview-note", "Loading instructions…"));
      api("/api/sites/" + encodeURIComponent(site.host) + "/connect/" + encodeURIComponent(method.value))
        .then(function (instructions) {
          renderInstructions(output, instructions, site);
        })
        .catch(function (error) {
          clear(output);
          output.appendChild(elem("p", "alert error", error.message));
        });
    }
    loadButton.addEventListener("click", load);
    dialog.showModal();
    loadButton.focus();
  }

  function renderInstructions(container, instructions, site) {
    clear(container);
    if (!instructions) {
      container.appendChild(elem("p", "alert error", "The API returned no instructions."));
      return;
    }
    container.appendChild(elem("p", "progress", instructions.method + " · generated"));
    container.appendChild(elem("h3", null, instructions.title));
    const steps = elem("ol", "steps");
    (instructions.steps || []).forEach(function (step) {
      steps.appendChild(elem("li", null, step));
    });
    container.appendChild(steps);
    if (instructions.snippet) {
      const pre = elem("pre");
      const code = elem("code", null, instructions.snippet);
      pre.appendChild(code);
      container.appendChild(pre);
      const copyRow = elem("div", "copy-row");
      const copy = elem("button", "btn small", "Copy snippet");
      copy.type = "button";
      copy.addEventListener("click", function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(instructions.snippet).then(function () {
            setStatus("Snippet copied to clipboard.");
          });
        }
      });
      copyRow.appendChild(copy);
      container.appendChild(copyRow);
    }
    const caveats = elem("div", "alert warn");
    caveats.appendChild(elem("p", null, "Read this before claiming the site is protected:"));
    const list = elem("ul", "checklist");
    (instructions.caveats || []).forEach(function (caveat) {
      list.appendChild(elem("li", null, caveat));
    });
    caveats.appendChild(list);
    container.appendChild(caveats);
    appendLockdownButtons(container, site);
  }

  function appendLockdownButtons(container, site) {
    const row = elem("div", "form-actions");
    row.style.marginTop = "0.8rem";
    const check = elem("button", "btn", "Check lockdown");
    check.type = "button";
    const result = elem("div");
    check.addEventListener("click", function () {
      clear(result);
      result.appendChild(elem("p", "preview-note", "Requesting the origin directly from the HDD host…"));
      api("/api/sites/" + encodeURIComponent(site.host) + "/lockdown-check", { method: "POST", body: {} })
        .then(function (lockdown) {
          clear(result);
          const alert = elem("div", "alert " + (lockdown && lockdown.protected ? "ok" : "warn"));
          alert.appendChild(elem("p", null, (lockdown && lockdown.protected ? "Locked down: " : "Not locked down (not protected): ") + (lockdown ? lockdown.result : "unknown")));
          if (lockdown && lockdown.detail) {
            alert.appendChild(elem("p", null, lockdown.detail));
          }
          if (lockdown && lockdown.status_code !== null && lockdown.status_code !== undefined) {
            alert.appendChild(elem("p", "mono", "Direct request status: " + lockdown.status_code));
          }
          result.appendChild(alert);
        })
        .catch(function (error) {
          clear(result);
          result.appendChild(elem("p", "alert error", error.message));
        });
    });
    row.appendChild(check);
    container.appendChild(row);
    container.appendChild(result);
  }

  function copyText(text, label) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        setStatus((label || "Text") + " copied to clipboard.");
      });
    }
  }

  // A pasted address such as "My-App.vercel.app/some/path" (with or without a scheme) becomes "my-app.vercel.app".
  const HTTPS_SCHEME = "https" + ":" + "//";
  function normalizeAppAddress(value) {
    let text = String(value || "").trim();
    text = text.replace(/^[a-z]+:\/\//i, "");
    text = text.split("/")[0].split("?")[0].split("#")[0];
    text = text.replace(/:\d+$/, "");
    return text.toLowerCase();
  }

  // Vercel's one-off deployment addresses look like project-<9 letters/digits>-team.vercel.app and change on every deploy.
  function looksLikeDeploymentAddress(host) {
    return /-(?=[a-z0-9]*\d)[a-z0-9]{9}-[a-z0-9-]+\.vercel\.app$/.test(host);
  }

  function copyBlock(title, value, label, multiline) {
    const box = elem("div", "copy-block");
    box.appendChild(elem("strong", null, title));
    const row = elem("div", "copy-row");
    if (multiline) {
      const pre = elem("pre");
      pre.appendChild(elem("code", null, value));
      row.appendChild(pre);
    } else {
      const input = elem("input", "mono");
      input.type = "text";
      input.readOnly = true;
      input.value = value;
      input.setAttribute("aria-label", title);
      row.appendChild(input);
    }
    const button = elem("button", "btn small", "Copy");
    button.type = "button";
    button.addEventListener("click", function () {
      copyText(value, label);
    });
    row.appendChild(button);
    box.appendChild(row);
    return box;
  }

  function openAddSiteWizard() {
    const dialog = makeDialog("wide");
    dialog.setAttribute("aria-labelledby", "wizard-title");
    const content = elem("div");
    dialog.appendChild(content);
    let createdSite = null;
    let instructions = null;
    let generatedSecret = null;
    function closeWizard() {
      closeDialog(dialog);
      loadSites().catch(function (error) {
        showError(error.message);
      });
    }
    dialog.addEventListener("cancel", function (event) {
      event.preventDefault();
      closeWizard();
    });
    function stepOne() {
      clear(content);
      content.appendChild(elem("p", "progress", "Step 1 of 3 · site and connection method"));
      const heading = elem("h2", null, "Add a site");
      heading.id = "wizard-title";
      content.appendChild(heading);
      content.appendChild(
        elem(
          "p",
          "dialog-lead",
          "Enter the public domain HDD will protect and the origin it forwards to. Start in monitor mode: block mode is only presented as protected once the origin lockdown and verification both pass."
        )
      );
      const form = elem("form", "stack");
      const host = elem("input");
      host.type = "text";
      host.required = true;
      host.placeholder = "demo.example.com";
      host.autocomplete = "off";
      host.spellcheck = false;
      const origin = elem("input");
      origin.type = "text";
      origin.required = true;
      origin.placeholder = "origin server URL, including the scheme";
      origin.autocomplete = "off";
      origin.spellcheck = false;
      const mode = selectOf(["monitor", "block", "off"], ["monitor (record only)", "block (refuse attacks)", "off (pass-through, not protected)"], "monitor");
      const connection = selectOf(["dns", "cloudflare", "nginx", "vercel"], ["DNS + Caddy", "Cloudflare tunnel/proxy", "nginx/Apache in front of an origin", "Vercel / serverless"], "dns");
      const upstreamHost = elem("input");
      upstreamHost.type = "text";
      upstreamHost.placeholder = "optional upstream Host override";
      upstreamHost.autocomplete = "off";
      const secretHeader = elem("input");
      secretHeader.type = "text";
      secretHeader.placeholder = "optional origin secret header name (serverless)";
      secretHeader.autocomplete = "off";
      const error = elem("p", "field-error");
      error.setAttribute("role", "alert");
      error.hidden = true;
      let quick = true;
      let frontDoor = false;
      let hostAutoFilled = false;
      const kindGroup = elem("div", "btn-group");
      kindGroup.setAttribute("role", "group");
      kindGroup.setAttribute("aria-label", "What are you protecting?");
      const quickButton = elem("button", "btn", "Vercel / serverless app (guided)");
      const serverButton = elem("button", "btn", "Normal server or domain");
      quickButton.type = "button";
      serverButton.type = "button";
      kindGroup.appendChild(quickButton);
      kindGroup.appendChild(serverButton);
      const kindBlock = elem("div", "stack");
      kindBlock.appendChild(elem("strong", null, "What are you protecting?"));
      kindBlock.appendChild(kindGroup);
      const vercelAddress = elem("input");
      vercelAddress.type = "text";
      vercelAddress.placeholder = "my-app.vercel.app";
      vercelAddress.autocomplete = "off";
      vercelAddress.spellcheck = false;
      const deployWarning = elem("p", "alert warn");
      deployWarning.hidden = true;
      deployWarning.textContent =
        "This looks like a one-off deployment address that changes with every deploy. Use your project's production address instead (Vercel → your project → Domains).";
      // Addendum 7 item 3: next to the default route, offer the front door that keeps visitors on the Vercel address.
      const frontChoice = elem("div", "btn-group");
      frontChoice.setAttribute("role", "group");
      frontChoice.setAttribute("aria-label", "Should visitors keep your Vercel address?");
      const defaultRouteButton = elem("button", "btn", "Visitors use an address that points at HDD (default)");
      const frontDoorButton = elem("button", "btn", "Keep visitors on my Vercel address (front door)");
      defaultRouteButton.type = "button";
      frontDoorButton.type = "button";
      frontChoice.appendChild(defaultRouteButton);
      frontChoice.appendChild(frontDoorButton);
      const frontChoiceBlock = elem("div", "stack");
      frontChoiceBlock.appendChild(elem("strong", null, "Should visitors keep your Vercel address?"));
      frontChoiceBlock.appendChild(frontChoice);
      const appAddressLabel = labelFor(
        "Your Vercel app address",
        vercelAddress,
        "Paste the address from Vercel → your project → Domains. HDD fills in the origin, the Host override and the secret header for you, and generates the secret."
      );
      const secondAddress = elem("input");
      secondAddress.type = "text";
      secondAddress.placeholder = "my-app-git-main-team.vercel.app";
      secondAddress.autocomplete = "off";
      secondAddress.spellcheck = false;
      const frontDoorBox = elem("div", "stack");
      frontDoorBox.hidden = true;
      append(
        frontDoorBox,
        labelFor(
          "Second address of the same project (the origin)",
          secondAddress,
          "The origin HDD forwards inspected requests to. In Vercel open your project, then Domains, and add or keep a second production domain for the same project (or use a deployment address of the same project). Never share it with visitors and never make it the public host: visitors keep using your main Vercel address."
        )
      );
      const quickBox = elem("div", "stack");
      append(quickBox, frontChoiceBlock, appAddressLabel, deployWarning, frontDoorBox);
      const serverBox = elem("div", "stack");
      append(
        serverBox,
        labelFor("Origin", origin, "Where HDD forwards inspected requests. The origin must be locked down afterwards."),
        labelFor("Initial mode", mode),
        labelFor("Connection method", connection),
        labelFor("Upstream Host override", upstreamHost, "For Vercel/serverless origins; leave blank to preserve the Host header."),
        labelFor("Origin secret header", secretHeader, "Optional for serverless origins without fixed IPs (Addendum 5).")
      );
      function setHint(label, text) {
        const hint = label.querySelector(".hint");
        if (hint) {
          hint.textContent = text;
        }
      }
      // Addendum 7 item 3: the front door keeps visitors on the main Vercel address, and the second address of the same
      // project is only the origin HDD forwards inspected requests to.
      function showFrontDoor(isFrontDoor) {
        frontDoor = isFrontDoor;
        frontDoorButton.setAttribute("aria-pressed", isFrontDoor ? "true" : "false");
        defaultRouteButton.setAttribute("aria-pressed", isFrontDoor ? "false" : "true");
        frontDoorBox.hidden = !isFrontDoor;
        secondAddress.required = isFrontDoor;
        setHint(
          appAddressLabel,
          isFrontDoor
            ? "Paste your main address from Vercel → your project → Domains. Visitors keep using this address; HDD registers it as the public host and sends every request through itself first."
            : "Paste the address from Vercel → your project → Domains. HDD fills in the origin, the Host override and the secret header for you, and generates the secret."
        );
        setHint(
          publicHostLabel,
          isFrontDoor
            ? "Filled from the address above when empty. In front-door mode this must be your main Vercel address, the one visitors keep using; the second address below is the origin HDD forwards to and must not be shared with visitors."
            : "The address visitors type to reach the site through HDD. Testing on this computer: use 127.0.0.1. Live: your own domain, pointed at HDD."
        );
        if (isFrontDoor && (host.value.trim() === "" || host.value.trim() === "127.0.0.1")) {
          host.value = normalizeAppAddress(vercelAddress.value);
          hostAutoFilled = true;
        }
      }
      function showKind(isQuick) {
        quick = isQuick;
        quickBox.hidden = !isQuick;
        serverBox.hidden = isQuick;
        quickButton.setAttribute("aria-pressed", isQuick ? "true" : "false");
        serverButton.setAttribute("aria-pressed", isQuick ? "false" : "true");
        origin.required = !isQuick;
        vercelAddress.required = isQuick;
        if (isQuick && host.value.trim() === "") {
          host.value = "127.0.0.1";
        }
      }
      quickButton.addEventListener("click", function () {
        showKind(true);
      });
      serverButton.addEventListener("click", function () {
        showKind(false);
      });
      defaultRouteButton.addEventListener("click", function () {
        showFrontDoor(false);
      });
      frontDoorButton.addEventListener("click", function () {
        showFrontDoor(true);
      });
      host.addEventListener("input", function () {
        hostAutoFilled = false;
      });
      vercelAddress.addEventListener("input", function () {
        deployWarning.hidden = !looksLikeDeploymentAddress(normalizeAppAddress(vercelAddress.value));
        if (frontDoor && (hostAutoFilled || host.value.trim() === "")) {
          host.value = normalizeAppAddress(vercelAddress.value);
          hostAutoFilled = true;
        }
      });
      const publicHostLabel = labelFor(
        "Public host",
        host,
        "The address visitors type to reach the site through HDD. Testing on this computer: use 127.0.0.1. Live: your own domain, pointed at HDD."
      );
      append(form, kindBlock, publicHostLabel, quickBox, serverBox, error);
      showKind(true);
      showFrontDoor(true);
      const actions = elem("div", "dialog-actions");
      const cancel = elem("button", "btn", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", closeWizard);
      const create = elem("button", "btn primary", "Create site");
      create.type = "submit";
      append(actions, cancel, create);
      form.appendChild(actions);
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        let hostValue = host.value.trim();
        const appAddress = normalizeAppAddress(vercelAddress.value);
        const secondValue = normalizeAppAddress(secondAddress.value);
        const originValue = quick
          ? HTTPS_SCHEME + (frontDoor ? secondValue : appAddress)
          : origin.value.trim();
        const lowerOrigin = originValue.toLowerCase();
        if (quick && frontDoor && hostValue === "") {
          // The front door registers the main Vercel address as the public host, so it is filled from the address above.
          hostValue = appAddress;
        }
        if (quick && (appAddress.length === 0 || /\s/.test(appAddress) || appAddress.indexOf(".") < 0)) {
          error.textContent = "Enter your Vercel app address, for example my-app.vercel.app.";
          error.hidden = false;
          return;
        }
        if (quick && /^[0-9]{1,3}([.][0-9]{1,3}){3}$/.test(appAddress)) {
          error.textContent =
            "Enter the app's name, not an IP address. Vercel serves your app only when it is reached by its name " +
            "(for example my-app.vercel.app), because one IP address is shared by thousands of apps.";
          error.hidden = false;
          return;
        }
        if (quick && frontDoor && secondValue.length === 0) {
          error.textContent =
            "Enter the second address of the same Vercel project (the origin HDD forwards to). In Vercel open your project, then Domains, and add or keep a second production domain for the same project (or use a deployment address of the same project).";
          error.hidden = false;
          return;
        }
        if (quick && frontDoor && secondValue === appAddress) {
          error.textContent =
            "The front door needs a second address of the same Vercel project: the public host and the second address are the same address, so visitors would skip HDD. Add a second production domain for the same project (Vercel → your project → Domains) or use a deployment address of that project as the origin.";
          error.hidden = false;
          return;
        }
        if (quick && frontDoor && hostValue.toLowerCase() !== appAddress) {
          error.textContent =
            "In front-door mode the public host must be your main Vercel address (the address above): visitors keep using it, and the second address below is only the origin HDD forwards to.";
          error.hidden = false;
          return;
        }
        if (hostValue.length > 0 && hostValue.toLowerCase() === normalizeAppAddress(originValue)) {
          error.textContent =
            "The public host and the origin are the same address. Visitors to that address go straight to the origin and skip HDD. " +
            "Use 127.0.0.1 for testing on this computer, or your own domain that you point at HDD.";
          error.hidden = false;
          return;
        }
        if (hostValue.length === 0 || /[\s/]/.test(hostValue)) {
          error.textContent = "Enter the public host name without a scheme, spaces or a path.";
          error.hidden = false;
          return;
        }
        if (!(lowerOrigin.startsWith("http:") || lowerOrigin.startsWith("https:"))) {
          error.textContent = "The origin must be an absolute URL with an http: or https: scheme.";
          error.hidden = false;
          return;
        }
        error.hidden = true;
        create.disabled = true;
        create.textContent = "Creating…";
        api("/api/sites", {
          method: "POST",
          body: quick
            ? frontDoor
              ? {
                  host: hostValue,
                  origin: originValue,
                  mode: "monitor",
                  connection: "vercel_front_door",
                  upstream_host: secondValue,
                  origin_secret_header: null,
                  generate_origin_secret: true,
                }
              : {
                  host: hostValue,
                  origin: originValue,
                  mode: "monitor",
                  connection: "vercel",
                  upstream_host: appAddress,
                  origin_secret_header: null,
                  generate_origin_secret: true,
                }
            : {
                host: hostValue,
                origin: originValue,
                mode: mode.value,
                connection: connection.value,
                upstream_host: upstreamHost.value.trim() || null,
                origin_secret_header: secretHeader.value.trim() || null,
              },
        })
          .then(function (response) {
            createdSite = response.site;
            instructions = response.setup;
            generatedSecret = response.origin_secret || null;
            state.sites = state.sites.filter(function (site) {
              return site.host !== createdSite.host;
            });
            state.sites.push(createdSite);
            stepTwo();
          })
          .catch(function (apiError) {
            error.textContent = apiError.message;
            error.hidden = false;
            create.disabled = false;
            create.textContent = "Create site";
          });
      });
      content.appendChild(form);
      dialog.showModal();
      host.focus();
    }
    // Addendum 7 item 3: the front-door guide. Visitors keep using the Vercel address; one self-contained block is
    // pasted at the very END of the Node handler and HDD_GATE_URL points it at the public URL of HDD.
    function frontDoorGuide() {
      const guide = elem("div", "stack");
      const intro = elem("div", "alert info");
      intro.appendChild(
        elem(
          "p",
          null,
          "HDD generated a strong secret for " +
            createdSite.host +
            ". It is shown only once here (HDD keeps its own copy in an owner-only file). In front-door mode visitors keep using " +
            createdSite.host +
            ", and HDD decides every request: the app answers only a request that came through HDD. Do these things in order, then press Check lockdown."
        )
      );
      guide.appendChild(intro);
      const steps = elem("ol", "steps");
      const one = elem("li");
      one.appendChild(elem("strong", null, "Add the secret environment variable"));
      one.appendChild(elem("p", "hint", "Vercel → your project → Settings → Environment Variables (Production). Name: HDD_ORIGIN_SECRET. The front-door block is off while this variable is empty."));
      one.appendChild(copyBlock("Value", generatedSecret, "The secret", false));
      steps.appendChild(one);
      const two = elem("li");
      two.appendChild(elem("strong", null, "Paste the front-door block at the very END of your handler file"));
      two.appendChild(elem("p", "hint", "Paste the whole block below at the very END of the file Vercel runs (the Node handler, usually api/index.js or api/app.js), after your last line. One block, no new file, and your own code stays exactly as it is. It is for CommonJS Node handlers that export a request handler with module.exports; a Next.js app should use the default (non-front-door) mode instead."));
      two.appendChild(elem("pre", "tree", "your-project/\n├─ api/\n│  └─ index.js   ← paste at the very END of this file\n├─ package.json\n└─ vercel.json"));
      if (instructions && instructions.snippet) {
        two.appendChild(copyBlock("api/index.js  (your handler file)", instructions.snippet, "The front-door block", true));
      }
      steps.appendChild(two);
      const three = elem("li");
      three.appendChild(elem("strong", null, "Point the front door at HDD"));
      three.appendChild(elem("p", "hint", "In the same Environment Variables screen (Production) add HDD_GATE_URL: the public URL of HDD, for example your HTTPS server address. Vercel's servers call it, so HDD must be reachable from the internet (a loopback address does not work). For demos, run `node scripts/hdd-tunnel.mjs --port 8080` from the repository root and use the URL it prints; the tunnel is temporary and its URL changes when it restarts. Also add HDD_FAIL_OPEN = 1 if the site must keep working while HDD is off or unreachable (those requests are then not inspected); leave it out to refuse requests instead."));
      steps.appendChild(three);
      const four = elem("li");
      four.appendChild(elem("strong", null, "Redeploy"));
      four.appendChild(elem("p", "hint", "Deploy again so both environment variables and the front-door block go live."));
      steps.appendChild(four);
      const five = elem("li");
      five.appendChild(elem("strong", null, "Check lockdown, then verify protection"));
      five.appendChild(elem("p", "hint", "Press Check lockdown below. The verification checks probe " + createdSite.host + " (the public host), not the second address. Until both checks pass the site stays not protected."));
      steps.appendChild(five);
      guide.appendChild(steps);
      const checkRow = elem("div", "form-actions");
      const check = elem("button", "btn primary", "Check lockdown");
      check.type = "button";
      const result = elem("div");
      check.addEventListener("click", function () {
        check.disabled = true;
        check.textContent = "Checking…";
        clear(result);
        api("/api/sites/" + encodeURIComponent(createdSite.host) + "/lockdown-check", { method: "POST", body: {} })
          .then(function (outcome) {
            const alert = elem("div", "alert " + (outcome.protected ? "ok" : "warn"));
            alert.appendChild(elem("strong", null, outcome.protected ? "Lockdown holds" : "Not locked down yet"));
            alert.appendChild(elem("p", null, outcome.detail || ""));
            result.appendChild(alert);
          })
          .catch(function (apiError) {
            result.appendChild(elem("p", "alert error", apiError.message));
          })
          .then(function () {
            check.disabled = false;
            check.textContent = "Check lockdown";
          });
      });
      checkRow.appendChild(check);
      guide.appendChild(checkRow);
      guide.appendChild(result);
      return guide;
    }
    function vercelGuide() {
      if (instructions && instructions.method === "vercel_front_door") {
        return frontDoorGuide();
      }
      const guide = elem("div", "stack");
      const intro = elem("div", "alert info");
      intro.appendChild(
        elem(
          "p",
          null,
          "HDD generated a strong secret for " +
            createdSite.host +
            ". It is shown only once here (HDD keeps its own copy in an owner-only file). If HDD_ORIGIN_SECRET already exists in Vercel, replace its value with this one: a site added again always gets a new secret. Do these four things, then press Check lockdown."
        )
      );
      guide.appendChild(intro);
      const steps = elem("ol", "steps");
      const one = elem("li");
      one.appendChild(elem("strong", null, "Add an environment variable"));
      one.appendChild(elem("p", "hint", "Vercel → your project → Settings → Environment Variables (Production). Name: HDD_ORIGIN_SECRET"));
      one.appendChild(copyBlock("Value", generatedSecret, "The secret", false));
      steps.appendChild(one);
      const two = elem("li");
      two.appendChild(elem("strong", null, "Paste the lock into your app"));
      two.appendChild(elem("p", "hint", "Copy the code below and paste it at the very end of the file shown. Save (commit) and nothing else changes. No new file is needed."));
      if (instructions && instructions.snippet) {
        // The generated text holds four pieces in a fixed order; each is offered on its own so the wrong one is never copied.
        const text = instructions.snippet;
        const edgeAt = text.indexOf("// middleware.ts (Edge Middleware alternative");
        const nodeAt = text.indexOf("// Node function lock");
        const esmAt = text.indexOf("// Node ES module lock");
        const nextCode = (edgeAt > 0 ? text.slice(0, edgeAt) : text).trim() + "\n";
        const nodeCode = nodeAt > 0 ? text.slice(nodeAt, esmAt > nodeAt ? esmAt : text.length).trim() + "\n" : "";
        const esmCode = esmAt > 0 ? text.slice(esmAt).trim() + "\n" : "";
        const options = [
          {
            label: "Node (module.exports), the usual one",
            title: "api/index.js  (your handler file)",
            code: nodeCode,
            hint: "Open the file Vercel runs (usually api/index.js or api/app.js) and paste the code at the very END of it, after your last line. Your own code stays exactly as it is.",
            tree: "your-project/\n├─ api/\n│  └─ index.js   ← paste at the very END of this file\n├─ package.json\n└─ vercel.json",
          },
          {
            label: "Node (export default)",
            title: "api/hdd-lock.js  (new file)",
            code: esmCode,
            hint: "Create the new file api/hdd-lock.js and paste the code. Then in your handler add: import { lock } from \"./hdd-lock.js\"; and change export default async (req, res) => { ... } into export default lock(async (req, res) => { ... });",
            tree: "your-project/\n├─ api/\n│  ├─ index.js      ← add the import and wrap the export\n│  └─ hdd-lock.js   ← NEW file: paste the code here\n└─ package.json",
          },
          {
            label: "Next.js",
            title: "middleware.ts  (new file)",
            code: nextCode,
            hint: "Create the new file middleware.ts in the project root, next to package.json (not inside app/ or pages/), and paste the code.",
            tree: "your-project/\n├─ app/  (or pages/)\n├─ middleware.ts   ← NEW file: paste the code here\n└─ package.json",
          },
        ].filter(function (option) {
          return option.code.length > 1;
        });
        const choice = elem("div", "btn-group");
        choice.setAttribute("role", "group");
        choice.setAttribute("aria-label", "How is your Vercel app written?");
        const buttons = options.map(function (option) {
          const button = elem("button", "btn", option.label);
          button.type = "button";
          choice.appendChild(button);
          return button;
        });
        const codeHolder = elem("div");
        const showOption = function (index) {
          buttons.forEach(function (button, i) {
            button.setAttribute("aria-pressed", i === index ? "true" : "false");
          });
          const option = options[index];
          clear(codeHolder);
          codeHolder.appendChild(elem("p", "hint", option.hint));
          codeHolder.appendChild(elem("pre", "tree", option.tree));
          codeHolder.appendChild(copyBlock(option.title, option.code, "The lock code", true));
        };
        buttons.forEach(function (button, i) {
          button.addEventListener("click", function () {
            showOption(i);
          });
        });
        two.appendChild(codeHolder);
        // The common case is shown by default; the other ways of writing an app are one click away.
        const other = elem("details");
        other.appendChild(elem("summary", null, "My app is written differently (export default, or Next.js)"));
        other.appendChild(choice);
        two.appendChild(other);
        if (options.length > 0) {
          showOption(0);
        }
      }
      steps.appendChild(two);
      const three = elem("li");
      three.appendChild(elem("strong", null, "Allow HDD to reach the app"));
      three.appendChild(elem("p", "hint", "Vercel → Settings → Deployment Protection → turn Vercel Authentication off for Production."));
      steps.appendChild(three);
      const four = elem("li");
      four.appendChild(elem("strong", null, "Redeploy"));
      four.appendChild(elem("p", "hint", "Deploy again so the variable and the lock go live."));
      steps.appendChild(four);
      guide.appendChild(steps);
      const checkRow = elem("div", "form-actions");
      const check = elem("button", "btn primary", "Check lockdown");
      check.type = "button";
      const result = elem("div");
      check.addEventListener("click", function () {
        check.disabled = true;
        check.textContent = "Checking…";
        clear(result);
        api("/api/sites/" + encodeURIComponent(createdSite.host) + "/lockdown-check", { method: "POST", body: {} })
          .then(function (outcome) {
            const alert = elem("div", "alert " + (outcome.protected ? "ok" : "warn"));
            alert.appendChild(elem("strong", null, outcome.protected ? "Lockdown holds" : "Not locked down yet"));
            alert.appendChild(elem("p", null, outcome.detail || ""));
            result.appendChild(alert);
          })
          .catch(function (apiError) {
            result.appendChild(elem("p", "alert error", apiError.message));
          })
          .then(function () {
            check.disabled = false;
            check.textContent = "Check lockdown";
          });
      });
      checkRow.appendChild(check);
      guide.appendChild(checkRow);
      guide.appendChild(result);
      return guide;
    }
    function stepTwo() {
      clear(content);
      const heading = elem("h2", null, "Step 2 of 3 · connect and lock down " + createdSite.host);
      heading.id = "wizard-title";
      content.appendChild(elem("p", "progress", "Step 2 of 3 · connection instructions and origin lockdown"));
      content.appendChild(heading);
      content.appendChild(
        elem(
          "p",
          "dialog-lead",
          "Copy these steps into your own DNS, Cloudflare, nginx or Vercel configuration. The origin must be locked down before the site can honestly be called protected."
        )
      );
      const instructionsBox = elem("div");
      if (generatedSecret) {
        content.appendChild(vercelGuide());
        const more = elem("details");
        more.appendChild(elem("summary", null, "Show the full generated instructions"));
        more.appendChild(instructionsBox);
        content.appendChild(more);
      } else {
        content.appendChild(instructionsBox);
      }
      renderInstructions(instructionsBox, instructions, createdSite);
      const actions = elem("div", "dialog-actions");
      const later = elem("button", "btn", "Finish later");
      later.type = "button";
      later.addEventListener("click", closeWizard);
      const next = elem("button", "btn primary", "Continue to verification");
      next.type = "button";
      next.addEventListener("click", stepThree);
      append(actions, later, next);
      content.appendChild(actions);
    }
    function stepThree() {
      clear(content);
      const heading = elem("h2", null, "Step 3 of 3 · verify protection for " + createdSite.host);
      heading.id = "wizard-title";
      content.appendChild(elem("p", "progress", "Step 3 of 3 · verify protection"));
      content.appendChild(heading);
      content.appendChild(
        elem(
          "p",
          "dialog-lead",
          "Verification sends at most two inert requests, only to the site you just registered: one benign request and the documented test payload through the public domain. Type the host name to confirm you own it."
        )
      );
      const form = elem("form", "stack");
      const confirmation = elem("input");
      confirmation.type = "text";
      confirmation.autocomplete = "off";
      confirmation.spellcheck = false;
      confirmation.placeholder = createdSite.host;
      const error = elem("p", "field-error");
      error.setAttribute("role", "alert");
      error.hidden = true;
      append(form, labelFor("Type " + createdSite.host + " to confirm", confirmation), error);
      const actions = elem("div", "dialog-actions");
      const later = elem("button", "btn", "Finish later");
      later.type = "button";
      later.addEventListener("click", closeWizard);
      const verify = elem("button", "btn primary", "Verify protection");
      verify.type = "submit";
      verify.disabled = true;
      append(actions, later, verify);
      form.appendChild(actions);
      const output = elem("div");
      form.appendChild(output);
      confirmation.addEventListener("input", function () {
        verify.disabled = confirmation.value.trim() !== createdSite.host;
      });
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        error.hidden = true;
        verify.disabled = true;
        verify.textContent = "Verifying…";
        clear(output);
        api("/api/sites/" + encodeURIComponent(createdSite.host) + "/verify", {
          method: "POST",
          body: { confirmation: confirmation.value.trim() },
        })
          .then(function (verification) {
            const alert = elem("div", "alert " + (verification.protected ? "ok" : "warn"));
            alert.appendChild(elem("p", null, verification.protected ? "Protection verified." : "Not protected yet."));
            alert.appendChild(elem("p", null, verification.summary || ""));
            if (verification.ray_id) {
              alert.appendChild(elem("p", "mono", "Blocked probe Ray ID: " + verification.ray_id));
            }
            const list = elem("ul", "checklist");
            (verification.checks || []).forEach(function (check) {
              list.appendChild(elem("li", null, check.status + " · " + check.name + " — " + check.detail));
            });
            alert.appendChild(list);
            output.appendChild(alert);
            verify.textContent = "Verify again";
            verify.disabled = confirmation.value.trim() !== createdSite.host;
            if (!verification.protected) {
              const blockFailed = (verification.checks || []).some(function (check) {
                return check.name === "block_probe" && check.status !== "PASS";
              });
              if (blockFailed && createdSite.mode !== "block") {
                // A new site starts in monitor mode, which only records attacks, so the test payload is not blocked.
                const fix = elem("div", "alert info");
                fix.appendChild(
                  elem(
                    "p",
                    null,
                    "This site is in " + createdSite.mode + " mode, which lets attacks through and only records them. Switch it to Block mode to refuse attacks."
                  )
                );
                const switchButton = elem("button", "btn primary", "Switch to Block mode and verify again");
                switchButton.type = "button";
                switchButton.addEventListener("click", function () {
                  switchButton.disabled = true;
                  switchButton.textContent = "Switching…";
                  api("/api/sites/" + encodeURIComponent(createdSite.host) + "/mode", { method: "POST", body: { mode: "block" } })
                    .then(function () {
                      createdSite.mode = "block";
                      form.requestSubmit();
                    })
                    .catch(function (apiError) {
                      switchButton.disabled = false;
                      switchButton.textContent = "Switch to Block mode and verify again";
                      error.textContent = apiError.message;
                      error.hidden = false;
                    });
                });
                fix.appendChild(switchButton);
                output.appendChild(fix);
              }
              output.appendChild(
                elem(
                  "p",
                  "preview-note",
                  "The site stays not protected until the failing checks pass or a typed, audited risk acceptance is recorded. HDD does not present it as protected."
                )
              );
            }
          })
          .catch(function (apiError) {
            error.textContent = apiError.message;
            error.hidden = false;
            verify.disabled = false;
            verify.textContent = "Verify protection";
          });
      });
      content.appendChild(form);
      confirmation.focus();
    }
    stepOne();
  }

  // ---------------------------------------------------------------- test console

  async function loadConsole() {
    const response = await api("/api/sites");
    state.sites = (response && response.sites) || [];
    const select = $("inspect-site");
    const previous = select.value;
    clear(select);
    const defaultOption = elem("option", null, "Default (balanced strictness)");
    defaultOption.value = "";
    select.appendChild(defaultOption);
    state.sites.forEach(function (site) {
      const option = elem("option", null, site.host + " (" + site.strictness + ")");
      option.value = site.host;
      if (site.host === previous) {
        option.selected = true;
      }
      select.appendChild(option);
    });
  }

  function renderInspectResult(payload) {
    const box = $("inspect-result");
    clear(box);
    box.hidden = false;
    $("inspect-empty").hidden = true;
    const verdict = payload.verdict || {};
    const blocked = verdict.action === "block";
    const alert = elem("div", "alert " + (blocked ? "warn" : "ok"));
    alert.appendChild(elem("p", null, blocked ? "Verdict: BLOCK — this payload matches the SQL-injection detector." : "Verdict: ALLOW — no rule family matched this payload."));
    const dl = elem("dl", "dl");
    dd(dl, "Action", actionChip(verdict.action || "allow"));
    dd(dl, "Category", verdict.category || "—");
    dd(dl, "Rule family", verdict.subtype || "—");
    dd(dl, "Rule ID", verdict.rule_id || "—");
    dd(dl, "Vector", verdict.vector || "—");
    dd(dl, "Field", verdict.field || "—");
    dd(dl, "Field kind", verdict.field_kind || "—");
    dd(dl, "Score", String(verdict.score === undefined ? "—" : verdict.score));
    dd(dl, "Evidence (redacted)", verdict.evidence || "—");
    dd(dl, "Truncated input", verdict.truncated ? "yes — only the first bytes were inspected" : "no");
    dd(dl, "Normalised value", payload.normalized || "—");
    alert.appendChild(dl);
    alert.appendChild(elem("p", "preview-note", "This ran the detector only: nothing was sent to a site and no ban was created."));
    box.appendChild(alert);
  }

  function initConsole() {
    bindConsoleForm();
    return loadConsole();
  }

  const CONSOLE_EXAMPLES = [
    ["Login bypass", "' OR 1=1--"],
    ["Quote match", "' OR '1'='1"],
    ["Comment", "admin' --"],
    ["Hash comment", "admin' #"],
    ["Block comment", "admin'/*"],
    ["LIMIT", "' or 1=1 LIMIT 1 --"],
    ["UNION", "' UNION SELECT username,password FROM users--"],
    ["Normal name", "O'Brien"],
  ];

  function renderConsoleExamples() {
    const box = $("inspect-examples");
    clear(box);
    box.appendChild(elem("span", "label", "Try an example"));
    CONSOLE_EXAMPLES.forEach(function (example) {
      const button = elem("button", "btn small", example[0]);
      button.type = "button";
      button.title = example[1];
      button.addEventListener("click", function () {
        const field = $("inspect-payload");
        field.value = example[1];
        field.focus();
      });
      box.appendChild(button);
    });
  }

  function bindConsoleForm() {
    const form = $("inspect-form");
    if (form.dataset.bound === "true") {
      return;
    }
    form.dataset.bound = "true";
    renderConsoleExamples();
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      const payload = $("inspect-payload").value;
      setFieldError("inspect-validation", "");
      if (payload.length === 0) {
        setFieldError("inspect-validation", "Enter a payload to inspect.");
        $("inspect-payload").focus();
        return;
      }
      const body = {
        payload: payload,
        field_kind: $("inspect-kind").value || null,
        vector: $("inspect-vector").value || "query",
        site: $("inspect-site").value || null,
      };
      api("/api/inspect", { method: "POST", body: body })
        .then(renderInspectResult)
        .catch(function (error) {
          setFieldError("inspect-validation", error.message);
        });
    });
  }

  // ---------------------------------------------------------------- block page preview

  async function loadBlockPreview() {
    try {
      const payload = await api("/api/block-preview");
      const frame = $("block-preview-frame");
      if (!payload || typeof payload.html !== "string") {
        throw new Error("The block page preview API returned no HTML.");
      }
      frame.setAttribute("srcdoc", payload.html);
      frame.hidden = false;
      $("block-preview-empty").hidden = true;
      $("block-preview-meta").textContent =
        "Preview uses a sample Ray ID in the real format: " + (payload.ray_id || "—") + ". A real blocked request shows its own Ray ID.";
    } catch (error) {
      $("block-preview-frame").hidden = true;
      $("block-preview-empty").hidden = false;
      $("block-preview-meta").textContent = "Preview unavailable: " + error.message;
    }
  }

  // ---------------------------------------------------------------- account

  function renderAccount() {
    const account = state.account;
    const profile = $("account-profile");
    clear(profile);
    if (!account) {
      profile.appendChild(elem("p", "preview-note", "The account API returned no data."));
      return;
    }
    const dl = elem("dl", "dl");
    dd(dl, "Username", account.username);
    dd(dl, "Email", account.email);
    dd(dl, "Role", account.role);
    dd(dl, "Created", fmtTime(account.created_at));
    profile.appendChild(dl);
    const sessionsBody = $("sessions-body");
    clear(sessionsBody);
    setEmptyHeading($("sessions-empty"), EMPTY_STATES.sessions);
    const sessions = account.sessions || [];
    $("sessions-empty").hidden = sessions.length > 0;
    $("sessions-table").hidden = sessions.length === 0;
    sessions.forEach(function (session) {
      const row = elem("tr");
      row.appendChild(elem("td", "nowrap", fmtTime(session.created_at)));
      row.appendChild(elem("td", "nowrap", fmtTime(session.last_seen_at)));
      row.appendChild(elem("td", "mono", session.ip));
      const currentCell = elem("td");
      currentCell.appendChild(session.current ? chip("this session", "ok") : chip("other", "muted"));
      row.appendChild(currentCell);
      const actions = elem("td");
      if (!session.current) {
        const revoke = elem("button", "btn small danger", "Revoke");
        revoke.type = "button";
        revoke.setAttribute("aria-label", "Revoke session created " + session.created_at);
        revoke.addEventListener("click", function () {
          api("/api/account/sessions/" + encodeURIComponent(session.id) + "/delete", { method: "POST", body: {} })
            .then(function () {
              setStatus("Session revoked.");
              return loadAccount();
            })
            .catch(function (error) {
              showError(error.message);
            });
        });
        actions.appendChild(revoke);
      } else {
        actions.appendChild(elem("span", "preview-note", "current"));
      }
      row.appendChild(actions);
      sessionsBody.appendChild(row);
    });
    const tokensBody = $("tokens-body");
    clear(tokensBody);
    setEmptyHeading($("tokens-empty"), EMPTY_STATES.tokens);
    const tokens = account.tokens || [];
    $("tokens-empty").hidden = tokens.length > 0;
    $("tokens-table").hidden = tokens.length === 0;
    tokens.forEach(function (token) {
      const row = elem("tr");
      row.appendChild(elem("td", null, token.name));
      row.appendChild(elem("td", "nowrap", fmtTime(token.created_at)));
      row.appendChild(elem("td", "nowrap", token.last_used_at ? fmtTime(token.last_used_at) : "never used"));
      const actions = elem("td");
      const revoke = elem("button", "btn small danger", "Revoke");
      revoke.type = "button";
      revoke.addEventListener("click", function () {
        api("/api/account/tokens/" + encodeURIComponent(token.id) + "/delete", { method: "POST", body: {} })
          .then(function () {
            setStatus("API token revoked.");
            return loadAccount();
          })
          .catch(function (error) {
            showError(error.message);
          });
      });
      actions.appendChild(revoke);
      row.appendChild(actions);
      tokensBody.appendChild(row);
    });
  }

  async function loadAccount() {
    state.account = await api("/api/account");
    renderAccount();
    bindAccountForms();
  }

  function bindAccountForms() {
    const emailForm = $("email-form");
    if (emailForm.dataset.bound !== "true") {
      emailForm.dataset.bound = "true";
      emailForm.addEventListener("submit", function (event) {
        event.preventDefault();
        setFieldError("email-error", "");
        const email = $("email-new").value.trim();
        if (email.indexOf("@") < 1) {
          setFieldError("email-error", "Enter a valid email address.");
          return;
        }
        api("/api/account/email", {
          method: "POST",
          body: { password: $("email-password").value, email: email },
        })
          .then(function () {
            $("email-form").reset();
            setStatus("Email changed.");
            return loadAccount();
          })
          .catch(function (error) {
            setFieldError("email-error", error.message);
          });
      });
    }
    const passwordForm = $("password-form");
    if (passwordForm.dataset.bound !== "true") {
      passwordForm.dataset.bound = "true";
      passwordForm.addEventListener("submit", function (event) {
        event.preventDefault();
        setFieldError("password-error", "");
        const next = $("password-new").value;
        const confirmation = $("password-confirm").value;
        if (next.length < 12) {
          setFieldError("password-error", "The new password must be at least 12 characters.");
          return;
        }
        if (next !== confirmation) {
          setFieldError("password-error", "The new password confirmation does not match.");
          return;
        }
        api("/api/account/password", {
          method: "POST",
          body: { current_password: $("password-current").value, new_password: next },
        })
          .then(function () {
            passwordForm.reset();
            setStatus("Password changed.");
          })
          .catch(function (error) {
            setFieldError("password-error", error.message);
          });
      });
    }
    const tokenForm = $("token-form");
    if (tokenForm.dataset.bound !== "true") {
      tokenForm.dataset.bound = "true";
      tokenForm.addEventListener("submit", function (event) {
        event.preventDefault();
        setFieldError("token-error", "");
        const name = $("token-name").value.trim();
        if (name.length === 0) {
          setFieldError("token-error", "Give the token a label so you can recognise it later.");
          return;
        }
        api("/api/account/tokens", { method: "POST", body: { name: name } })
          .then(function (created) {
            tokenForm.reset();
            infoDialog({
              title: "API token created",
              lead: "Copy the token now: it is shown once and only its hash is stored. Any script holding it acts with your role's permissions.",
              value: created.token,
              notes: ["The token value is never displayed again.", "Revoke it here or from the Account screen if it leaks."],
            }).then(function () {
              return loadAccount();
            });
          })
          .catch(function (error) {
            setFieldError("token-error", error.message);
          });
      });
    }
  }

  // ---------------------------------------------------------------- users

  async function loadUsers() {
    if (!isOwner()) {
      const body = $("users-body");
      clear(body);
      $("users-empty").hidden = false;
      $("users-table").hidden = true;
      $("add-user-card").hidden = true;
      showError("The Users screen is owner-only. Your viewer role is read-only.");
      return;
    }
    $("add-user-card").hidden = false;
    const response = await api("/api/users");
    const users = (response && response.users) || [];
    const body = $("users-body");
    clear(body);
    $("users-empty").hidden = users.length > 0;
    $("users-table").hidden = users.length === 0;
    users.forEach(function (user) {
      const row = elem("tr");
      row.appendChild(elem("td", "mono", user.username));
      row.appendChild(elem("td", null, user.email));
      const roleCell = elem("td");
      roleCell.appendChild(chip(user.role, user.role === "owner" ? "ok" : "muted"));
      row.appendChild(roleCell);
      row.appendChild(elem("td", "nowrap", fmtTime(user.created_at)));
      const actions = elem("td");
      const group = elem("div", "btn-group");
      const roleButton = elem("button", "btn small", user.role === "owner" ? "Make viewer" : "Make owner");
      roleButton.type = "button";
      roleButton.addEventListener("click", function () {
        api("/api/users/" + encodeURIComponent(user.id) + "/role", {
          method: "POST",
          body: { role: user.role === "owner" ? "viewer" : "owner" },
        })
          .then(function () {
            setStatus("Role updated for " + user.username + ".");
            return loadUsers();
          })
          .catch(function (error) {
            showError(error.message);
          });
      });
      const remove = elem("button", "btn small danger", "Remove");
      remove.type = "button";
      remove.addEventListener("click", function () {
        confirmDialog({
          title: "Remove user " + user.username + "?",
          lead: "The account is deleted and its sessions stop working immediately. The last owner cannot be removed.",
          fieldLabel: "Type " + user.username + " to confirm",
          expected: user.username,
          confirmLabel: "Remove user",
          danger: true,
        }).then(function (answer) {
          if (answer === null) {
            return;
          }
          return api("/api/users/" + encodeURIComponent(user.id) + "/delete", { method: "POST", body: { confirmation: answer } }).then(function () {
            setStatus("User " + user.username + " removed.");
            return loadUsers();
          });
        }).catch(function (error) {
          showError(error.message);
        });
      });
      append(group, roleButton, remove);
      actions.appendChild(group);
      row.appendChild(actions);
      body.appendChild(row);
    });
    const form = $("user-form");
    if (form.dataset.bound !== "true") {
      form.dataset.bound = "true";
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        setFieldError("user-error", "");
        const username = $("user-username").value.trim();
        const email = $("user-email").value.trim();
        const password = $("user-password").value;
        if (username.length < 3) {
          setFieldError("user-error", "The username must be at least 3 characters.");
          return;
        }
        if (email.indexOf("@") < 1) {
          setFieldError("user-error", "Enter a valid email address.");
          return;
        }
        if (password.length < 12) {
          setFieldError("user-error", "The initial password must be at least 12 characters.");
          return;
        }
        api("/api/users", {
          method: "POST",
          body: { username: username, email: email, password: password, role: $("user-role").value },
        })
          .then(function () {
            form.reset();
            setStatus("User " + username + " added.");
            return loadUsers();
          })
          .catch(function (error) {
            setFieldError("user-error", error.message);
          });
      });
    }
  }

  // ---------------------------------------------------------------- about

  async function loadAbout() {
    const container = $("about-health");
    clear(container);
    try {
      const health = await api("/healthz");
      const dl = elem("dl", "dl");
      dd(dl, "Status", health.status);
      dd(dl, "Version", health.version);
      dd(dl, "Uptime", fmtSeconds(health.uptime_seconds));
      dd(dl, "Configured sites", String(health.sites));
      dd(dl, "Owner account exists", health.accounts_ready ? "yes" : "no — first-run setup is still open");
      container.appendChild(dl);
    } catch (error) {
      container.appendChild(elem("p", "alert error", "Health endpoint unavailable: " + error.message));
    }
  }

  // ---------------------------------------------------------------- session and boot

  function renderSession() {
    const me = state.me;
    $("session-name").textContent = me ? me.username : "";
    const roleChip = $("session-role");
    roleChip.textContent = me ? me.role : "";
    roleChip.className = "chip " + (me && me.role === "owner" ? "ok" : "muted");
    const ownerOnly = document.querySelectorAll("[data-owner-only]");
    for (let index = 0; index < ownerOnly.length; index += 1) {
      ownerOnly[index].hidden = !isOwner();
    }
  }

  async function boot() {
    try {
      const status = await api("/api/setup-status");
      if (status && status.setup_required) {
        window.location.assign("/setup");
        return;
      }
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      showError(error.message);
      return;
    }
    try {
      state.me = await api("/api/me");
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      showError(error.message);
      return;
    }
    renderSession();
    $("logout-btn").addEventListener("click", function () {
      api("/api/logout", { method: "POST", body: {} })
        .catch(function () {
          return null;
        })
        .then(function () {
          goToLogin();
        });
    });
    $("add-site-btn").addEventListener("click", openAddSiteWizard);
    $("events-refresh").addEventListener("click", function () {
      loadEvents().catch(function (error) {
        showError(error.message);
      });
    });
    bindUnblockForm();
    $("bans-refresh").addEventListener("click", function () {
      loadBans().catch(function (error) {
        showError(error.message);
      });
    });
    $("sites-refresh").addEventListener("click", function () {
      loadSites().catch(function (error) {
        showError(error.message);
      });
    });
    $("block-preview-refresh").addEventListener("click", function () {
      loadBlockPreview().catch(function (error) {
        showError(error.message);
      });
    });
    $("event-site").addEventListener("change", renderEvents);
    $("event-action").addEventListener("change", renderEvents);
    $("event-search").addEventListener("input", renderEvents);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden && currentRoute() === "overview") {
        refreshLive();
      }
    });
    window.addEventListener("hashchange", showRoute);
    showRoute();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
