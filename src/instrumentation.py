"""
Runtime DOM/JS Instrumentation Layer (extends spec Component 6).

The existing browser_controller wires Playwright-level events (console,
request, response, download, dialog, framenavigated). Those cover network
and browser-chrome level behavior but miss everything that happens INSIDE
the page's own JS execution: dynamically injected <script>/<iframe> tags,
window.open() popups, localStorage/sessionStorage/IndexedDB writes,
clipboard access, permission-prompt requests, and credential-form submits.

This module is injected once per page/context via add_init_script(), so it
runs before any site script executes. It reports structured events back to
Python through an exposed binding (`__reportRuntimeEvent`) rather than
polling — keeps the hot path lightweight and avoids missing bursts of
activity between polls.

Values are truncated/length-only where they could contain attacker-supplied
sensitive-looking strings (e.g. storage payloads) — we log characteristics,
not content, to keep telemetry safe to store/share.
"""

INSTRUMENTATION_JS = r"""
(() => {
  if (window.__deceptionInstrumented) return;
  window.__deceptionInstrumented = true;

  const report = (type, detail) => {
    try {
      if (window.__reportRuntimeEvent) {
        window.__reportRuntimeEvent(JSON.stringify({ type, detail, url: location.href, ts: Date.now() }));
      }
    } catch (e) { /* never let instrumentation break the page */ }
  };

  // ── dynamic script / iframe injection (createElement hook) ──────────────
  const origCreateElement = Document.prototype.createElement;
  Document.prototype.createElement = function (tagName, ...rest) {
    const el = origCreateElement.call(this, tagName, ...rest);
    const tag = String(tagName).toLowerCase();
    if (tag === "script" || tag === "iframe") {
      report(tag === "script" ? "dynamic_script_injection" : "dynamic_iframe_injection",
             { tag });
    }
    return el;
  };

  // ── MutationObserver — catches injection via innerHTML / append too ─────
  try {
    const mo = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          const tag = node.tagName ? node.tagName.toLowerCase() : "";
          if (tag === "script") {
            report("dynamic_script_injection", { via: "mutation", src: (node.src || "").slice(0, 200) });
          } else if (tag === "iframe") {
            report("dynamic_iframe_injection", { via: "mutation", src: (node.src || "").slice(0, 200) });
          }
        }
      }
    });
    // Observer target may not exist yet at document_start; retry once DOM is ready.
    const attach = () => {
      if (document.documentElement) {
        mo.observe(document.documentElement, { childList: true, subtree: true });
      } else {
        setTimeout(attach, 50);
      }
    };
    attach();
  } catch (e) {}

  // ── popups / new tabs ─────────────────────────────────────────────────
  let popupCount = 0;
  const origOpen = window.open;
  window.open = function (url, ...rest) {
    popupCount += 1;
    report(popupCount > 2 ? "popup_spam" : "new_tab_abuse",
           { url: String(url || "").slice(0, 200), count: popupCount });
    return origOpen.call(window, url, ...rest);
  };

  // ── storage write monitoring (length/shape only, not full content) ─────
  const wrapStorage = (storage, label) => {
    if (!storage) return;
    const origSetItem = storage.setItem.bind(storage);
    storage.setItem = function (key, value) {
      const len = value ? String(value).length : 0;
      if (len > 4000) {
        report("storage_exfil_write", { store: label, key: String(key).slice(0, 100), length: len });
      }
      return origSetItem(key, value);
    };
  };
  try { wrapStorage(window.localStorage, "localStorage"); } catch (e) {}
  try { wrapStorage(window.sessionStorage, "sessionStorage"); } catch (e) {}

  // ── IndexedDB open ──────────────────────────────────────────────────────
  try {
    const origIDBOpen = indexedDB.open.bind(indexedDB);
    indexedDB.open = function (name, ...rest) {
      report("indexeddb_write", { db: String(name).slice(0, 100) });
      return origIDBOpen(name, ...rest);
    };
  } catch (e) {}

  // ── clipboard access ────────────────────────────────────────────────────
  try {
    if (navigator.clipboard) {
      if (navigator.clipboard.writeText) {
        const origWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = function (text) {
          report("clipboard_write_runtime", { length: (text || "").length });
          return origWrite(text);
        };
      }
      if (navigator.clipboard.readText) {
        const origRead = navigator.clipboard.readText.bind(navigator.clipboard);
        navigator.clipboard.readText = function () {
          report("clipboard_read_runtime", {});
          return origRead();
        };
      }
    }
    const origExec = document.execCommand ? document.execCommand.bind(document) : null;
    if (origExec) {
      document.execCommand = function (cmd, ...rest) {
        if (String(cmd).toLowerCase() === "copy") report("clipboard_write_runtime", { via: "execCommand" });
        if (String(cmd).toLowerCase() === "paste") report("clipboard_read_runtime", { via: "execCommand" });
        return origExec(cmd, ...rest);
      };
    }
  } catch (e) {}

  // ── permission prompts (notifications, geolocation, etc.) ──────────────
  try {
    if (window.Notification && Notification.requestPermission) {
      const origPerm = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function (...args) {
        report("permission_request_suspicious", { api: "Notification" });
        return origPerm(...args);
      };
    }
    if (navigator.permissions && navigator.permissions.query) {
      const origQuery = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function (opts) {
        report("permission_request_suspicious", { api: "permissions.query", name: opts && opts.name });
        return origQuery(opts);
      };
    }
    if (navigator.geolocation && navigator.geolocation.getCurrentPosition) {
      const origGeo = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
      navigator.geolocation.getCurrentPosition = function (...args) {
        report("permission_request_suspicious", { api: "geolocation" });
        return origGeo(...args);
      };
    }
  } catch (e) {}

  // ── service worker registration (persistence mechanism) ────────────────
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      const origReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = function (scriptURL, ...rest) {
        report("service_worker_registration", { script: String(scriptURL).slice(0, 200) });
        return origReg(scriptURL, ...rest);
      };
    }
  } catch (e) {}

  // ── form submissions — field NAMES only, never values ───────────────────
  document.addEventListener("submit", (ev) => {
    try {
      const form = ev.target;
      if (!(form && form.elements)) return;
      const fieldNames = Array.from(form.elements)
        .map(el => (el.name || el.id || "").toLowerCase())
        .filter(Boolean);
      const credLike = fieldNames.some(n =>
        /pass|pwd|ssn|card|cvv|routing|pin|secret|token/i.test(n));
      if (credLike) {
        report("form_submit_credentials", { fields: fieldNames.slice(0, 20) });
      }
    } catch (e) {}
  }, true);
})();
"""
