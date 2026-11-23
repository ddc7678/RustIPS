// RustIPS UI behaviour: theme toggle, confirmations and 2 s live updates.
// Loaded as an external script so the Content-Security-Policy can forbid
// inline code entirely.
(function () {
  "use strict";

  var root = document.documentElement;
  // The saved theme is applied by /assets/theme.js in <head> before paint.

  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var current = root.dataset.theme;
      if (!current) {
        current = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark";
      }
      var next = current === "light" ? "dark" : "light";
      root.dataset.theme = next;
      try {
        localStorage.setItem("rustips-theme", next);
      } catch (_) {}
    });
  }

  // Remember which navigation groups the operator collapsed. The group that
  // contains the current page always starts open so its active link is visible.
  Array.prototype.forEach.call(document.querySelectorAll(".nav-group"), function (group) {
    var summary = group.querySelector(".nav-head");
    var key = "rustips-nav-" + (summary ? summary.textContent.trim() : "group");
    var stored = null;
    try {
      stored = localStorage.getItem(key);
    } catch (_) {}
    if (stored === "closed" && !group.querySelector("a.active")) {
      group.open = false;
    }
    group.addEventListener("toggle", function () {
      try {
        localStorage.setItem(key, group.open ? "open" : "closed");
      } catch (_) {}
    });
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (form && form.dataset && form.dataset.confirm) {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    }
  });

  function fmt(n) {
    if (n === null || n === undefined) return "—";
    return Number(n).toLocaleString();
  }

  function bytes(n) {
    var units = ["B", "KiB", "MiB", "GiB"];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i += 1;
    }
    return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i];
  }

  function uptime(secs) {
    var d = Math.floor(secs / 86400);
    var h = Math.floor((secs % 86400) / 3600);
    var m = Math.floor((secs % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return m + "m";
  }

  function field(name, value) {
    var nodes = document.querySelectorAll('[data-field="' + name + '"]');
    for (var i = 0; i < nodes.length; i += 1) {
      nodes[i].textContent = value;
    }
  }

  function stamp(iso) {
    if (!iso) return "";
    return iso.replace("T", " ").slice(0, 19);
  }

  function cell(row, text, className) {
    var td = document.createElement("td");
    if (className) td.className = className;
    td.textContent = text === null || text === undefined ? "" : String(text);
    return td;
  }

  function countryBadge(country) {
    if (!country) return null;
    var badge = document.createElement("span");
    badge.className = "tag country-tag country-" + country;
    badge.textContent = country;
    return badge;
  }

  function appendCountry(parent, country) {
    var badge = countryBadge(country);
    if (!badge) return;
    parent.appendChild(document.createTextNode(" "));
    parent.appendChild(badge);
  }

  function ipCell(ip, country) {
    var td = document.createElement("td");
    td.className = "mono";
    if (ip && ip !== "0.0.0.0") {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "ip-link";
      button.dataset.ip = ip;
      button.textContent = ip;
      td.appendChild(button);
      appendCountry(td, country);
    } else {
      td.textContent = ip || "—";
    }
    return td;
  }

  function renderRecent(rows) {
    var body = document.getElementById("recent-detections");
    if (!body) return;
    body.textContent = "";
    (rows || []).forEach(function (r) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(tr, stamp(r.first_seen), "mono"));
      var detector = document.createElement("td");
      var tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = r.detector;
      detector.appendChild(tag);
      detector.appendChild(document.createTextNode(" " + (r.detector_title || "")));
      tr.appendChild(detector);
      tr.appendChild(ipCell(r.src, r.country));
      tr.appendChild(cell(tr, r.dst ? r.dst + (r.dst_port ? ":" + r.dst_port : "") : "—", "mono"));
      tr.appendChild(cell(tr, r.count));
      body.appendChild(tr);
    });
  }

  function renderRank(id, rows) {
    var list = document.getElementById(id);
    if (!list) return;
    list.textContent = "";
    (rows || []).forEach(function (r) {
      var li = document.createElement("li");
      var left = document.createElement("span");
      left.className = "mono";
      if (id === "top-sources" && r[0] && r[0] !== "0.0.0.0") {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "ip-link";
        button.dataset.ip = r[0];
        button.textContent = r[0];
        left.appendChild(button);
        appendCountry(left, r[2]);
      } else {
        left.textContent = r[0];
      }
      var right = document.createElement("span");
      right.className = "num";
      right.textContent = fmt(r[1]);
      li.appendChild(left);
      li.appendChild(right);
      list.appendChild(li);
    });
  }

  // Per-IP history dialog. Any element with data-ip opens it; the fragment is
  // rendered server-side with all stored history for that address.
  var ipDialog = document.getElementById("ip-dialog");
  if (ipDialog) {
    var ipBody = document.getElementById("ip-dialog-body");
    document.addEventListener("click", function (event) {
      var trigger = event.target.closest ? event.target.closest("[data-ip]") : null;
      if (!trigger) return;
      var ip = trigger.getAttribute("data-ip");
      if (!ip) return;
      event.preventDefault();
      if (ipBody) ipBody.textContent = "Loading…";
      if (typeof ipDialog.showModal === "function") {
        if (!ipDialog.open) ipDialog.showModal();
      } else {
        ipDialog.setAttribute("open", "");
      }
      fetch("/api/ip?ip=" + encodeURIComponent(ip), {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "text/html" }
      })
        .then(function (response) {
          if (response.redirected && response.url.indexOf("/login") !== -1) {
            throw new Error("session expired; reload and log in");
          }
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.text();
        })
        .then(function (html) {
          if (ipBody) ipBody.innerHTML = html;
        })
        .catch(function (error) {
          if (ipBody) ipBody.textContent = "Could not load IP history: " + error.message;
        });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-ip-close]"), function (button) {
      button.addEventListener("click", function () {
        if (typeof ipDialog.close === "function") ipDialog.close();
        else ipDialog.removeAttribute("open");
      });
    });
    ipDialog.addEventListener("click", function (event) {
      if (event.target === ipDialog && typeof ipDialog.close === "function") {
        ipDialog.close();
      }
    });
  }

  var systemDialog = document.getElementById("system-dialog");
  if (systemDialog) {
    var systemBody = document.getElementById("system-dialog-body");
    document.addEventListener("click", function (event) {
      var trigger = event.target.closest ? event.target.closest("[data-system-dialog]") : null;
      if (!trigger) return;
      event.preventDefault();
      if (systemBody) systemBody.textContent = "Loading…";
      if (typeof systemDialog.showModal === "function") {
        if (!systemDialog.open) systemDialog.showModal();
      } else {
        systemDialog.setAttribute("open", "");
      }
      fetch("/api/system?hours=24", {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "text/html" }
      })
        .then(function (response) {
          if (response.redirected && response.url.indexOf("/login") !== -1) {
            throw new Error("session expired; reload and log in");
          }
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.text();
        })
        .then(function (html) {
          if (systemBody) systemBody.innerHTML = html;
        })
        .catch(function (error) {
          if (systemBody) systemBody.textContent = "Could not load resource history: " + error.message;
        });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-system-close]"), function (button) {
      button.addEventListener("click", function () {
        if (typeof systemDialog.close === "function") systemDialog.close();
        else systemDialog.removeAttribute("open");
      });
    });
    systemDialog.addEventListener("click", function (event) {
      if (event.target === systemDialog && typeof systemDialog.close === "function") {
        systemDialog.close();
      }
    });
  }

  var systemGraphs = document.getElementById("system-graphs");
  if (systemGraphs) {
    window.setInterval(function () {
      fetch("/api/system?hours=1&compact=1", {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "text/html" }
      })
        .then(function (response) {
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.text();
        })
        .then(function (html) {
          systemGraphs.innerHTML = html;
        })
        .catch(function () {});
    }, 30000);
  }

  var body = document.body;
  if (!body || !body.dataset.live) return;

  var previous = null;
  var previousAt = performance.now();

  function poll() {
    fetch("/api/summary", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("http " + response.status);
        return response.json();
      })
      .then(function (s) {
        var now = performance.now();
        var dt = Math.max(0.001, (now - previousAt) / 1000);
        var pps = previous ? Math.max(0, (s.packets - previous.packets) / dt) : 0;
        var bps = previous ? Math.max(0, (s.bytes - previous.bytes) / dt) : 0;
        previous = s;
        previousAt = now;
        field("packets", fmt(s.packets));
        field("bandwidth", bytes(bps) + "/s");
        field("pps", fmt(Math.round(pps)) + " pps");
        field("detections", fmt(s.detections));
        field("detections-run", fmt(s.detections_run));
        field("blocks", fmt(s.blocks));
        field("active-blocks", fmt(s.active_blocks));
        field("det-per-min", fmt(s.detections_last_min));
        field("blocks-per-min", fmt(s.blocks_last_min));
        field("drops", fmt(s.drops));
        field("kernel-packets", fmt(s.kernel_packets));
        field("uptime", uptime(s.uptime_secs));
        renderRecent(s.recent);
        renderRank("top-sources", s.top_sources);
        renderRank("top-ports", s.top_ports);
      })
      .catch(function () {
        // A failed poll is usually an expired session. The next navigation
        // sends the operator back to the login page.
      });
  }

  if (document.getElementById("recent-detections") ||
      document.getElementById("top-sources")) {
    window.setInterval(poll, 2000);
  }

  // Fragment polling keeps the detections and blocks tables current without a
  // page reload (FR-185).
  if (body.dataset.partial) {
    var target = document.getElementById("live-table");
    if (target) {
      window.setInterval(function () {
        if (target.contains(document.activeElement)) return;
        fetch(body.dataset.partial, { credentials: "same-origin", cache: "no-store" })
          .then(function (response) {
            if (!response.ok) throw new Error("http " + response.status);
            return response.text();
          })
          .then(function (html) {
            target.innerHTML = html;
          })
          .catch(function () {});
      }, 2000);
    }
  }
})();
