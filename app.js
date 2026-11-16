"use strict";
(() => {
  // ------------------------------------------------------------------ helpers
  const TABS = [["overview", "Overview"], ["details", "Details"], ["scope", "Scope"], ["findings", "Findings"],
                ["evidence", "Evidence"], ["import", "Import"], ["report", "Report"]];
  const SEVS = ["Critical", "High", "Medium", "Low", "Info"];
  let META = null;
  const $app = document.getElementById("app");

  function add(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k === null || k === undefined || k === false) continue;
      el.append(k.nodeType ? k : document.createTextNode(String(k)));
    }
  }
    const cvssVersion = select([["3.1", "CVSS 3.1"], ["4.0", "CVSS 4.0"]],
      f.cvss_vector.startsWith("CVSS:4.0/") ? "4.0" : "3.1");
    const cvss40Vector = text(f.cvss_vector.startsWith("CVSS:4.0/") ? f.cvss_vector : "",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (["value", "checked", "disabled", "readOnly", "multiple"].includes(k)) el[k] = v;
      else el.setAttribute(k, v === true ? "" : v);
    }
    add(el, kids);
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

  async function api(method, path, body) {
    const opt = { method, headers: { "X-Requested-With": "secreport" }, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(path, opt); } catch (e) { throw new Error("Cannot reach the server. Is it still running?"); }
    const ct = res.headers.get("Content-Type") || "";
    let data = null;
    if (ct.includes("json")) data = await res.json();
    else if (!res.ok) data = { error: await res.text() };
    if (!res.ok) throw new Error((data && data.error) || `Error ${res.status}`);
    return data;
  }
  const get = (p) => api("GET", p);
  const post = (p, b) => api("POST", p, b === undefined ? {} : b);
  const put = (p, b) => api("PUT", p, b);
  const del = (p, b) => api("DELETE", p, b === undefined ? {} : b);

  function toast(msg, bad) {
    const box = document.getElementById("toasts");
    const t = h("div", { class: "toast" + (bad ? " bad" : ""), text: msg, title: "Click to dismiss", onclick: () => t.remove() });
    while (box.children.length >= 3) box.firstChild.remove();
    box.append(t);
    setTimeout(() => t.remove(), bad ? 7000 : 3500);
  }
  const fail = (e) => toast(e.message || String(e), true);

  function dialog({ title, body, buttons = [], wide = false, onClose }) {
    const dlg = h("dialog", { class: wide ? "wide" : "" });
    const close = () => dlg.close();
    const bodyEl = h("div", { class: "dlg-b" }, body);
    const foot = h("div", { class: "dlg-f" });
    const ctl = { el: dlg, close, body: bodyEl };
    for (const b of buttons) {
      const btn = h("button", { class: "btn " + (b.cls || ""), type: "button", text: b.label });
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try { await b.onclick(ctl, btn); } catch (e) { fail(e); } finally { btn.disabled = false; }
      });
      foot.append(btn);
    }
    dlg.append(h("div", { class: "dlg-h" }, h("h2", { text: title }),
      h("button", { class: "btn small", type: "button", "aria-label": "Close", onclick: close, text: "✕" })), bodyEl, foot);
    dlg.addEventListener("close", () => { dlg.remove(); if (onClose) onClose(); });
    document.body.append(dlg);
    dlg.showModal();
    return ctl;
  }

  // form widgets
  const field = (label, input, hint) => h("div", {}, h("label", { text: label }), input,
    hint ? h("div", { class: "muted small", text: hint }) : null);
  const text = (value, ph) => h("input", { type: "text", value: value || "", placeholder: ph || "" });
  const area = (value, tall, ph) => h("textarea", { class: tall ? "tall" : "", value: value || "", placeholder: ph || "" });
  function select(options, value) {
    const s = h("select", {}, options.map(([v, l]) => h("option", { value: v, text: l })));
    s.value = value === undefined ? options[0][0] : value;
    return s;
  }
  const lines = (el) => el.value.split("\n").map((x) => x.trim()).filter(Boolean);
  const listText = (arr) => (arr || []).join("\n");
  const sevBadge = (s) => h("span", { class: "sev " + s, text: s });
  const fmtDate = (iso) => { try { return iso ? new Date(iso).toLocaleString() : ""; } catch (e) { return iso || ""; } };
  const sizeText = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";

  function sevBars(counts) {
    return h("div", {}, SEVS.map((s) => {
      const n = (counts && counts[s]) || 0;
      const max = Math.max(1, ...SEVS.map((x) => (counts && counts[x]) || 0));
      const fill = h("div", { class: "fill " + s });
      fill.style.width = n ? Math.max(4, Math.round(100 * n / max)) + "%" : "0";
      return h("div", { class: "hbar" }, h("span", { text: s }), h("div", { class: "track" }, fill), h("b", { text: n }));
    }));
  }

  // ------------------------------------------------------------------ CVSS 3.1 (mirrors secreport/cvss.py)
  const CV = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 },
    PRU: { N: 0.85, L: 0.62, H: 0.27 }, PRC: { N: 0.85, L: 0.68, H: 0.5 },
    UI: { N: 0.85, R: 0.62 }, CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const CV_FIELDS = [
    ["AV", "Attack vector", [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]]],
    ["AC", "Attack complexity", [["L", "Low"], ["H", "High"]]],
    ["PR", "Privileges required", [["N", "None"], ["L", "Low"], ["H", "High"]]],
    ["UI", "User interaction", [["N", "None"], ["R", "Required"]]],
    ["S", "Scope", [["U", "Unchanged"], ["C", "Changed"]]],
    ["C", "Confidentiality impact", [["H", "High"], ["L", "Low"], ["N", "None"]]],
    ["I", "Integrity impact", [["H", "High"], ["L", "Low"], ["N", "None"]]],
    ["A", "Availability impact", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ];
  function roundup(v) { const i = Math.round(v * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; }
  function cvssScore(m) {
    const ch = m.S === "C";
    const pr = (ch ? CV.PRC : CV.PRU)[m.PR];
    const iss = 1 - (1 - CV.CIA[m.C]) * (1 - CV.CIA[m.I]) * (1 - CV.CIA[m.A]);
    const imp = ch ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const ex = 8.22 * CV.AV[m.AV] * CV.AC[m.AC] * pr * CV.UI[m.UI];
    if (imp <= 0) return 0;
    return ch ? roundup(Math.min(1.08 * (imp + ex), 10)) : roundup(Math.min(imp + ex, 10));
  }
  const cvssSeverity = (s) => s === 0 ? "Info" : s < 4 ? "Low" : s < 7 ? "Medium" : s < 9 ? "High" : "Critical";
  function parseVec(v) {
    const m = {};
    (v || "").split("/").slice(1).forEach((p) => { const [k, x] = p.split(":"); m[k] = x; });
    return m;
  }
  window.SecReport = { cvssScore, parseVec };

  // ------------------------------------------------------------------ router
  let current = null;   // {id, eng, tab}
  async function route() {
    const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    try {
      if (!META) META = await get("/api/meta");
      if (parts[0] === "e" && parts[1]) await showEngagement(parts[1], parts[2] || "overview");
      else await showHome();
    } catch (e) {
      clear($app);
      $app.append(h("div", { class: "note bad" }, e.message),
        h("p", {}, h("a", { href: "#/", text: "Back to all engagements" })));
    }
  }
  window.addEventListener("hashchange", route);

  // ------------------------------------------------------------------ home
  let renderSeq = 0;   // only the newest navigation may draw; stale async renders are dropped
  async function showHome() {
    const seq = ++renderSeq;
    const list = await get("/api/engagements");
    if (seq !== renderSeq) return;
    current = null;
    document.title = "SecReport";
    clear($app);
    const cards = list.map((e) => {
      const bars = h("div", { class: "bars", "aria-hidden": "true" }, SEVS.map((s) => {
        const n = (e.counts_all && e.counts_all[s]) || 0;
        const max = Math.max(1, ...SEVS.map((x) => (e.counts_all && e.counts_all[x]) || 0));
        const b = h("span", { class: n ? "on " + s : "" });
        b.style.height = n ? Math.max(12, Math.round(100 * n / max)) + "%" : "8%";
        return b;
      }));
      const open = () => { location.hash = `#/e/${e.id}`; };
      return h("div", { class: "card click", tabindex: "0", role: "link", onclick: open,
        onkeydown: (ev) => { if (ev.key === "Enter") open(); } },
        h("div", { class: "row between" }, h("b", { text: e.name }), h("span", { class: "badge", text: e.label || e.report_type })),
        h("div", { class: "muted small", text: e.client }),
        h("div", { class: "row between", style: null }, bars,
          h("div", { class: "small" }, h("div", { text: `${e.findings} finding(s)` }),
            h("div", { class: e.drafts ? "badge warn" : "badge ok", text: e.drafts ? `${e.drafts} draft` : "all reviewed" }))),
        h("div", { class: "muted small", text: "Updated " + fmtDate(e.updated_at) }));
    });
    $app.append(
      h("div", { class: "row between" }, h("h1", { text: "Engagements" }),
        h("div", { class: "row" },
          h("button", { class: "btn", onclick: () => compareDialog(list), disabled: list.length < 2, text: "Compare two" }),
          h("button", { class: "btn primary", onclick: newEngagementDialog, text: "+ New engagement" }))),
      h("p", { class: "muted", text: "One place for OSINT, red team, web pentest and bug bounty reports. Only document work you are authorized to do." }),
      list.length ? h("div", { class: "grid cards" }, cards) :
        h("div", { class: "card empty" }, h("h2", { text: "No engagements yet" }),
          h("p", { text: "Create your first engagement. You will record who authorized the work and what is in scope before adding findings." }),
          h("button", { class: "btn primary", onclick: newEngagementDialog, text: "+ New engagement" })));
  }

  function newEngagementDialog() {
    const f = {
      name: text("", "e.g. Acme Q4 web assessment"), client: text("", "Client or program owner"),
      type: select(META.report_types.map((t) => [t.id, t.label]), "webpentest"), tester: text("", "Your name / team"),
      auth: text("", "Contract no., permission letter, or program policy URL"),
      inScope: area("", false, "*.example.test\n10.0.0.0/24"), out: area("", false, "admin.example.test"),
      start: h("input", { type: "date" }), end: h("input", { type: "date" }),
    };
    const body = h("div", {},
      h("div", { class: "note" }, "Scope and authorization come first. Findings can only be added for targets listed as in scope."),
      h("div", { class: "grid two" }, field("Engagement name *", f.name), field("Client / program *", f.client)),
      h("div", { class: "grid two" }, field("Report type", f.type), field("Prepared by", f.tester)),
      field("Authorization reference *", f.auth, "Required before any scope check passes."),
      h("div", { class: "grid two" }, field("In scope (one per line)", f.inScope, "Domains, *.wildcards, IPs or CIDR ranges."),
        field("Out of scope (one per line)", f.out, "Out of scope always wins.")),
      h("div", { class: "grid two" }, field("Start date", f.start), field("End date", f.end)));
    dialog({
      title: "New engagement", body,
      buttons: [{ label: "Cancel", onclick: (c) => c.close() },
        { label: "Create", cls: "primary", onclick: async (c) => {
          const e = await post("/api/engagements", {
            name: f.name.value, client: f.client.value, report_type: f.type.value, tester: f.tester.value,
            scope: { authorization_ref: f.auth.value, in_scope: lines(f.inScope), out_of_scope: lines(f.out),
                     start_date: f.start.value, end_date: f.end.value } });
          c.close(); location.hash = `#/e/${e.id}`; } }],
    });
  }

  function compareDialog(list) {
    const opts = list.map((e) => [e.id, `${e.name} (${e.client})`]);
    const a = select(opts, opts[opts.length > 1 ? 1 : 0][0]), b = select(opts, opts[0][0]);
    const out = h("div");
    dialog({
      title: "Compare original test and retest", wide: true,
      body: h("div", {}, h("div", { class: "grid two" }, field("Earlier (original)", a), field("Later (retest)", b)), out),
      buttons: [{ label: "Close", onclick: (c) => c.close() },
        { label: "Compare", cls: "primary", onclick: async () => {
          const r = await post("/api/diff", { a: a.value, b: b.value });
          clear(out);
          const sect = (title, rows, fmt) => h("div", {}, h("h3", { text: `${title} (${rows.length})` }),
            rows.length ? h("ul", {}, rows.map((x) => h("li", {}, fmt(x)))) : h("div", { class: "muted small", text: "None" }));
          const one = (f) => [sevBadge(f.severity), " ", f.id, " ", f.title];
          out.append(sect("New findings", r.new, one), sect("No longer present", r.resolved, one),
            sect("Marked fixed or verified", r.fixed_status, (p) => one(p.new)),
            sect("Risk accepted", r.accepted, (p) => one(p.new)),
            sect("Still open", r.persisting, (p) => one(p.new)),
            sect("Severity changed", r.severity_changed, (p) => [p.new.title, ": ", p.old.severity, " → ", p.new.severity]));
        } }],
    });
  }

  // ------------------------------------------------------------------ engagement shell
  async function showEngagement(id, tab) {
    const seq = ++renderSeq;
    const eng = await get(`/api/e/${encodeURIComponent(id)}`);
    if (seq !== renderSeq) return;
    current = { id, eng, tab };
    document.title = `${eng.name} - SecReport`;
    clear($app);
    const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, label]) => {
      const extra = k === "findings" ? ` (${eng.findings.length})` : k === "evidence" ? ` (${eng.evidence.length})` : "";
      return h("button", { class: "tab", role: "tab", "aria-selected": String(k === tab), text: label + extra,
        onclick: () => { location.hash = `#/e/${id}/${k}`; } });
    }));
    const panel = h("div", { role: "tabpanel" });
    $app.append(
      h("div", { class: "row between" },
        h("div", {}, h("a", { href: "#/", class: "small", text: "← All engagements" }),
          h("h1", { text: eng.name }), h("div", { class: "muted", text: `${eng.client}  ·  ${eng.label}` })),
        h("div", { class: "row" },
          h("button", { class: "btn small", text: "Start retest copy", onclick: async () => {
            if (!confirm("Create a copy of this engagement for the retest? Findings are kept as drafts, evidence is not copied.")) return;
            try { const n = await post(`/api/e/${id}/retest`); location.hash = `#/e/${n.id}`; } catch (e) { fail(e); } } }),
          h("button", { class: "btn small danger", text: "Delete", onclick: () => deleteDialog(eng) }))),
      tabs, panel);
    const views = { overview: viewOverview, details: viewDetails, scope: viewScope, findings: viewFindings,
                    evidence: viewEvidence, import: viewImport, report: viewReport };
    (views[tab] || viewOverview)(panel, eng);
  }
  const refresh = () => showEngagement(current.id, current.tab);

  function deleteDialog(eng) {
    const confirmBox = text("", eng.id);
    dialog({ title: "Delete engagement", body: h("div", {},
      h("div", { class: "note bad" }, "This permanently deletes the engagement, its findings and all stored evidence from this computer."),
      field(`Type ${eng.id} to confirm`, confirmBox)),
      buttons: [{ label: "Cancel", onclick: (c) => c.close() },
        { label: "Delete forever", cls: "danger", onclick: async (c) => {
          await del(`/api/e/${eng.id}`, { confirm: confirmBox.value }); c.close(); location.hash = "#/"; } }] });
  }

  // ------------------------------------------------------------------ overview
  function viewOverview(root, eng) {
    const drafts = eng.findings.filter((f) => !f.approved).length;
    root.append(h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", { text: "Approved findings" }), sevBars(eng.counts_approved),
        h("p", { class: "muted small", text: "Only approved findings appear in client reports." })),
      h("div", { class: "card" }, h("h2", { text: "All findings (including drafts)" }), sevBars(eng.counts_all),
        drafts ? h("div", {}, h("span", { class: "badge warn", text: `${drafts} waiting for review` }), " ",
          h("button", { class: "btn small", text: "Review now", onclick: () => { location.hash = `#/e/${eng.id}/findings`; } })) : null),
      h("div", { class: "card" }, h("h2", { text: "Ready to send?" }),
        h("div", { class: "ready" }, h("ul", {}, eng.readiness.map((r) => h("li", {},
          h("span", { class: "dot " + (r.ok ? "ok" : "no"), text: r.ok ? "✓" : "!" }), h("span", { text: r.message })))))),
      h("div", { class: "card" }, h("h2", { text: "Quick actions" }),
        h("div", { class: "chips" },
          h("button", { class: "btn", text: "Add from library", onclick: () => libraryDialog(eng) }),
          h("button", { class: "btn", text: "New finding", onclick: () => findingDialog(eng, null) }),
          h("button", { class: "btn", text: "Import tool results", onclick: () => { location.hash = `#/e/${eng.id}/import`; } }),
          h("button", { class: "btn primary", text: "Make report", onclick: () => { location.hash = `#/e/${eng.id}/report`; } })))));
  }

  // ------------------------------------------------------------------ details
  function rowsEditor(columns, rows) {
    const box = h("div");
    const body = h("div");
    const addRow = (data) => {
      const inputs = columns.map(([k, label, wide]) => h("input", { type: "text", value: (data && data[k]) || "", placeholder: label, "aria-label": label }));
      const row = h("div", { class: "row", style: null }, inputs.map((i) => { const w = h("div", { class: "grow" }, i); w.style.flex = "1 1 150px"; return w; }),
        h("button", { class: "btn small", type: "button", text: "Remove", onclick: () => row.remove() }));
      row._get = () => Object.fromEntries(columns.map(([k], i) => [k, inputs[i].value]));
      body.append(row);
    };
    (rows || []).forEach(addRow);
    box.append(body, h("button", { class: "btn small", type: "button", text: "+ Add row", onclick: () => addRow() }));
    box.get = () => [...body.children].map((r) => r._get()).filter((r) => Object.values(r).some((v) => v.trim()));
    return box;
  }

  function viewDetails(root, eng) {
    const t = eng.report_type;
    const f = {
      type: select(META.report_types.map((x) => [x.id, x.label]), t), name: text(eng.name), client: text(eng.client),
      tester: text(eng.tester), cls: text(eng.classification), program: text(eng.program),
      brandName: text(eng.brand_name), brandColor: h("input", { type: "color", value: eng.brand_color || "#0f172a" }),
      brandLogo: h("input", { type: "file", accept: "image/png,image/jpeg" }),
      summary: area(eng.summary, true, "Plain-language summary for managers: what was tested, what matters most."),
      method: area(eng.methodology, true), rec: area(eng.recommendations), narr: area(eng.attack_narrative, true),
      obj: area(listText(eng.objectives)), gaps: area(listText(eng.detection_gaps)),
    };
    const timeline = rowsEditor([["date", "Date / time"], ["title", "Event"], ["detail", "Detail"], ["source", "Source"]], eng.timeline);
    const entities = rowsEditor([["name", "Name"], ["type", "Type"], ["confidence", "Confidence"], ["notes", "Notes"]], eng.entities);
    const show = (types, node) => types.includes(t) ? node : null;
    root.append(h("div", { class: "card" },
      h("div", { class: "grid two" }, field("Engagement name", f.name), field("Client / program", f.client)),
      h("div", { class: "grid three" }, field("Report type", f.type, "Changing this changes the report layout."),
        field("Prepared by", f.tester), field("Classification label", f.cls, "Shown on every page, e.g. CONFIDENTIAL.")),
      show(["bugbounty"], field("Program / platform", f.program)),
      field("Executive summary", f.summary), field("Methodology", f.method),
      show(["osint", "redteam"], field("Objectives (one per line)", f.obj)),
      show(["redteam"], field("Attack narrative", f.narr)),
      show(["osint", "redteam"], h("div", {}, h("h3", { text: "Timeline" }), timeline)),
      show(["osint"], h("div", {}, h("h3", { text: "Entities and assets" }), entities)),
      show(["redteam"], field("Detection and response gaps (one per line)", f.gaps)),
      field("Recommendations", f.rec),
      h("h2", { text: "Client branding" }),
      h("div", { class: "grid two" }, field("Company name", f.brandName), field("Brand colour", f.brandColor)),
      field("Logo (PNG or JPEG, max 2 MB)", f.brandLogo),
      h("div", { class: "row" },
        h("button", { class: "btn", text: eng.brand_logo_path ? "Replace logo" : "Upload logo", onclick: async () => {
          const logo = f.brandLogo.files[0];
          if (!logo) return toast("Choose a logo file first", true);
          if (logo.size > 2 * 1024 * 1024) return toast("Logo file is larger than 2 MB", true);
          try {
            await post(`/api/e/${eng.id}/branding/logo`, { data_b64: toBase64(await logo.arrayBuffer()) });
            toast("Logo stored"); refresh();
          } catch (e) { fail(e); } } }),
        eng.brand_logo_path ? h("button", { class: "btn", text: "Remove logo", onclick: async () => {
          try { await del(`/api/e/${eng.id}/branding/logo`); toast("Logo removed"); refresh(); } catch (e) { fail(e); } } }) : null,
        h("span", { class: "muted small", text: eng.brand_logo_path ? "A logo is stored for this engagement." : "No logo uploaded." })),
      h("div", { class: "row", style: null }, h("button", { class: "btn primary", text: "Save details", onclick: async () => {
        try {
          await put(`/api/e/${eng.id}`, { report_type: f.type.value, name: f.name.value, client: f.client.value,
            tester: f.tester.value, classification: f.cls.value, program: f.program.value, summary: f.summary.value,
            brand_name: f.brandName.value, brand_color: f.brandColor.value,
            methodology: f.method.value, recommendations: f.rec.value, attack_narrative: f.narr.value,
            objectives: lines(f.obj), detection_gaps: lines(f.gaps),
            timeline: timeline.get(), entities: entities.get() });
          toast("Saved"); refresh();
        } catch (e) { fail(e); } } }))));
  }

  // ------------------------------------------------------------------ scope
  function viewScope(root, eng) {
    const s = eng.scope;
    const f = { auth: text(s.authorization_ref), roe: area(s.rules_of_engagement), inn: area(listText(s.in_scope), true),
      out: area(listText(s.out_of_scope)), start: h("input", { type: "date", value: s.start_date }),
      end: h("input", { type: "date", value: s.end_date }) };
    const probe = text("", "app.example.test or https://app.example.test/login");
    const probeOut = h("div");
    root.append(h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", { text: "Authorization and scope" }),
        field("Authorization reference *", f.auth, "Contract number, signed permission, or bug bounty program policy URL."),
        h("div", { class: "grid two" }, field("Start date", f.start), field("End date", f.end)),
        field("In scope (one per line)", f.inn, "Domain, *.wildcard.domain, IP or CIDR."),
        field("Out of scope (one per line)", f.out, "Always wins over in-scope."),
        field("Rules of engagement", f.roe),
        h("div", { class: "row" }, h("button", { class: "btn primary", text: "Save scope", onclick: async () => {
          try {
            await put(`/api/e/${eng.id}`, { scope: { authorization_ref: f.auth.value, rules_of_engagement: f.roe.value,
              in_scope: lines(f.inn), out_of_scope: lines(f.out), start_date: f.start.value, end_date: f.end.value } });
            toast("Scope saved"); refresh();
          } catch (e) { fail(e); } } }))),
      h("div", { class: "card" }, h("h2", { text: "Check a target" }),
        h("p", { class: "muted small", text: "Ask the scope guard if a host, URL or IP range is allowed before you record anything about it." }),
        probe, h("div", { class: "row" }, h("button", { class: "btn", text: "Check", onclick: async () => {
          try {
            const r = await post(`/api/e/${eng.id}/scope-check`, { targets: lines(probe).length ? lines(probe) : [probe.value] });
            clear(probeOut);
            r.forEach((x) => probeOut.append(h("div", { class: "note " + (x.allowed ? "ok" : "bad") },
              h("b", { text: x.allowed ? "ALLOWED " : "BLOCKED " }), x.target, " - ", x.reason)));
          } catch (e) { fail(e); } } })), probeOut)));
  }

  // ------------------------------------------------------------------ findings
  function viewFindings(root, eng) {
    const q = text("", "Search findings..."), sevF = select([["", "All severities"], ...SEVS.map((s) => [s, s])]),
      stF = select([["", "All reviews"], ["draft", "Draft"], ["approved", "Approved"]]);
    const tbody = h("tbody");
    const draw = () => {
      clear(tbody);
      const term = q.value.toLowerCase();
      const rows = eng.findings.filter((f) => (!term || (f.title + f.id + f.affected_assets.join(" ")).toLowerCase().includes(term))
        && (!sevF.value || f.severity === sevF.value)
        && (!stF.value || (stF.value === "approved") === f.approved));
      if (!rows.length) tbody.append(h("tr", {}, h("td", { colspan: "5", class: "empty", text: eng.findings.length ? "No findings match." : "No findings yet. Add one from the library, import tool results, or write your own." })));
      rows.forEach((f) => {
        const open = () => findingDialog(eng, f);
        tbody.append(h("tr", { class: "click", tabindex: "0", onclick: open, onkeydown: (e) => { if (e.key === "Enter") open(); } },
          h("td", { class: "mono", text: f.id }), h("td", {}, h("b", { text: f.title }), f.ai_assisted ? h("span", { class: "badge", text: " AI-assisted" }) : null,
            f.placeholders ? h("div", { class: "small", style: null }, h("span", { class: "badge warn", text: "TODO placeholders" })) : null),
          h("td", {}, sevBadge(f.severity), f.score !== null ? h("span", { class: "muted small", text: "  " + f.score }) : null),
          h("td", { text: f.status }),
          h("td", {}, f.approved ? h("span", { class: "badge ok", text: "Approved" }) : h("span", { class: "badge warn", text: "Draft" }))));
      });
    };
    [q, sevF, stF].forEach((el) => el.addEventListener("input", draw));
    draw();
    root.append(h("div", { class: "row between" },
      h("div", { class: "row" }, h("div", { class: "grow" }, q), sevF, stF),
      h("div", { class: "row" }, h("button", { class: "btn", text: "Add from library", onclick: () => libraryDialog(eng) }),
        h("button", { class: "btn primary", text: "+ New finding", onclick: () => findingDialog(eng, null) }))),
      h("div", { class: "card", style: null }, h("table", {}, h("thead", {}, h("tr", {}, ["ID", "Finding", "Severity", "Status", "Review"].map((x) => h("th", { text: x })))), tbody)));
  }

  function libraryDialog(eng) {
    const q = text("", "Search the library..."), kind = select([["", "All kinds"], ["web", "Web"], ["osint", "OSINT"], ["redteam", "Red team"]],
      eng.report_type === "osint" ? "osint" : eng.report_type === "redteam" ? "redteam" : "web");
    const assets = area("", false, "app.example.test");
    const listEl = h("div", { class: "scroll" });
    let chosen = null;
    const draw = () => {
      clear(listEl);
      const term = q.value.toLowerCase();
      META.library.filter((e) => (!kind.value || e.kind === kind.value) && (!term || (e.title + e.cwe + e.id).toLowerCase().includes(term)))
        .forEach((e) => {
          const r = h("label", { class: "check" }, h("input", { type: "radio", name: "lib", onchange: () => { chosen = e; } }),
            sevBadge(e.severity), h("span", { text: e.title }), h("span", { class: "muted small", text: e.cwe }));
          listEl.append(r);
        });
    };
    [q, kind].forEach((el) => el.addEventListener("input", draw));
    draw();
    dialog({ title: "Add from the finding library", wide: true,
      body: h("div", {}, h("div", { class: "note" }, "The finding is added as a draft with TODO placeholders for the details only you know. Every asset must be in scope."),
        h("div", { class: "grid two" }, q, kind), listEl, field("Affected assets (one per line) *", assets)),
      buttons: [{ label: "Cancel", onclick: (c) => c.close() },
        { label: "Add as draft", cls: "primary", onclick: async (c) => {
          if (!chosen) throw new Error("Pick a library entry first");
          const f = await post(`/api/e/${eng.id}/findings`, { library_id: chosen.id, affected_assets: lines(assets) });
          c.close(); toast(`Added ${f.id}`); await refresh(); } }] });
  }

  function findingDialog(eng, f) {
    const isNew = !f;
    f = f || { title: "", cvss_vector: "", manual_severity: "Info", cwe: "", owasp: "", mitre: [], affected_assets: [], description: "",
      impact: "", steps_to_reproduce: "", remediation: "", references: [], evidence_ids: [], status: "open",
      source_reliability: "", info_credibility: "", sources: [], retest_notes: "", approved: false, warnings: [], placeholders: false };
    const useCvss = !!f.cvss_vector;
    const m = Object.assign({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" }, useCvss ? parseVec(f.cvss_vector) : {});
    const inp = {
      title: text(f.title, "Short, specific title"), cwe: text(f.cwe, "CWE-89"), mitre: text((f.mitre || []).join(", "), "T1190, T1059"),
      owasp: select([["", "(none)"], ...Object.entries(META.owasp).map(([c, n]) => [c, `${c} ${n}`])], ""),
      assets: area(listText(f.affected_assets), false, "app.example.test"),
      desc: area(f.description, true), impact: area(f.impact), steps: area(f.steps_to_reproduce, true), fix: area(f.remediation),
      refs: area(listText(f.references)), status: select(META.statuses.map((s) => [s, s]), f.status), retest: area(f.retest_notes),
      manual: select(SEVS.map((s) => [s, s]), SEVS.includes(f.manual_severity) ? f.manual_severity : "Info"),
      rel: select([["", "(not graded)"], ...Object.entries(META.reliability).map(([k, v]) => [k, `${k} - ${v}`])], f.source_reliability || ""),
      cred: select([["", "(not graded)"], ...Object.entries(META.credibility).map(([k, v]) => [k, `${k} - ${v}`])], f.info_credibility || ""),
      sources: area(listText(f.sources), false, "https://... (where this came from) and date collected"),
    };
    const owaspCode = (f.owasp || "").match(/A\d{2}:\d{4}/);
    if (owaspCode && META.owasp[owaspCode[0]]) inp.owasp.value = owaspCode[0];
    // CVSS builder
    const useBox = h("input", { type: "checkbox", checked: useCvss });
    const cv = {};
    const scoreEl = h("div", { class: "score", text: "-" }), sevEl = h("span"), vecEl = h("div", { class: "mono muted" });
    const cvGrid = h("div", { class: "cvss" }, CV_FIELDS.map(([k, label, opts]) => {
      cv[k] = select(opts, m[k]); cv[k].addEventListener("input", recompute);
      return field(label, cv[k]);
    }));
    const cvss40Wrap = field("CVSS 4.0 vector", cvss40Vector,
      "Enter a CVSS:4.0 vector. The local scorer validates it when the field loses focus.");
    const versionWrap = field("Scoring version", cvssVersion);
    const manualWrap = field("Severity (no CVSS)", inp.manual, "Use for informational or OSINT items that are not a technical vulnerability.");
    function vector() { return "CVSS:3.1/" + CV_FIELDS.map(([k]) => `${k}:${cv[k].value}`).join("/"); }
    function recompute() {
      const on = useBox.checked;
      const version = cvssVersion.value;
      versionWrap.hidden = !on;
      cvGrid.hidden = !on || version !== "3.1";
      cvss40Wrap.hidden = !on || version !== "4.0";
      manualWrap.hidden = on; scoreEl.parentElement.hidden = !on;
      if (!on) return;
      if (version === "4.0") {
        const savedScore = Number.isFinite(f.score) ? f.score : null;
        scoreEl.textContent = savedScore === null ? "-" : savedScore.toFixed(1);
        clear(sevEl);
        if (savedScore !== null) sevEl.append(sevBadge(cvssSeverity(savedScore)));
        vecEl.textContent = cvss40Vector.value;
        return;
      }
      const mm = Object.fromEntries(CV_FIELDS.map(([k]) => [k, cv[k].value]));
      const s = cvssScore(mm);
      scoreEl.textContent = s.toFixed(1); clear(sevEl); sevEl.append(sevBadge(cvssSeverity(s))); vecEl.textContent = vector();
    }
    useBox.addEventListener("input", recompute);
    cvssVersion.addEventListener("input", recompute);
    let scoreRequest = 0;
    cvss40Vector.addEventListener("change", async () => {
      if (!useBox.checked || cvssVersion.value !== "4.0") return;
      const request = ++scoreRequest;
      try {
        const result = await get(`/api/cvss?vector=${encodeURIComponent(cvss40Vector.value.trim())}`);
        if (request !== scoreRequest) return;
        scoreEl.textContent = result.score.toFixed(1);
        clear(sevEl); sevEl.append(sevBadge(result.severity === "None" ? "Info" : result.severity));
        vecEl.textContent = `${result.label}  ${cvss40Vector.value.trim()}`;
      } catch (e) {
        if (request !== scoreRequest) return;
        scoreEl.textContent = "-"; clear(sevEl); vecEl.textContent = e.message;
      }
    });
    const scoreBox = h("div", { class: "row" }, scoreEl, sevEl, vecEl);
    // evidence links
    const evChecks = eng.evidence.map((e) => ({ e, box: h("input", { type: "checkbox", checked: (f.evidence_ids || []).includes(e.id) }) }));
    // dataset lists
    const dl = h("datalist", { id: "cwelist" }, Object.entries(META.cwe).map(([c, n]) => h("option", { value: c, text: n })));
    inp.cwe.setAttribute("list", "cwelist");
    const dl2 = h("datalist", { id: "mitrelist" }, Object.entries(META.mitre).map(([c, n]) => h("option", { value: c, text: n })));
    inp.mitre.setAttribute("list", "mitrelist");
    const isOsint = eng.report_type === "osint" || f.source_reliability || (f.sources || []).length;

    const payload = () => ({
      title: inp.title.value, cvss_vector: useBox.checked ? (cvssVersion.value === "4.0" ? cvss40Vector.value.trim() : vector()) : "",
      manual_severity: useBox.checked ? "" : inp.manual.value,
      cwe: inp.cwe.value, owasp: inp.owasp.value, mitre: inp.mitre.value.split(",").map((x) => x.trim()).filter(Boolean),
      affected_assets: lines(inp.assets), description: inp.desc.value, impact: inp.impact.value, steps_to_reproduce: inp.steps.value,
      remediation: inp.fix.value, references: lines(inp.refs), status: inp.status.value, retest_notes: inp.retest.value,
      source_reliability: inp.rel.value, info_credibility: inp.cred.value, sources: lines(inp.sources),
      evidence_ids: evChecks.filter((x) => x.box.checked).map((x) => x.e.id),
    });

    // approval + AI sections (existing findings only)
    let extra = null;
    if (!isNew) {
      const reviewer = text(localStorage.getItem("sr_reviewer") || "", "Your full name");
      const promptBox = area("", false); promptBox.readOnly = true; promptBox.hidden = true;
      const reply = area("", false, 'Paste the AI reply here (JSON with "description", "impact", "remediation", "steps_to_reproduce")');
      const redactBox = h("input", { type: "checkbox", checked: true });
      extra = h("div", {},
        h("h3", { text: "Review" }),
        h("div", { class: f.approved ? "note ok" : "note warn" }, f.approved ? `Approved by ${f.approved_by} on ${fmtDate(f.approved_at)}. Editing the text will remove this approval.`
          : "Draft: not included in reports until a named reviewer approves it."),
        h("div", { class: "row" }, h("div", { class: "grow" }, reviewer),
          f.approved ? h("button", { class: "btn", type: "button", text: "Revoke approval", onclick: async () => {
            try { await post(`/api/e/${eng.id}/findings/${f.id}/unapprove`); dlgCtl.close(); refresh(); } catch (e) { fail(e); } } })
            : h("button", { class: "btn primary", type: "button", text: "Approve this finding", onclick: async () => {
              try {
                try { localStorage.setItem("sr_reviewer", reviewer.value); } catch (e) { /* ignore */ }
                await post(`/api/e/${eng.id}/findings/${f.id}/approve`, { reviewer: reviewer.value });
                toast(`${f.id} approved`); dlgCtl.close(); refresh();
              } catch (e) { fail(e); } } })),
        h("p", { class: "muted small", text: "Save your edits first, then approve. Approving means a person has checked every statement against the evidence." }),
        h("details", {}, h("summary", { text: "Improve the text with a free AI chat (optional)" }),
          h("p", { class: "muted small", text: "SecReport never contacts an AI service. It makes a prompt for you to paste into any AI chat, then reads the reply back as an AI-assisted draft that needs your approval again. AI can invent facts, so check everything." }),
          h("label", { class: "check" }, redactBox, "Mask client names, IPs, emails and secrets in the prompt"),
          h("div", { class: "row" }, h("button", { class: "btn small", type: "button", text: "Make prompt", onclick: async () => {
            try { const r = await post(`/api/e/${eng.id}/findings/${f.id}/ai-prompt`, { redact: redactBox.checked }); promptBox.value = r.prompt; promptBox.hidden = false; promptBox.select(); } catch (e) { fail(e); } } }),
            h("button", { class: "btn small", type: "button", text: "Copy", onclick: async () => {
              try { await navigator.clipboard.writeText(promptBox.value); toast("Copied"); } catch (e) { toast("Select the text and copy it manually", true); } } })),
          promptBox, reply,
          h("button", { class: "btn small", type: "button", text: "Apply reply as draft", onclick: async () => {
            try {
              const r = await post(`/api/e/${eng.id}/findings/${f.id}/ai-apply`, { text: reply.value });
              toast("Applied. Approval cleared; review before approving." + (r.warnings.length ? " " + r.warnings.join(" ") : ""));
              dlgCtl.close(); refresh();
            } catch (e) { fail(e); } } })));
    }
    const warnNodes = [];
    if (f.placeholders) warnNodes.push(h("div", { class: "note warn", text: "This finding still has TODO placeholders. Replace them with real details before approving." }));
    (f.warnings || []).forEach((w) => warnNodes.push(h("div", { class: "note", text: w })));

    const body = h("div", {}, dl, dl2, warnNodes,
      field("Title *", inp.title),
      h("div", { class: "row", style: null }, h("label", { class: "check" }, useBox, "Score with CVSS"), versionWrap),
      cvGrid, cvss40Wrap, h("div", {}, scoreBox), manualWrap,
      h("div", { class: "grid three" }, field("Weakness (CWE)", inp.cwe), field("OWASP Top 10 (2021)", inp.owasp), field("MITRE ATT&CK", inp.mitre)),
      field("Affected assets (one per line) *", inp.assets, "Each one is checked against the engagement scope."),
      field("Description", inp.desc), field("Impact", inp.impact), field("Steps to reproduce", inp.steps), field("Remediation", inp.fix),
      isOsint ? h("div", { class: "grid two" }, field("Source reliability", inp.rel), field("Information credibility", inp.cred)) : null,
      isOsint ? field("Sources", inp.sources) : null,
      field("References (one per line)", inp.refs),
      h("div", { class: "grid two" }, field("Status", inp.status), field("Retest notes", inp.retest)),
      eng.evidence.length ? h("div", {}, h("label", { text: "Evidence attached to this finding" }),
        evChecks.map(({ e, box }) => h("label", { class: "check" }, box, `${e.id}  ${e.filename}`))) : null,
      extra);
    recompute();
    const buttons = [{ label: "Close", onclick: (c) => c.close() }];
    if (!isNew) buttons.unshift({ label: "Delete", cls: "danger", onclick: async (c) => {
      if (!confirm(`Delete ${f.id}? This cannot be undone.`)) return;
      await del(`/api/e/${eng.id}/findings/${f.id}`); c.close(); toast("Deleted"); refresh(); } });
    buttons.push({ label: isNew ? "Add finding" : "Save changes", cls: "primary", onclick: async (c) => {
      if (isNew) { const r = await post(`/api/e/${eng.id}/findings`, payload()); toast(`Added ${r.id}`); }
      else { await put(`/api/e/${eng.id}/findings/${f.id}`, payload()); toast("Saved"); }
      c.close(); refresh(); } });
    const dlgCtl = dialog({ title: isNew ? "New finding" : `${f.id}: edit finding`, body, buttons, wide: true });
  }

  // ------------------------------------------------------------------ evidence
  function toBase64(buf) {
    let bin = ""; const bytes = new Uint8Array(buf), chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    return btoa(bin);
  }
  function viewEvidence(root, eng) {
    const file = h("input", { type: "file" }), desc = text("", "What does this show?");
    const links = eng.findings.map((f) => ({ f, box: h("input", { type: "checkbox" }) }));
    const results = h("div");
    root.append(h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", { text: "Add evidence" }),
        h("p", { class: "muted small", text: "Each file is copied into the engagement and fingerprinted with SHA-256, so you can prove later that it was not changed. Max 50 MB." }),
        field("File (screenshot, log, capture)", file), field("Description", desc),
        links.length ? h("div", {}, h("label", { text: "Link to findings" }), h("div", { class: "scroll-s" }, links.map(({ f, box }) => h("label", { class: "check" }, box, `${f.id}  ${f.title}`)))) : null,
        h("button", { class: "btn primary", text: "Upload", onclick: async (ev) => {
          const b = ev.currentTarget;
          if (!file.files[0]) return toast("Choose a file first", true);
          b.disabled = true;
          try {
            const buf = await file.files[0].arrayBuffer();
            await post(`/api/e/${eng.id}/evidence`, { name: file.files[0].name, description: desc.value,
              finding_ids: links.filter((x) => x.box.checked).map((x) => x.f.id), data_b64: toBase64(buf) });
            toast("Evidence stored"); refresh();
          } catch (e) { fail(e); b.disabled = false; } } })),
      h("div", { class: "card" }, h("h2", { text: "Integrity check" }),
        h("p", { class: "muted small", text: "Re-calculates every fingerprint and reports any file that changed or went missing." }),
        h("button", { class: "btn", text: "Verify all evidence", disabled: !eng.evidence.length, onclick: async () => {
          try {
            const r = await get(`/api/e/${eng.id}/verify`); clear(results);
            r.forEach((x) => results.append(h("div", { class: "note " + (x.ok ? "ok" : "bad") }, h("b", { text: x.id + " " }), x.ok ? "OK, hash matches" : x.detail)));
          } catch (e) { fail(e); } } }), results)),
      h("div", { class: "card", style: null }, eng.evidence.length ? h("table", {}, h("thead", {}, h("tr", {}, ["ID", "File", "Size", "SHA-256", "Findings", "Description"].map((x) => h("th", { text: x })))),
        h("tbody", {}, eng.evidence.map((e) => h("tr", {}, h("td", { class: "mono", text: e.id }),
          h("td", {}, h("a", { href: `/api/e/${eng.id}/evidence/${e.id}`, text: e.filename })), h("td", { text: sizeText(e.size) }),
          h("td", { class: "mono", text: e.sha256 }), h("td", { text: (e.finding_ids || []).join(", ") || "-" }), h("td", { text: e.description }))))) : h("div", { class: "empty", text: "No evidence yet." })));
  }

  // ------------------------------------------------------------------ import
  function viewImport(root, eng) {
    const tool = select([["auto", "Detect automatically"], ...META.importers.map((t) => [t, {
      nuclei: "Nuclei (JSON/JSONL)", zap: "OWASP ZAP (JSON)", burp: "Burp Suite (XML)",
      nmap: "Nmap (XML, -oX)", nessus: "Nessus (.nessus XML)", sarif: "SARIF 2.1.0 (JSON)",
    }[t] || t])]);
    const file = h("input", { type: "file" }), paste = area("", true, "...or paste the results here");
    const defaultAsset = text("", "app.example.test");
    const out = h("div");
    file.addEventListener("change", async () => { if (file.files[0]) paste.value = await file.files[0].text(); });
    root.append(h("div", { class: "card" }, h("h2", { text: "Import results from other tools" }),
      h("div", { class: "note" }, "SecReport only reads result files you already have. It never scans anything. Items outside the engagement scope are skipped, duplicates are merged, and everything arrives as a draft for review."),
      h("div", { class: "grid two" }, field("Tool", tool), field("Results file", file)),
      field("Default scoped target for local-file SARIF results", defaultAsset,
        "Optional. Used only when a SARIF result has no absolute HTTP(S) artifact URI; it must pass this engagement's scope."), paste,
      h("div", { class: "row", style: null }, h("button", { class: "btn primary", text: "Import as drafts", onclick: async (ev) => {
        const b = ev.currentTarget; b.disabled = true;
        try {
          const r = await post(`/api/e/${eng.id}/import`, { tool: tool.value, content: paste.value,
            default_asset: defaultAsset.value.trim() });
          clear(out);
          out.append(h("div", { class: "note ok", text: r.summary }),
            r.skipped_scope.length ? h("div", {}, h("h3", { text: "Skipped: outside scope" }),
              h("ul", {}, r.skipped_scope.map((s) => h("li", { text: `${s.title} → ${s.asset} (${s.reason})` })))) : null,
            r.skipped_invalid.length ? h("div", {}, h("h3", { text: "Skipped: invalid" }), h("ul", {}, r.skipped_invalid.map((s) => h("li", { text: `${s.title}: ${s.reason}` })))) : null,
            h("button", { class: "btn", text: "Review findings", onclick: () => { location.hash = `#/e/${eng.id}/findings`; } }));
          current.eng = await get(`/api/e/${eng.id}`);
        } catch (e) { fail(e); } finally { b.disabled = false; } } })), out));
  }

  // ------------------------------------------------------------------ report
  function viewReport(root, eng) {
    const draft = h("input", { type: "checkbox" }), redact = h("input", { type: "checkbox" }), terms = text("", "client name, project codename, host names...");
    const preview = h("div");
    const url = (fmt, inline) => `/api/e/${eng.id}/report?format=${fmt}&draft=${draft.checked ? 1 : 0}&redact=${redact.checked ? 1 : 0}`
      + `&terms=${encodeURIComponent(terms.value)}${inline ? "&inline=1" : ""}`;
    const download = async (fmt) => {
      try {
        const res = await fetch(url(fmt, false), { credentials: "same-origin" });
        if (!res.ok) { let m = `Error ${res.status}`; try { m = (await res.json()).error; } catch (e) { /* ignore */ } throw new Error(m); }
        const blob = await res.blob(), cd = res.headers.get("Content-Disposition") || "";
        const name = (cd.match(/filename="([^"]+)"/) || [])[1] || `report.${fmt}`;
        const a = h("a", { href: URL.createObjectURL(blob), download: name }); document.body.append(a); a.click(); a.remove();
      } catch (e) { fail(e); }
    };
    const showPreview = () => {
      clear(preview);
      const fr = h("iframe", { class: "preview", sandbox: "", title: "Report preview", src: url("html", true) });
      preview.append(fr);
    };
    const pdfOk = !!META.pdf_engine;
    root.append(h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", { text: "Options" }),
        h("label", { class: "check" }, draft, "Include draft (unapproved) findings, marked as DRAFT"),
        h("label", { class: "check" }, redact, "Redacted client copy (masks IPs, emails, secrets and the terms below)"),
        field("Extra words to mask (comma separated)", terms, "Redaction is pattern based. Always read the result before sending it."),
        h("div", { class: "chips", style: null }, h("button", { class: "btn primary", text: "Preview", onclick: showPreview }),
          h("button", { class: "btn", text: "Word (.docx)", onclick: () => download("docx") }),
          h("button", { class: "btn", text: "PDF", disabled: !pdfOk, onclick: () => download("pdf") }),
          h("button", { class: "btn", text: "HTML", onclick: () => download("html") }),
          h("button", { class: "btn", text: "Markdown", onclick: () => download("md") })),
        pdfOk ? null : h("p", { class: "muted small", text: "PDF needs Google Chrome, Chromium or Edge installed. Without it, download HTML or Word and use Print > Save as PDF." })),
      h("div", { class: "card" }, h("h2", { text: "Before you send it" }),
        h("div", { class: "ready" }, h("ul", {}, eng.readiness.map((r) => h("li", {}, h("span", { class: "dot " + (r.ok ? "ok" : "no"), text: r.ok ? "✓" : "!" }), h("span", { text: r.message }))))))),
      h("div", { class: "card", style: null }, preview, h("p", { class: "muted small", text: "Press Preview to see the report here." })));
  }

  // ------------------------------------------------------------------ start
  document.getElementById("topinfo").textContent = "Reports for authorized security work";
  route();
})();
