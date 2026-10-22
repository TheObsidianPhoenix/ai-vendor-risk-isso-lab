/* Counterpart browser app.
 *
 * Security notes:
 * - Vendor documents are written by outsiders, so every value from the server is
 *   shown with textContent through h(). Nothing is ever inserted as HTML, so text
 *   in a document can't become code on this page (XSS; OWASP A03).
 * - Buttons a role can't use are hidden or disabled for convenience only.
 *   The server checks every permission again on every request.
 * - Every change request sends a custom header the server requires (CSRF defence).
 */
"use strict";

// ---------- tiny DOM helper: text only, never HTML ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value === null || value === undefined) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "style") el.style.cssText = value; // Via the style API, which the strict CSP allows (style attributes in markup it blocks)
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}
function icon(name, size) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  if (size) { svg.setAttribute("width", size); svg.setAttribute("height", size); }
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}
const CATEGORY_NAMES = {
  identity_access: "Identity & access", encryption: "Encryption", incident_response: "Incident response",
  vulnerability_management: "Vulnerability management", data_retention: "Data retention",
  logging_monitoring: "Logging & monitoring", business_continuity: "Business continuity",
  security_awareness: "Security awareness", secure_development: "Secure development",
  third_party: "Third-party risk", privacy: "Privacy", ai_governance: "AI governance",
};
const STATE_NAMES = { verified: "Verified", unverified: "Unverified", conflict: "Conflict", absent: "Absent",
  contradicted: "Contradicted", critical_gap: "Critical gap", missing: "Not reported" };
const FLAG_NAMES = { hidden_text: "Hidden text", instruction_like_text: "Instruction aimed at an AI",
  metadata_instruction: "Instruction hidden in file properties", hidden_sheet: "Hidden sheet",
  hidden_rows_or_columns: "Hidden rows or columns", external_link: "External link" };
const catName = (c) => CATEGORY_NAMES[c] || c;
function classBadge(cls, score) {
  if (!cls) return h("span", { class: "badge b-neutral" }, "Not scored");
  const css = { Low: "b-low", Moderate: "b-mod", High: "b-high", Critical: "b-crit" }[cls];
  return h("span", { class: "badge " + css }, score !== null && score !== undefined ? `${score} · ${cls}` : cls);
}
function statusBadge(status) {
  const css = { "Approved": "b-low", "Approved with Conditions": "b-mod", "Rejected": "b-crit",
    "Further Review Required": "b-info" }[status] || "b-neutral";
  const human = ["Approved", "Approved with Conditions", "Rejected", "Further Review Required"].includes(status);
  return h("span", { class: "badge " + css }, human ? icon("user", 12) : null, status);
}
const when = (iso) => iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
const kb = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB";

// ---------- API ----------
async function api(method, path, body, extraHeaders) {
  const headers = Object.assign({ "X-Counterpart-Request": "1" }, extraHeaders || {});
  let payload;
  if (body instanceof ArrayBuffer) payload = body;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  const data = await res.json().catch(() => ({ error: "Unexpected response" }));
  if (res.status === 401 && path !== "/api/session") { state.me = null; render(); }
  if (!res.ok) throw Object.assign(new Error(data.error || "Request failed"), { status: res.status });
  return data;
}
function toast(message, ms) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.remove("show"), ms || 3200);
}

// ---------- state & routing ----------
const state = { me: null };
const can = (perm) => state.me && state.me.user.permissions.includes(perm);
window.addEventListener("hashchange", () => render());

function theme(initial) {
  let saved = null;
  try { saved = localStorage.getItem("cp-theme"); } catch (e) { /* storage may be blocked */ }
  const dark = initial ? (saved ? saved === "dark" : matchMedia("(prefers-color-scheme: dark)").matches)
    : document.documentElement.dataset.theme !== "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  if (!initial) { try { localStorage.setItem("cp-theme", dark ? "dark" : "light"); } catch (e) { /* ignore */ } }
}

async function boot() {
  theme(true);
  try { state.me = await api("GET", "/api/me"); } catch (e) { state.me = null; }
  render();
}

async function render() {
  const root = document.getElementById("root");
  if (!state.me) { root.replaceChildren(await loginScreen()); return; }
  const [route, id] = (location.hash.slice(1) || "overview").split("/");
  const content = h("main", { class: "content", id: "content" });
  root.replaceChildren(shell(route, content));
  const screens = { overview, vendors, vendor, newvendor: newVendor, queue, rules, audit: auditScreen, users, settings };
  const screen = screens[route] || overview;
  content.append(h("p", { class: "muted" }, "Loading…"));
  try {
    const node = await screen(id);
    content.replaceChildren(h("div", { class: "screen active" }, node));
  } catch (err) {
    content.replaceChildren(h("div", { class: "screen active" },
      h("div", { class: "callout callout-crit" }, icon("alert"), h("div", {}, h("strong", {}, err.message)))));
  }
}

// ---------- shell ----------
function shell(route, content) {
  const me = state.me.user;
  const link = (r, ic, label, show = true, count) => show ? h("a", { href: "#" + r, "aria-current": route === r ? "page" : null },
    icon(ic), label, count ? h("span", { class: "count" }, count) : null) : null;
  const redTeam = state.me.model_mode !== "normal";
  return h("div", { class: "app" },
    h("aside", { class: "sidebar", id: "sidebar", "aria-label": "Primary" },
      h("div", { class: "brand" },
        h("div", { class: "brand-mark" }, icon("shield", 18)),
        h("div", {}, h("div", { class: "brand-name" }, "Counterpart"), h("div", { class: "brand-sub" }, "by Meridian Trust Labs"))),
      h("nav", { class: "nav" },
        h("div", { class: "nav-group" }, h("div", { class: "nav-label" }, "Vendor risk"),
          link("overview", "grid", "Overview"),
          link("vendors", "building", "Vendors", can("vendor.view_own") || can("vendor.view_all")),
          link("queue", "inbox", "Review queue", can("decision.record")),
          link("rules", "ruler", "Scoring rules")),
        h("div", { class: "nav-group" }, h("div", { class: "nav-label" }, "Security & governance"),
          link("audit", "list", "Audit log", can("audit.view")),
          link("users", "users", "Users & roles", can("users.view")),
          link("settings", "gear", "Settings"))),
      h("div", { class: "sidebar-foot" }, h("strong", {}, "Local sandbox"), h("br"),
        "Synthetic data only. The AI is a stand-in until Phase 5.")),
    h("div", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "icon-btn menu-btn", "aria-label": "Open navigation",
          onclick: () => document.getElementById("sidebar").classList.toggle("open") }, icon("menu")),
        h("span", { class: "env" }, "Sandbox · synthetic data"),
        redTeam ? h("a", { class: "env", href: "#settings", style: "color:var(--crit);background:var(--crit-bg);text-decoration:none" },
          "Red team mode on") : null,
        h("div", { class: "topbar-right" },
          h("div", { style: "text-align:right;line-height:1.2" }, h("div", { class: "strong small" }, me.name),
            h("div", { class: "small muted" }, me.role_name)),
          h("div", { class: "avatar", title: me.name }, me.name.split(" ").map((p) => p[0]).join("")),
          h("button", { class: "icon-btn", "aria-label": "Toggle dark mode", onclick: () => theme(false) }, icon("moon")),
          h("button", { class: "btn btn-sm", onclick: signOut }, "Sign out"))),
      content));
}
async function signOut() {
  await api("DELETE", "/api/session").catch(() => null);
  state.me = null;
  location.hash = "";
  render();
}

// ---------- sign in ----------
async function loginScreen() {
  const data = await api("GET", "/api/demo-users");
  const byRole = {};
  for (const u of data.users) (byRole[u.role_name] = byRole[u.role_name] || []).push(u);
  return h("div", { class: "login" },
    h("div", { class: "login-card panel" },
      h("div", { class: "brand", style: "padding:0 0 12px" },
        h("div", { class: "brand-mark" }, icon("shield", 18)),
        h("div", {}, h("div", { class: "brand-name", style: "color:var(--text)" }, "Counterpart"),
          h("div", { class: "brand-sub" }, "AI-assisted vendor risk · Meridian Trust Labs"))),
      h("h1", {}, "Sign in"),
      h("p", { class: "muted", style: "margin:6px 0 16px" },
        "Choose a fictional user. Each role sees and can do different things, and the server enforces it."),
      Object.entries(byRole).map(([role, users]) => h("div", { class: "login-group" },
        h("div", { class: "nav-label", style: "color:var(--text-3);padding-left:0" }, role),
        users.map((u) => h("button", { class: "login-user", onclick: () => signIn(u.id) },
          h("span", { class: "avatar" }, u.name.split(" ").map((p) => p[0]).join("")),
          h("span", {}, h("span", { class: "strong" }, u.name), h("br"), h("span", { class: "small muted" }, u.title)))))),
      h("p", { class: "annot" }, h("b", {}, "Sandbox sign-in. "), data.note)));
}
async function signIn(userId) {
  await api("POST", "/api/session", { user_id: userId });
  state.me = await api("GET", "/api/me");
  location.hash = "#overview";
  render();
}

// ---------- overview ----------
async function overview() {
  const o = await api("GET", "/api/overview");
  const me = state.me.user;
  const kpi = (label, value, note, color) => h("div", { class: "panel kpi" }, h("div", { class: "label" }, label),
    h("div", { class: "value", style: color ? `color:${color}` : null }, value), h("div", { class: "note" }, note));
  return h("div", {},
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, `Welcome, ${me.name.split(" ")[0]}`),
        h("p", { class: "sub" }, "AI assessments are advisory. Only an authorized reviewer sets a vendor's final status.")),
      h("div", { class: "actions" },
        can("vendor.create") ? h("a", { class: "btn btn-primary", href: "#newvendor" }, "Add vendor") : null,
        can("decision.record") ? h("a", { class: "btn btn-primary", href: "#queue" }, "Open review queue") : null)),
    h("div", { class: "grid g-4" },
      kpi("Vendors you can see", o.vendor_count, me.role === "app_user" ? "Only vendors you requested" : "All vendors"),
      kpi("Awaiting human decision", o.awaiting_decision, "No vendor has a status until a person decides", "var(--human)"),
      kpi("Prompt-injection indicators", o.injection_flagged, "Vendors with flagged documents", o.injection_flagged ? "var(--crit)" : null),
      o.denied_events === null ? kpi("Critical-rated vendors", o.by_classification.Critical || 0, "Need two reviewers to approve")
        : kpi("Denied actions logged", o.denied_events, "Permission checks that said no", "var(--high)")),
    h("div", { class: "panel", style: "margin-top:16px" },
      h("div", { class: "panel-head" }, h("h2", {}, "How Counterpart decides")),
      h("div", { class: "panel-body" }, h("div", { class: "pipeline how" },
        [["upload", "Upload", "Untrusted vendor files"], ["shield", "Intake checks", "Type, size, macros, hidden text"],
          ["chip", "AI reads", "Proposes evidence, with quotes"], ["check", "Validation", "Schema and every quote checked"],
          ["ruler", "Code scores", "Published rule set " + "1.0"], ["user", "A person decides", "Reviewer only, with rationale"]]
          .map(([ic, t, d], i) => h("div", { class: "step " + (i === 5 ? "wait" : "done") },
            h("div", { class: "node" }, icon(ic, 16)), h("div", { class: "t" }, t), h("div", { class: "d" }, d)))))),
    o.recent.length ? vendorTable(o.recent, "Recent vendors") :
      h("div", { class: "callout callout-info", style: "margin-top:16px" }, icon("info"),
        h("div", {}, can("vendor.create") ? "No vendors yet. Choose Add vendor to start." :
          "No vendors yet. An Application User (Priya or Omar) adds vendors and uploads their documents.")));
}

function vendorTable(list, title) {
  return h("div", { class: "panel", style: "margin-top:16px" },
    title ? h("div", { class: "panel-head" }, h("h2", {}, title)) : null,
    h("div", { class: "panel-body flush table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Vendor", "Requested by", "Rules-engine score", "Flags", "Final status (human)"].map((t) => h("th", {}, t)))),
      h("tbody", {}, list.map((v) => h("tr", { class: "clickable", onclick: () => { location.hash = "#vendor/" + v.id; } },
        h("td", {}, h("a", { class: "strong", href: "#vendor/" + v.id, style: "color:var(--text);text-decoration:none" }, v.name),
          h("div", { class: "small muted" }, v.service)),
        h("td", { class: "small" }, v.owner_name),
        h("td", {}, classBadge(v.classification, v.score)),
        h("td", {}, v.injection_flagged ? h("span", { class: "badge b-crit" }, icon("alert", 12), "Injection flagged") : h("span", { class: "muted small" }, "None")),
        h("td", {}, statusBadge(v.status))))))));
}

// ---------- vendors ----------
async function vendors() {
  const data = await api("GET", "/api/vendors");
  return h("div", {},
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Vendors"),
        h("p", { class: "sub" }, "Two separate things for every vendor: the score the rules engine calculated, and the final status a person set.")),
      h("div", { class: "actions" }, can("vendor.create") ? h("a", { class: "btn btn-primary", href: "#newvendor" }, "Add vendor") : null)),
    data.vendors.length ? vendorTable(data.vendors) : h("p", { class: "muted" }, "No vendors yet."),
    h("p", { class: "annot" }, h("b", {}, "Why two columns? "),
      "A score is evidence; a status is a decision. They're separate records, so nobody can mistake the AI's assessment for an approval."));
}

async function newVendor() {
  const form = h("form", { class: "panel panel-body", style: "max-width:640px",
    onsubmit: async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const r = await api("POST", "/api/vendors", { name: f.get("name"), service: f.get("service"),
          data_shared: f.get("data_shared"), uses_ai_on_customer_data: f.get("uses_ai") === "yes" });
        toast("Vendor created. Now upload its documents.");
        location.hash = "#vendor/" + r.vendor.id;
      } catch (err) { toast(err.message); }
    } },
    field("Vendor name", h("input", { class: "input", name: "name", required: true, maxlength: 80, placeholder: "e.g. Nimbus Notes AI" })),
    field("What they do for us", h("input", { class: "input", name: "service", required: true, maxlength: 200, placeholder: "e.g. Meeting transcription and summaries" })),
    field("Data we'd share", h("input", { class: "input", name: "data_shared", required: true, maxlength: 200, placeholder: "e.g. Confidential meeting audio and transcripts" })),
    h("div", { class: "field" }, h("span", {}, "Will this vendor use AI on our data?"),
      h("div", { class: "radio-cards" },
        radioCard("uses_ai", "yes", "Yes", "AI governance is assessed as a critical control"),
        radioCard("uses_ai", "no", "No", "AI governance isn't scored")),
      h("div", { class: "help" }, "You answer this, not the vendor's documents, so a document can't talk its way out of an AI review.")),
    h("button", { class: "btn btn-primary", type: "submit" }, "Create vendor"));
  return h("div", {}, h("div", { class: "crumbs" }, h("a", { href: "#vendors" }, "Vendors"), " / New"),
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Add a vendor"),
      h("p", { class: "sub" }, "You'll be the requester. Separation of duties means you can't also be its reviewer."))), form);
}
function field(label, input, help) {
  return h("label", { class: "field" }, h("span", {}, label), input, help ? h("div", { class: "help" }, help) : null);
}
function radioCard(name, value, title, desc, checked) {
  return h("label", { class: "radio-card" }, h("input", { type: "radio", name, value, required: true, checked: !!checked }),
    h("span", {}, h("span", { class: "t" }, title), h("br"), h("span", { class: "d" }, desc)));
}

// ---------- vendor workspace ----------
async function vendor(id) {
  const d = await api("GET", "/api/vendors/" + id);
  const v = d.vendor, a = d.assessment;
  return h("div", {},
    h("div", { class: "crumbs" }, h("a", { href: "#vendors" }, "Vendors"), " / ", v.name),
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, v.name),
        h("p", { class: "sub" }, `${v.service} · Data shared: ${v.data_shared} · Requested by ${v.owner_name}` +
          (v.uses_ai_on_customer_data ? " · Uses AI on our data" : ""))),
      h("div", { class: "actions" }, h("span", { class: "small muted" }, "Final status"), statusBadge(d.status.status))),
    legend(),
    documentsPanel(d),
    a ? assessmentPanel(d) : null,
    a && a.status === "ready_for_review" ? decisionPanel(d) : null);
}

function legend() {
  return h("div", { class: "panel", style: "padding:12px 16px;margin-bottom:16px" }, h("div", { class: "legend" },
    h("strong", { style: "color:var(--text)" }, "Where each item came from:"),
    h("span", { class: "prov prov-fact" }, icon("doc"), "Document fact"), "quoted from the vendor's files",
    h("span", { class: "prov prov-ai" }, icon("chip"), "AI interpretation"), "advisory, may be wrong",
    h("span", { class: "prov prov-rule" }, icon("ruler"), "Rules engine"), "fixed calculation",
    h("span", { class: "prov prov-human" }, icon("user"), "Human decision"), "authorized reviewer"));
}

function documentsPanel(d) {
  const v = d.vendor;
  // A person says what each document is. Only "independent audit report" can make a control verified.
  const typeSelect = h("select", { class: "input", id: "docType", style: "max-width:520px" },
    h("option", { value: "" }, "Choose the document type first…"),
    Object.entries(d.document_types).map(([value, label]) => h("option", { value }, label)));
  const input = h("input", { type: "file", multiple: true, accept: ".pdf,.xlsx,.docx", class: "sr-only", id: "fileInput",
    onchange: async (e) => {
      const docType = document.getElementById("docType").value;
      if (!docType) { toast("Choose what kind of document this is before uploading."); e.target.value = ""; return; }
      for (const file of e.target.files) {
        toast(`Checking ${file.name}…`, 8000);
        try {
          const r = await api("POST", `/api/vendors/${v.id}/documents`, await file.arrayBuffer(), { "X-Filename": file.name, "X-Document-Type": docType });
          toast(r.document.status === "accepted" ? `${file.name}: accepted` + (r.document.flags.length ? " with flags" : "")
            : `${file.name}: rejected. ${r.document.rejection_reason}`, 5000);
        } catch (err) { toast(`${file.name}: ${err.message}`, 5000); }
      }
      render();
    } });
  const canAssess = d.can.assess && d.documents.some((doc) => doc.status === "accepted");
  return h("div", { class: "panel", style: "margin-bottom:16px" },
    h("div", { class: "panel-head" }, h("h2", {}, "1 · Documents and intake checks"),
      h("span", { class: "meta" }, "Every file is checked before the AI sees it")),
    d.can.upload ? h("div", { class: "panel-body" },
      h("label", { class: "field" }, h("span", {}, "What kind of document is it?"), typeSelect,
        h("div", { class: "help" }, "Only an independent audit report can make a control \u201cverified.\u201d Anything the vendor writes about itself counts as a claim.")),
      h("label", { class: "dropzone", for: "fileInput", style: "display:block;cursor:pointer" },
      icon("upload"), h("div", { class: "strong", style: "margin-top:6px" }, "Choose vendor documents to upload"),
      h("div", { class: "small muted" }, "PDF, XLSX or DOCX · up to 10 MB each · checked for macros, hidden text and more")), input) : null,
    d.documents.length ? h("div", { class: "panel-body flush table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Document", "Intake result", "What the scanner found", "SHA-256"].map((t) => h("th", {}, t)))),
      h("tbody", {}, d.documents.map((doc) => h("tr", {},
        h("td", {}, h("div", { class: "strong" }, doc.filename),
          h("div", { class: "small muted" }, `${(d.document_types[doc.doc_type] || "Type not set").split(" (")[0]} · ${kb(doc.size_bytes)} · uploaded by ${doc.uploaded_by_name}`)),
        h("td", {}, doc.status === "rejected" ? h("span", { class: "badge b-crit" }, "Rejected")
          : doc.flags.some((f) => f.injection) ? h("span", { class: "badge b-crit" }, icon("alert", 12), "Accepted, flagged")
            : h("span", { class: "badge b-low" }, "Passed")),
        h("td", { class: "small" }, doc.status === "rejected" ? doc.rejection_reason
          : doc.flags.length ? doc.flags.map((f) => h("div", { style: "margin-bottom:6px" },
            h("strong", {}, `${FLAG_NAMES[f.kind] || f.kind} · ${f.location}`), h("br"), f.detail,
            f.excerpt ? h("div", { class: "quote", style: "font-size:13px;margin-top:4px;border-left-color:var(--crit)" }, `"${f.excerpt}"`,
              h("cite", {}, f.kind === "hidden_text" ? "Removed before the AI saw the document" : "Kept as data, flagged for the reviewer")) : null))
            : h("span", { class: "muted" }, "Nothing suspicious")),
        h("td", { class: "small muted", title: doc.sha256, style: "font-family:ui-monospace,monospace" }, doc.sha256.slice(0, 12))))))) :
      h("div", { class: "panel-body muted" }, d.can.upload ? "No documents yet." : "No documents yet. Only the requester can upload them."),
    d.can.assess ? h("div", { class: "panel-body", style: "border-top:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap" },
      h("button", { class: "btn btn-primary", disabled: !canAssess, onclick: async (e) => {
        e.target.disabled = true; toast("AI is reading the documents…", 8000);
        try { const r = await api("POST", `/api/vendors/${v.id}/assessments`);
          toast(r.assessment.status === "ready_for_review" ? "Assessment complete. Ready for human review." : "AI output rejected by the validator.", 5000);
        } catch (err) { toast(err.message); }
        render();
      } }, icon("chip"), d.assessment ? "Run a new assessment" : "Run AI assessment"),
      h("span", { class: "small muted" }, d.assessment ? `${d.assessment_count} assessment(s) so far. Earlier versions are kept.`
        : "The AI proposes evidence. It can't approve or reject.")) : null);
}

function assessmentPanel(d) {
  const a = d.assessment;
  const injection = a.injection_flags.length ? h("div", { class: "callout callout-crit", style: "margin-bottom:16px" }, icon("alert"),
    h("div", {}, h("strong", {}, "Instructions aimed at the AI were found in the documents. They were treated as data and not followed."),
      a.injection_flags.map((f) => h("div", { class: "small", style: "margin-top:4px" }, `${f.document} · ${f.location} · ${FLAG_NAMES[f.kind] || f.kind}`)),
      h("div", { class: "small", style: "margin-top:6px" }, "The score isn't affected, and the vendor still needs a human decision."))) : null;

  if (a.status !== "ready_for_review") {
    return h("div", { class: "panel", style: "margin-bottom:16px" },
      h("div", { class: "panel-head" }, h("h2", {}, `2 · AI assessment (version ${a.version})`), h("span", { class: "meta" }, a.model_id)),
      h("div", { class: "panel-body" }, injection, pipeline(a),
        h("div", { class: "callout callout-crit" }, icon("lock"), h("div", {},
          h("strong", {}, a.status === "ai_call_failed" ? "The AI couldn't complete this assessment, so nothing was scored."
            : "The AI's answer was rejected and nothing from it was used."),
          h("div", { style: "margin-top:4px" }, a.status === "ai_call_failed" ? "Reason: " : "Validator: ", h("span", { class: "strong" }, a.rejection_reason)),
          h("div", { class: "small", style: "margin-top:6px" },
            "No score was produced and no status changed. The event is in the audit log. A reviewer can't decide on a rejected assessment, so a new one must be run.")))));
  }
  const s = a.score;
  const linesByCat = Object.fromEntries(s.lines.map((l) => [l.category, l]));
  const findingsByCat = Object.fromEntries(a.findings.map((f) => [f.category, f]));
  const order = s.lines.slice().sort((x, y) => y.points - x.points);
  return h("div", { style: "margin-bottom:16px" },
    h("div", { class: "panel", style: "margin-bottom:16px" },
      h("div", { class: "panel-head" }, h("h2", {}, `2 · AI assessment and score (version ${a.version})`),
        h("span", { class: "meta" }, `${a.model_id} · started by ${a.started_by_name}`)),
      h("div", { class: "panel-body" }, injection, pipeline(a),
        a.citation_problems.length ? h("div", { class: "callout callout-warn", style: "margin-bottom:16px" }, icon("alert"), h("div", {},
          h("strong", {}, `${a.citation_problems.length} quote(s) from the AI couldn't be found in the documents.`),
          h("div", { class: "small", style: "margin-top:4px" }, "Those findings count as missing evidence. Making things up can only make a vendor look worse, never better."),
          h("ul", { class: "small", style: "margin:6px 0 0;padding-left:18px" }, a.citation_problems.slice(0, 6).map((p) => h("li", {}, p))))) : null,
        h("div", { class: "grid g-main" },
          h("div", { class: "panel" }, order.map((line) => findingRow(line, findingsByCat[line.category]))),
          h("div", { class: "stack" },
            h("div", { class: "zone zone-rule" },
              h("div", { class: "zone-title" }, h("span", { class: "prov prov-rule" }, icon("ruler"), "Rules engine"),
                h("span", { class: "hint" }, `Rule set ${s.rule_set_version}`)),
              h("div", { class: "score-head" }, h("div", { class: "score-big" }, s.score), classBadge(s.classification)),
              h("div", { class: "meter" }, h("i", { style: `left:calc(${Math.min(s.score, 100)}% - 1px)` })),
              h("div", { class: "meter-scale" }, ["0 Low", "25 Moderate", "50 High", "75 Critical"].map((t) => h("span", {}, t))),
              h("div", { style: "margin-top:10px" }, order.filter((l) => l.points).map((l) => h("div", { class: "calc-row" },
                h("span", {}, `${catName(l.category)} · ${STATE_NAMES[l.scored_state]}`), h("span", { class: "pts" }, "+" + l.points)))),
              s.floor_rule_applied ? h("p", { class: "small", style: "margin-top:8px" }, h("strong", {}, "Floor rule: "), s.floor_rule_applied) : null,
              h("p", { class: "small muted", style: "margin-top:8px" }, "Calculated by code from the evidence states. The AI never assigns points.")),
            h("div", { class: "zone zone-ai" },
              h("div", { class: "zone-title" }, h("span", { class: "prov prov-ai" }, icon("chip"), "AI summary"), h("span", { class: "hint" }, "Advisory")),
              h("p", { class: "small" }, a.summary),
              a.follow_up_questions.length ? h("div", { style: "margin-top:10px" }, h("div", { class: "strong small" }, "Suggested questions for the vendor"),
                h("ol", { class: "small", style: "margin:6px 0 0;padding-left:18px" }, a.follow_up_questions.map((q) => h("li", {}, q)))) : null))))));
}

function pipeline(a) {
  const ok = a.status === "ready_for_review";
  const steps = [["Intake", a.injection_flags.length ? "flag" : "done", a.injection_flags.length ? "Flags found" : "Passed"],
    ["AI extraction", a.status === "ai_call_failed" ? "flag" : "done", a.model_mode !== "normal" ? "Red team mode"
      : a.model_id.startsWith("pretend") ? "Pretend model" : "Bedrock" + (a.usage ? ` · ${a.usage.input_tokens + a.usage.output_tokens} tokens` : "")],
    ["Schema check", ok ? "done" : "flag", ok ? "Valid" : "Rejected"],
    ["Quote check", !ok ? "" : a.citation_problems.length ? "flag" : "done", !ok ? "Skipped" : a.citation_problems.length ? `${a.citation_problems.length} not found` : "All found"],
    ["Rules engine", ok ? "done" : "", ok ? `Scored ${a.score.score}` : "Not run"],
    ["Human decision", "wait", "Reviewer only"]];
  return h("div", { class: "pipeline", style: "grid-template-columns:repeat(6,minmax(0,1fr));margin-bottom:18px" },
    steps.map(([t, cls, d], i) => h("div", { class: "step " + cls }, h("div", { class: "node" }, cls === "flag" ? "!" : String(i + 1)),
      h("div", { class: "t" }, t), h("div", { class: "d" }, d))));
}

function findingRow(line, finding) {
  const pts = h("span", { class: "prov prov-rule" }, icon("ruler"), `${STATE_NAMES[line.scored_state]} · +${line.points}`);
  return h("div", { class: "finding" },
    h("div", {}, h("div", { class: "cat" }, catName(line.category)), h("div", { class: "small muted" }, line.reason)),
    h("div", { class: "rows" },
      finding && finding.citations.length ? [h("div", {}, h("span", { class: "prov prov-fact" }, icon("doc"), `Document fact${finding.citations.length > 1 ? "s" : ""}`)),
        finding.citations.map((c) => h("div", { class: "quote", style: c.verified ? null : "border-left-color:var(--crit);opacity:.8" }, `"${c.quote}"`,
          h("cite", {}, `${c.document} · ${c.location} · `, c.verified ? h("span", { style: "color:var(--ok)" }, "quote found in document")
            : h("span", { style: "color:var(--crit);font-weight:600" }, `not found: ${c.problem}`))))]
        : h("div", {}, h("span", { class: "prov prov-fact" }, icon("doc"), "Document fact"), " ", h("span", { class: "small muted" }, "No passage reported by the AI.")),
      finding ? [h("div", {}, h("span", { class: "prov prov-ai" }, icon("chip"), "AI interpretation"), " ",
        h("span", { class: "small" }, `${STATE_NAMES[finding.evidence_state]}: ${finding.interpretation}`)),
        h("div", { class: "conf" }, "Model confidence ", h("span", { class: "conf-bar" }, h("i", { style: `width:${{ high: 90, medium: 60, low: 30 }[finding.confidence]}%` })), finding.confidence)] : null),
    h("div", {}, pts));
}

function decisionPanel(d) {
  const a = d.assessment, s = a.score;
  const mine = d.decisions.filter((x) => x.assessment_id === a.id);
  const history = mine.map((x) => h("div", { class: "signature", style: "margin-bottom:8px" },
    h("div", { class: "avatar" }, x.reviewer_name.split(" ").map((p) => p[0]).join("")),
    h("div", { style: "flex:1" }, h("div", {}, h("span", { class: "name" }, x.reviewer_name), " · ", statusBadge(x.decision),
      x.stage === "first_approval" ? h("span", { class: "badge b-neutral", style: "margin-left:6px" }, "First of two approvals") : null,
      x.override ? h("span", { class: "badge b-high", style: "margin-left:6px" }, "Override of rules-engine rating") : null),
      h("div", { class: "small", style: "margin-top:4px" }, x.rationale),
      x.conditions ? h("div", { class: "small", style: "margin-top:2px" }, h("strong", {}, "Conditions: "), x.conditions) : null,
      h("div", { class: "when" }, `${when(x.recorded_at)} · assessment v${x.assessment_version} · rule set ${x.rule_set_version} · score ${x.score} ${x.classification}`))));

  let body;
  if (d.status.final) {
    body = h("div", { class: "callout callout-info" }, icon("lock"), h("div", {}, h("strong", {}, "Decision recorded and locked."),
      " Decisions are never edited or replaced. New evidence means a new assessment and a new decision."));
  } else if (!d.can.decide) {
    body = h("div", { class: "callout callout-info" }, icon("lock"), h("div", {}, h("strong", {}, "Only a Vendor Risk Reviewer can record the decision."),
      ` You're signed in as ${state.me.user.role_name}. The server would refuse this even if the form were shown.`));
  } else if (d.can.decide_blocked_reason) {
    body = h("div", { class: "callout callout-warn" }, icon("users"), h("div", {}, h("strong", {}, d.can.decide_blocked_reason)));
  } else {
    const pending = mine.find((x) => x.stage === "first_approval");
    const form = h("form", { onsubmit: async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const r = await api("POST", `/api/assessments/${a.id}/decisions`, { decision: f.get("decision"), rationale: f.get("rationale"),
          conditions: f.get("conditions") || "", evidence_confirmed: f.get("evidence") === "on" });
        toast(r.decision.stage === "first_approval" ? "First approval recorded. A second reviewer must approve." : "Decision recorded.", 5000);
        render();
      } catch (err) { toast(err.message, 6000); }
    } },
      s.classification === "Critical" ? h("div", { class: "callout callout-warn", style: "margin-bottom:12px" }, icon("users"),
        h("div", {}, pending ? `${pending.reviewer_name} gave the first approval. Your decision completes the review; you must be a different reviewer.`
          : "Critical vendor: an approval needs a second, different reviewer before it's final.")) : null,
      h("div", { class: "field" }, h("span", {}, "Your decision"), h("div", { class: "radio-cards" },
        radioCard("decision", "Approved", "Approved", "Risk accepted as is"),
        radioCard("decision", "Approved with Conditions", "Approved with conditions", "Accept if the conditions are met"),
        radioCard("decision", "Further Review Required", "Further review required", "Need more evidence first"),
        radioCard("decision", "Rejected", "Rejected", "Don't use this vendor"))),
      field("Rationale", h("textarea", { class: "input", name: "rationale", required: true, minlength: 20, maxlength: 2000,
        placeholder: "Why? Reference the evidence you relied on." }), "Saved with your name and the assessment version. At least 20 characters."),
      field("Conditions (for an approval with conditions)", h("input", { class: "input", name: "conditions", maxlength: 500,
        placeholder: "e.g. Contractual opt-out from model training before go-live" })),
      h("label", { class: "check", style: "margin-bottom:14px" }, h("input", { type: "checkbox", name: "evidence", required: true }),
        h("span", {}, "I examined the source evidence and the flags, not only the AI summary.")),
      h("button", { class: "btn btn-primary", type: "submit" }, icon("user"), "Record my decision"),
      h("p", { class: "small muted", style: "margin-top:8px" },
        `Needs a sign-in within the last 15 minutes. Yours has ${Math.floor(state.me.fresh_for_seconds / 60)} minute(s) left.`));
    body = form;
  }
  return h("div", { class: "zone zone-human" },
    h("div", { class: "zone-title" }, h("span", { class: "prov prov-human" }, icon("user"), "Human decision"),
      h("h3", {}, "3 · Final decision"), h("span", { class: "hint" }, "Recorded only by an authorized reviewer")),
    history, body);
}

// ---------- review queue ----------
async function queue() {
  const data = await api("GET", "/api/vendors");
  const waiting = data.vendors.filter((v) => v.status === "Awaiting human decision" || v.status === "Awaiting second approval");
  return h("div", {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Review queue"),
      h("p", { class: "sub" }, "Vendors with a valid assessment and no final decision. Highest risk first."))),
    waiting.length ? vendorTable(waiting.sort((x, y) => (y.score || 0) - (x.score || 0))) : h("p", { class: "muted" }, "Nothing waiting."));
}

// ---------- scoring rules ----------
async function rules() {
  const r = await api("GET", "/api/rules");
  return h("div", {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, `Scoring rules · rule set ${r.version}`),
      h("p", { class: "sub" }, "Published, versioned and changed only through a reviewed pull request. Anyone can recompute a score by hand."))),
    h("div", { class: "grid g-2" },
      h("div", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Points per evidence state")),
        h("div", { class: "panel-body" }, Object.entries(r.points).map(([k, v]) => h("div", { class: "calc-row" }, STATE_NAMES[k] || k, h("span", { class: "pts" }, "+" + v))))),
      h("div", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Classification")),
        h("div", { class: "panel-body" }, r.bands.map(([floor, name]) => h("div", { class: "calc-row" }, classBadge(name), h("span", { class: "pts" }, `${floor} and up`))),
          h("p", { class: "small", style: "margin-top:10px" }, "Floors: one critical gap means at least High; two or more means Critical."),
          h("p", { class: "small", style: "margin-top:6px" }, "Critical controls: ", r.critical.map(catName).join(", "), ".")))));
}

// ---------- audit ----------
async function auditScreen() {
  const r = await api("GET", "/api/audit");
  const c = r.chain;
  return h("div", {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Audit log"),
      h("p", { class: "sub" }, "Every security-relevant action, who did it and the outcome. Never document contents or tokens."))),
    h("div", { class: "callout " + (c.intact ? "callout-info" : "callout-crit"), style: "margin-bottom:16px" }, icon(c.intact ? "shield" : "alert"),
      h("div", {}, h("strong", {}, c.intact ? `Hash chain intact: ${c.events} events verified.` : `Tampering detected at event ${c.first_bad_seq}.`),
        " Each event includes a fingerprint of the one before it, so editing or deleting history breaks the chain.")),
    h("div", { class: "panel" }, h("div", { class: "panel-body flush table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["#", "When", "Who", "Action", "Outcome", "Details"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.events.map((e) => h("tr", {},
        h("td", { class: "small muted" }, e.seq), h("td", { class: "small nowrap" }, when(e.time)),
        h("td", { class: "small" }, e.actor, h("div", { class: "muted" }, e.role)),
        h("td", { class: "small strong" }, e.action),
        h("td", {}, h("span", { class: "badge " + (e.outcome === "success" ? "b-low" : e.outcome === "denied" ? "b-crit" : "b-high") }, e.outcome)),
        h("td", { class: "small", style: "max-width:420px;word-break:break-word" },
          Object.entries(e.details).filter(([, v]) => v !== null && !(Array.isArray(v) && !v.length))
            .map(([k, v]) => h("div", {}, h("span", { class: "muted" }, k + ": "), Array.isArray(v) ? v.join("; ") : String(v)))))))))));
}

// ---------- users & roles ----------
async function users() {
  const r = await api("GET", "/api/users");
  const perms = [["vendor.create", "Create vendors"], ["document.upload_own", "Upload documents (own vendors)"],
    ["vendor.view_all", "See every vendor"], ["assessment.run_any", "Run assessments (any vendor)"],
    ["decision.record", "Record final decisions"], ["audit.view", "Read the audit log"], ["settings.change", "Change settings"]];
  const roles = Object.keys(r.roles);
  return h("div", {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Users & roles"),
      h("p", { class: "sub" }, "Least privilege: each role has only what it needs. Anything not listed is denied."))),
    h("div", { class: "panel", style: "margin-bottom:16px" }, h("div", { class: "panel-body flush table-wrap" }, h("table", { class: "rbac" },
      h("thead", {}, h("tr", {}, h("th", {}, "Permission"), roles.map((k) => h("th", {}, r.roles[k])))),
      h("tbody", {}, perms.map(([p, label]) => h("tr", {}, h("td", {}, label), roles.map((k) => {
        const has = r.users.some((u) => u.role === k && u.permissions.includes(p));
        return h("td", { class: has ? "yes" : "no" }, has ? "✓" : "—");
      }))))))),
    h("div", { class: "panel" }, h("div", { class: "panel-body flush table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Person (fictional)", "Role", "Title"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.users.map((u) => h("tr", {}, h("td", { class: "strong" }, u.name), h("td", {}, u.role_name), h("td", { class: "small" }, u.title))))))),
    h("p", { class: "annot" }, h("b", {}, "Separation of duties: "), "the person who requests a vendor can't be its reviewer, and administrators can't record decisions."));
}

// ---------- settings ----------
async function settings() {
  const r = await api("GET", "/api/settings");
  return h("div", {},
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Settings"),
      h("p", { class: "sub" }, "Red team mode makes the pretend AI misbehave on purpose, to show the guardrails work."))),
    h("div", { class: "panel panel-body", style: "max-width:720px" },
      h("div", { class: "field" }, h("span", {}, "AI model behaviour"),
        h("div", { style: "display:grid;gap:8px" }, Object.entries(r.modes).map(([k, label]) => h("label", { class: "radio-card" },
          h("input", { type: "radio", name: "mode", value: k, checked: r.model_mode === k, disabled: !r.can_change,
            onchange: async () => {
              try { await api("POST", "/api/settings", { model_mode: k }); state.me = await api("GET", "/api/me");
                toast("Saved. The next assessment uses this behaviour."); render();
              } catch (err) { toast(err.message); }
            } }),
          h("span", {}, h("span", { class: "t" }, label)))))),
      r.can_change ? h("p", { class: "small muted" }, "Changing this is recorded in the audit log.")
        : h("div", { class: "callout callout-info" }, icon("lock"), h("div", {}, "Only an Administrator can change this."))));
}

boot();
