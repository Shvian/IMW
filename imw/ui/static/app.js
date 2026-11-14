"use strict";
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let STATE = {}, PAGE = "overview", LAST_OUT = "", LAST_LOAD = "";
const REVIEW = { view: "review", filters: {}, page: 0, sort: "target_safe", desc: false, selected: new Set(), data: null };

async function api(path, body) {
  const opts = body === undefined ? { headers: { "X-IMW": "1" } }
    : { method: "POST", headers: { "Content-Type": "application/json", "X-IMW": "1" }, body: JSON.stringify(body) };
  $("#busy").classList.toggle("hidden", body === undefined || path === "/api/ping");
  try {
    const r = await fetch(path, opts);
    const data = await r.json().catch(() => ({ error: "Unexpected response" }));
    if (r.status === 401) { document.body.innerHTML = "<p style='padding:30px'>Session ended. Restart the Workbench to get a new link.</p>"; throw new Error("session"); }
    if (r.status === 423) { showLogin("Locked after inactivity. Sign in again to continue."); throw new Error("session"); }
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  } finally { $("#busy").classList.add("hidden"); }
}
function msg(el, kind, text) { el.innerHTML = `<div class="msg ${kind}">${esc(text)}</div>`; }
// After a save: warn when the server removed invisible or control characters from what was typed.
const CLEANED = "Invisible or control characters (for example zero-width spaces or line breaks) were removed from what you typed.";
const okOrCleaned = (el, r, text) => msg(el, r && r.cleaned ? "warn" : "ok", r && r.cleaned ? `${text} ${CLEANED}` : text);

async function refresh() {
  STATE = await api("/api/state");
  $("#hdr-sub").textContent = STATE.has_db
    ? `${STATE.records} records · secrets ${({dpapi: "encrypted (DPAPI)", none: "not stored", plain: "PLAINTEXT (test mode)"})[STATE.protector] || ""}`
    : "No data loaded yet";
}
/* ---------------- Unsaved changes ---------------- */
// Typing in a settings field or a side panel marks it unsaved until it is saved. Leaving the page,
// closing or switching the panel, or closing the browser tab then asks first. Filters, search boxes,
// ticks that only select rows, reasons and the output page don't count.
const DIRTY = { main: false, panel: false };
const NOT_A_CHANGE = new Set(["f-search", "s-filter", "s-nofull", "p-filter", "view", "f-safe", "f-platform", "f-source", "f-status", "allmatch",
  "p-nosafe", "s-selall", "m-selall", "selall", "reason", "m-reason", "ra-reason", "pe-reason", "o-safe", "o-platform", "o-source",
  "o-name", "o-replace", "confirm", "pa-safe", "pa-role", "role-from", "new-layer", "sv-reason",
  "pv-filter", "pv-changed", "cols-mode", "s-cols-mode"]);
function trackDirty(e) {
  const el = e.target;
  if (!el.matches || !el.matches("input, select, textarea") || el.type === "search" || el.name === "sec" || el.name === "scope") return;
  if (NOT_A_CHANGE.has(el.id) || ["s-sel", "sel", "m-sel", "pick", "perm"].some(c => el.classList.contains(c))) return;
  if (el.closest("#drawer")) DIRTY.panel = true;
  else if (el.closest("#main") && PAGE !== "output") DIRTY.main = true;
}
document.addEventListener("input", trackDirty);
// Adding or removing rows, placeholders or roles on a settings page is a change too. Buttons that
// re-draw their own block (Remove placeholder, Delete role) are gone before this runs, so they mark it themselves.
document.addEventListener("click", (e) => {
  const b = e.target.closest && e.target.closest("#main button");
  if (b && PAGE.startsWith("rules") && (b.matches("[data-add], .l-del, #add-layer, #reset-layers, #role-add, #conv-keep") || b.closest("td.x"))) DIRTY.main = true;
});
document.addEventListener("change", trackDirty);
function leaveOk(scope) {
  const dirty = scope === "panel" ? DIRTY.panel : DIRTY.main || DIRTY.panel;
  if (!dirty) return true;
  const where = scope === "panel" || !DIRTY.main ? "in this panel" : "on this page";
  if (!confirm(`You have changes ${where} that are not saved yet.\n\nLeave without saving them? Click Cancel to go back and save.`)) return false;
  DIRTY.panel = false; if (scope !== "panel") DIRTY.main = false;
  return true;
}
const saved = (scope) => { if (scope === "panel") DIRTY.panel = false; else { DIRTY.main = false; } syncSave(); };
// Save & apply is greyed out ("Saved") until something on the page changes.
function syncSave() {
  const b = document.querySelector("#main #save"); if (!b) return;
  const can = DIRTY.main || STATE.stale;   // unmapped records: applying the rules is useful even with nothing changed
  b.disabled = !can; b.textContent = can ? "Save & apply this page" : "Saved";
}
["input", "change", "click"].forEach(ev => document.addEventListener(ev, () => setTimeout(syncSave, 0)));
window.addEventListener("beforeunload", (e) => { if (!LOCKED && (DIRTY.main || DIRTY.panel)) { e.preventDefault(); e.returnValue = ""; } });

function go(page) {
  if (!leaveOk()) return;
  DIRTY.main = DIRTY.panel = false;
  PAGE = page; onTableCount = null; if (typeof SAFES !== "undefined") SAFES.panel = null;
  document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("active",
    b.dataset.group ? page.startsWith(b.dataset.group) : b.dataset.page === page));
  $("#nav").dataset.open = page.startsWith("rules") ? "rules" : page.startsWith("review") ? "review" : "";
  closeDrawer();
  PAGES[page]().then(() => applyTips()).catch(e => { if (e.message !== "session") msg($("#main"), "err", e.message); });
}
document.querySelectorAll("#nav button").forEach(b => b.onclick = () => go(b.dataset.page));

/* ---------------- Dark / light ---------------- */
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("imw-theme", t); } catch (e) {}
  themeIcon();
}
function themeIcon() {
  const dark = document.documentElement.dataset.theme === "dark";
  $("#theme").textContent = dark ? "☀" : "☾";
  $("#theme").setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  $("#theme").title = (dark ? "Switch to light mode. " : "Switch to dark mode. ") + "Your choice is remembered in this browser.";
}
$("#theme").onclick = () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
themeIcon();

/* ---------------- Sign-in, lock, end session ---------------- */
let LOCKED = true, LAST_PING = 0;
function showLogin(why) {
  LOCKED = true;
  $("#login-why").textContent = why || "Sign in to continue.";
  $("#login").classList.remove("hidden");
  $("#main").innerHTML = ""; closeDrawer(); DIRTY.main = DIRTY.panel = false;
  $("#login-msg").innerHTML = ""; $("#signin").classList.remove("error");
  $("#login-pw").value = ""; $("#login-pw").type = "password"; $("#login-pw").focus();
}
async function checkSession() {
  const r = await fetch("/api/session", { headers: { "X-IMW": "1" } });
  if (r.status === 401) { document.body.innerHTML = "<p style='padding:30px'>Session ended. Restart the Workbench to get a new link.</p>"; return null; }
  return r.json();
}
$("#pw-toggle").onclick = () => {
  const pw = $("#login-pw"), show = pw.type === "password";
  pw.type = show ? "text" : "password"; $("#pw-toggle").setAttribute("aria-label", show ? "Hide password" : "Show password"); pw.focus();
};
["keydown", "keyup"].forEach(ev => $("#login-pw").addEventListener(ev, (e) => {
  if (e.getModifierState) $("#login-caps").classList.toggle("hidden", !e.getModifierState("CapsLock"));
}));
$("#login-pw").addEventListener("input", () => $("#signin").classList.remove("error"));
$("#login-form").onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#login-go");   // not "go": that would hide go(), and the page would stay blank
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span><span>Checking…</span>';
  try {
    await api("/api/unlock", { password: $("#login-pw").value });
    $("#login-pw").value = ""; $("#login-msg").innerHTML = ""; $("#signin").classList.remove("error");
    LOCKED = false; LAST_PING = Date.now();
    $("#login").classList.add("hidden");
    go(PAGE);
  } catch (err) {
    $("#login-msg").innerHTML = `<span>⚠</span><span>${esc(err.message)}</span>`;
    $("#signin").classList.add("error"); $("#login-pw").select();
  } finally { btn.disabled = false; btn.innerHTML = "<span>Unlock</span>"; }
};
$("#lock").onclick = async () => { await api("/api/lock", {}).catch(() => {}); showLogin("Session locked."); };
$("#logout").onclick = () => {
  $("#end-db").textContent = STATE.workspace ? STATE.workspace + (STATE.workspace.includes("\\") ? "\\" : "/") + "migration.db" : "migration.db";
  $("#end-confirm").value = ""; $("#end-del").checked = false; $("#end-msg").textContent = ""; syncEndDel();
  $("#endbox").classList.remove("hidden"); $("#end-go").focus();
};
$("#end-cancel").onclick = () => $("#endbox").classList.add("hidden");
// Ending is one click; deleting the database as well needs DELETE DB typed.
function syncEndDel() {
  const del = $("#end-del").checked;
  $("#end-confirm-row").classList.toggle("hidden", !del);
  $("#end-go").textContent = del ? "End session and delete the database" : "End session";
  if (del) $("#end-confirm").focus();
}
$("#end-del").onchange = syncEndDel;
$("#end-go").onclick = async () => {
  if ($("#end-del").checked && $("#end-confirm").value !== "DELETE DB") return $("#end-msg").innerHTML = '<span style="color:var(--err)">Type DELETE DB exactly to delete the database.</span>';
  try {
    const del = $("#end-del").checked;
    const r = await api("/api/end", { confirm: del ? "DELETE DB" : "END SESSION", delete_db: del });
    document.body.innerHTML = `<p style='padding:30px'>Session ended and the Workbench has stopped.
      ${(r.not_deleted || []).length ? "Some database files could not be deleted (" + esc(r.not_deleted.join(", ")) + "), probably because Windows still had them open. They stay encrypted for your Windows account; delete them from the workspace folder." : r.database_deleted ? "The database was securely deleted." : "The database is still on disk, encrypted for your Windows account. Start the Workbench again to open it."}
      You can close this tab.</p>`;
  } catch (e) { $("#end-msg").innerHTML = `<span style="color:var(--err)">${esc(e.message)}</span>`; }
};
// Real use (keys, clicks, mouse) keeps the session open; nothing else does.
["keydown", "mousedown", "mousemove", "wheel", "touchstart"].forEach(ev => document.addEventListener(ev, () => {
  if (!LOCKED && Date.now() - LAST_PING > 60000) { LAST_PING = Date.now(); api("/api/ping", {}).catch(() => {}); }
}, { passive: true }));
setInterval(async () => {
  if (LOCKED) return;
  const s = await checkSession().catch(() => null);
  if (s && s.locked) showLogin("Locked after " + s.idle_minutes + " minutes without activity. Sign in again to continue.");
}, 30000);
async function start() {
  const s = await checkSession();
  if (!s) return;
  $("#login-user").textContent = s.user;
  const short = String(s.user || "").split(/[\\@ ]/).filter(Boolean);
  const nm = (short.length > 1 && /\\/.test(s.user) ? short[1] : short[0]) || "?";
  $("#login-avatar").textContent = nm.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
  $("#login-idle").textContent = s.idle_minutes;
  if (s.locked) showLogin("Sign in to continue.");
  else { LOCKED = false; go("overview"); }
}

const PAGES = {};

/* ---------------- Forbidden characters, checked as you type ---------------- */
// The same characters the server removes from typed names (UNSAFE_LINE in imw/transform.py).
const INVISIBLE = /[\u0000-\u001f\u007f\u200b-\u200f\u2028\u2029\u2060\ufeff]/g;
const INVISIBLE_MSG = "invisible or control characters will be removed";
const hasInvisible = (v) => { INVISIBLE.lastIndex = 0; return INVISIBLE.test(v); };
const CHECKS = {
  safe: (v) => {
    const bad = [...new Set(v.match(/[\\/:*?"<>|]/g) || [])];
    const out = hasInvisible(v) ? [INVISIBLE_MSG] : [];
    if (bad.length) out.push(`${bad.join(" ")} not allowed in Safe names: will become "-"`);
    if (v.replace(/\{[^}]*\}/g, "").length > 28 && !/\{/.test(v)) out.push(`${v.length} characters: Safe names are cut to 28`);
    return out.join("; ");
  },
  platform: (v) => {
    if (v === "(none)") return "";
    const bad = [...new Set(v.replace(INVISIBLE, "").match(/[^A-Za-z0-9_.\-]/g) || [])].map(c => c === " " ? "space" : c);
    return [hasInvisible(v) ? INVISIBLE_MSG : "", bad.length ? `${bad.join(" ")} not allowed in a platform ID: will become "_"` : ""].filter(Boolean).join("; ");
  },
  account: (v) => {
    const bad = [...new Set(v.match(/[\\/:*?"<>|]/g) || [])];
    return [hasInvisible(v) ? INVISIBLE_MSG : "", bad.length ? `${bad.join(" ")} not allowed in account names: will become "_"` : ""].filter(Boolean).join("; ");
  },
  member: (v) => hasInvisible(v) ? INVISIBLE_MSG : "",
};
function checkInput(el) {
  if (!el || !el.dataset || !CHECKS[el.dataset.check]) return;
  const issue = el.value ? CHECKS[el.dataset.check](el.value) : "";
  let m = el.nextElementSibling && el.nextElementSibling.classList.contains("chk-msg") ? el.nextElementSibling : null;
  el.classList.toggle("chk-bad", !!issue);
  if (!issue) { if (m) m.remove(); return; }
  if (!m) { m = document.createElement("span"); m.className = "chk-msg"; el.after(m); }
  m.textContent = "⚠ " + issue;
}
document.addEventListener("input", (e) => checkInput(e.target));

/* ---------------- Tooltips on every input ---------------- */
const TIP_ID = {
  "login-pw": "Your Windows password. Windows checks it; the Workbench never stores it.",
  "end-confirm": "Type DELETE DB in capitals to confirm that the database is deleted.",
  "end-del": "Tick to overwrite and delete migration.db when the session ends. Output files are kept.",
  "dir-fallback": "searchIn for members no source above matches. Leave empty so Privilege Cloud searches every directory. Fill it only if names clash across directories: the directory's ID (GUID) from Identity, or Vault.",
  "dir-strip": "Remove the domain part (CORP\\ or @corp.example.com) from those members' names.",
  "dir-type": "Member type (memberType) used when the export doesn't say whether a member is a user, a group or a role.\nUser = one person's account; Group = a directory or Privilege Cloud group; Role = an Identity role.",
  "fallback": "How accounts with no rule are given a Safe. The default follows your folder structure, abbreviated.",
  "prefix": "Text added to the start of every Safe name, e.g. MIG-. Leave empty for none. Counts toward the 28 characters.",
  "conv-template": "Safe name pattern for accounts that have folders. {folder} = every folder level abbreviated, {folder_leaf} = the last one. Other placeholders: {env}, {tech}, {flavor}, {acct} and your own (under Codes used in names).\nA code already used earlier in the name is not repeated. If a name is too long, long folder names become initials first, then the top folder levels are left out.",
  "conv-flat": "Safe name pattern for accounts with no folders (flat KeePass files, spreadsheets), e.g. {env}-{tech}-{flavor}-{acct}.",
  "conv-skip": "Folder level names to leave out of Safe names, separated by commas, e.g. Root, Shared.",
  "max-acc": "Safes with more accounts than this are flagged for a look. CyberArk recommends roughly 3000-5000 at most.",
  "new-layer": "Name of a new placeholder, letters, digits and _ only (e.g. region). Use it as {region} in a Safe name pattern.",
  "s-cpm": "Name of the CPM that manages the Safes' accounts, e.g. PasswordManager. Empty = no CPM.",
  "s-desc": "Safe description, up to 100 characters. {folder} = the Safe's source folder, {safe} = its name.",
  "s-ver": "How many old passwords each Safe keeps (whole number).",
  "s-days": "How many days each Safe keeps old passwords (whole number).",
  "a-auto": "Ticked: the CPM changes passwords on its schedule. Unticked: accounts are uploaded with automatic management off.",
  "a-reason": "Reason recorded on accounts when automatic management is off.",
  "gr-first": "Ticked: access-group rules win over the folder exceptions.",
  "role-from": "The preset whose permissions a new custom role starts with. You can change every tick afterwards.",
  "defplat": "Platform ID for record types that no rule or table row covers. Empty = those accounts are flagged as errors.",
  "an-t": "Account name pattern. Placeholders: {name} {address} {username} {platform} {safe} {folder_leaf} {type} {source_id}.\nExamples: {name} (the source's own name) · {username}@{address} → svc_backup@srv01",
  "an-f": "Used when the pattern above comes out empty, e.g. {address}-{username}.",
  "url-host": "Ticked: an address like https://fw01.example.com/login becomes fw01.example.com.",
  "json": "Every setting as JSON. Only for settings the other pages don't cover.",
  "view": "Which accounts to list.", "f-safe": "Only accounts in this Safe.", "f-platform": "Only accounts on this platform.",
  "f-source": "Only accounts from this source.", "f-status": "Only accounts with this status.",
  "f-search": "Search account name, username, address, folder, record ID and Safe. Part of a word is enough.",
  "allmatch": "Ticked: the change applies to every account in this list (all pages), not only the ticked ones.",
  "reason": "Why you made the change. Saved with it in the activity log.",
  "a-safe": "Safe to move the ticked accounts to. Pick one or type a new name; forbidden characters \\ / : * ? \" < > | become -.",
  "a-plat": "Platform ID for the ticked accounts, exactly as in Privilege Cloud (letters, digits, _ . -). (none) removes the platform, so they are not uploaded.",
  "a-name": "New name for the one ticked account. \\ / : * ? \" < > | become _. To leave names empty so Privilege Cloud names them, use the button next to Rename.",
  "s-filter": "Show only Safes whose name contains this text.",
  "s-nofull": "Show only the Safes where no member has full permissions. Only shows or hides rows; changes nothing.",
  "m-reason": "Why you changed the members. Saved with the change in the activity log.",
  "m-name": "The member to add, as Privilege Cloud will search for it (no CORP\\ prefix if the directory below already says which domain).",
  "m-dir": "Optional searchIn. Leave empty so Privilege Cloud searches every directory. Fill it only if the name exists in more than one directory: the directory's ID (GUID) from Identity, or Vault.",
  "m-type": "User = one person's account; Group = a directory or Privilege Cloud group; Role = an Identity role.", "m-role": "Permission preset or custom role the member gets on the ticked Safes.",
  "m-rname": "Member to take off the ticked Safes, as shown in the Members table.",
  "o-safe": "Only accounts in this Safe.", "o-platform": "Only accounts on this platform.", "o-source": "Only accounts from this source.",
  "confirm": "Type INCLUDE SECRETS in capitals to write passwords into Accounts.csv.",
  "o-name": "Name of the output folder. Letters, digits, - and _ ; empty = the date and time.",
  "o-replace": "Ticked: an output folder with the same name is replaced.",
};
const MEMBER_TYPES = ["Group", "User", "Role"];
/* Plain words for the codes the rules record (shown instead of fallback:convention, platform_map and so on). */
const SORTABLE_COLS = new Set(["target_safe", "account_name", "username", "address", "platform_id", "status", "folder", "source", "record_id"]);
const STATUS_LABEL = { OK: "OK", REVIEW: "Needs a look", ERROR: "Error" };
const pill = (st) => st ? `<span class="pill ${esc(st)}">${esc(STATUS_LABEL[st] || st)}</span>` : "";
const APPROVED_TIP = "Approved by you: you looked at it and it is fine. It still shows as needing a look, and the approval goes away by itself if anything about the account changes.";
// "Needs a look" keeps its label; an approved one gets a green tick next to it.
const statusPill = (st, approved) => pill(st) + (st === "REVIEW" && approved === "Y" ? `<span class="approved" title="${esc(APPROVED_TIP)}">✓</span>` : "");
function howChosen(src) {
  return String(src || "").split(/;\s*|\s\|\s/).filter(Boolean).map(one => {
    const [kind, ...rest] = one.split(":"); const what = rest.join(":");
    const fallback = { convention: "the folder naming convention", folder_leaf: "the last folder",
      folder_path: "the whole folder path", unmapped: "no rule matched (UNMAPPED)" }[what] || "the naming convention";
    return ({ "fallback": fallback,
      "folder_rule": `the folder exception for ${what}`, "group_rule": `the access-group rule for ${what}`,
      "platform_rule": `a platform rule on ${what}`, "platform_map": "the record type list", "default": "the default platform",
      "source": "the export itself", "override": "your change", "none": "nothing" })[kind] || one;
  }).filter((v, i, a) => a.indexOf(v) === i).join(", ");
}
const PC_NAMES = '<span class="muted" title="No account name: Privilege Cloud generates one on upload">(named by Privilege Cloud)</span>';
const DIR_TIP = {
  name: "A label you choose, so you can tell sources apart in the preview. Not uploaded.\nExample: Corporate AD",
  match: "Which members this source takes, by the name in the export:\n• a domain: CORP or corp.example.com (matches CORP\\DBA-Team and dba-team@corp.example.com)\n• * : every member\n• re: and a regular expression on the full name: re:^APP_ (names starting APP_), re:(?i)admins$ (ending in admins)\nSources are checked top to bottom; the first match wins.",
  search_in: "Optional. Leave empty and Privilege Cloud searches every directory it knows for the member.\nFill it only when the same name exists in more than one directory: then give that directory's ID (a GUID) from Identity Administration, or Vault for Privilege Cloud's own users and groups.\nExample: 0b6c2e8a-1f4d-4c55-9a51-2f6c3d1e7a90",
  strip_domain: "yes = drop the domain from the name:\nCORP\\DBA-Team → DBA-Team\njdoe@corp.example.com → jdoe\nno = keep the name exactly as in the export.",
  find: "Optional. A regular expression to find in the name (after the domain is dropped). Upper/lower case is ignored.\nExamples: ^GRP- (GRP- at the start), _Admins$ (at the end), ^(.*)-RO$ (any name ending -RO; ( ) keeps the part before it)",
  replace: "What the found text becomes. Empty = remove it. \\1 puts back the first ( ) part of Find.\nExamples: Find ^GRP- Replace PAM- : GRP-DBA → PAM-DBA\nFind ^(.*)-RO$ Replace \\1-ReadOnly : Web-RO → Web-ReadOnly",
  add_prefix: "Text put in front of every name from this source, after Find/Replace.\nExample: PAM- turns DBA-Team into PAM-DBA-Team",
  add_suffix: "Text put after every name from this source, after Find/Replace.\nExample: @corp.example.com turns jdoe into jdoe@corp.example.com",
  case: "keep = as in the export; lower = all lower case (DBA-Team → dba-team); UPPER = all capitals (DBA-Team → DBA-TEAM).",
};
const TIP_KEY = {
  name: DIR_TIP.name, match: DIR_TIP.match, search_in: DIR_TIP.search_in, strip_domain: DIR_TIP.strip_domain,
  find: DIR_TIP.find, replace: DIR_TIP.replace, add_prefix: DIR_TIP.add_prefix, add_suffix: DIR_TIP.add_suffix, case: DIR_TIP.case,
  folder_prefix: "Folder path; accounts in it and every folder under it go to the Safe on this row, e.g. \\IT\\Network.",
  safe: "Target Safe name. Placeholders like {1}, {folder_leaf}, {convention} or {env} can be used.",
  word: "A word or phrase that appears in folder names.", code: "The 1-4 letter code it becomes in Safe names, e.g. BOS. Letters and digits only.",
  field: "What to look at: folder_word, folder_level, folder, platform, username, address, name, type, source, an earlier placeholder (env, tech, flavor, acct) or column:<source column name>.",
  pattern: "Regular expression, upper/lower case ignored. ^ = starts with, $ = ends with, | = or. Example: ^prod$|^live$.",
  field2: "Optional second thing to look at; both must match.", pattern2: "Pattern for the second thing to look at.",
  safe_pattern: "Safes whose name matches this pattern get the settings on this row, e.g. ^DB- or ^P-.",
  managingCPM: "CPM for these Safes. Empty = the default above.", description: "Description for these Safes. {folder} and {safe} can be used.",
  numberOfVersionsRetention: "Old passwords kept, as a number of versions. Fill this or days, not both.",
  numberOfDaysRetention: "Old passwords kept, as a number of days. Fill this or versions, not both.",
  group: "Access group exactly as in the export, e.g. CORP\\Unix-Admins.", group_pattern: "Or a pattern on the group name; its ( ) parts can be used in the Safe name as {1}, {2}.",
  min_role: "Only use this rule when the group has at least this role on the account.",
  role: "Permission word exactly as in the source export, e.g. Owner, View, Edit.", to: "Privilege Cloud preset or custom role it becomes.",
  type: "Record type or template name exactly as in the export, e.g. Windows Account.",
  platform: "Privilege Cloud platform ID, exactly as configured (letters, digits, _ . -), e.g. WinDomain.",
  column: "Source column name exactly as in the export.", property: "Platform property name it becomes, e.g. Port. It must exist on the platform.",
};
const TIP_CLASS = {
  pick: "Tick to load this file. Tick Permissions file too if it lists access instead of accounts.",
  perm: "This file lists access groups per folder or record. Ticking it also ticks Load.",
  src: "Which kind of export this is. Auto-detect usually works.",
  "l-label": "A name for this placeholder, for your reference.",
  "l-default": "Code used when no row below matches. Empty = the placeholder is left out of the name.",
  "role-name": "Name of the custom role. It must differ from the five presets.",
  "role-perm": "Tick to give this permission to the custom role.",
  "s-sel": "Tick to include this Safe in the add or remove below.", "m-sel": "Tick to remove this member from the Safe on its row.",
  sel: "Tick to include this account in the change below.",
};
function applyTips(root = document) {
  root.querySelectorAll("input, select, textarea").forEach(el => {
    if (el.title || el.type === "hidden") return;
    const tip = TIP_ID[el.id] || (el.dataset.k && TIP_KEY[el.dataset.k]) || (el.dataset.folder !== undefined && "Your own code for this folder name (1-4 letters). Empty = the automatic code shown in grey.")
      || [...el.classList].map(c => TIP_CLASS[c]).find(Boolean)
      || (el.name === "an-mode" && "Build each account name from the pattern, or leave names empty so Privilege Cloud generates them on upload.")
      || (el.name === "ret" && "Keep old passwords either as a number of versions or a number of days.")
      || (el.name === "scope" && "Everything, or only the accounts matching the choices on this line.")
      || (el.name === "sec" && "Dry run leaves passwords out; upload-ready decrypts them into Accounts.csv.");
    if (tip) el.title = tip;
  });
  root.querySelectorAll("[data-check]").forEach(el => { if (el.value) checkInput(el); });
}
let TIP_T;
new MutationObserver(() => { clearTimeout(TIP_T); TIP_T = setTimeout(() => applyTips(), 50); }).observe(document.body, { childList: true, subtree: true });

/* ---------------- Overview: where you are and what is next ---------------- */
PAGES.overview = async () => {
  await refresh();
  const m = $("#main");
  if (!STATE.has_db) {
    m.innerHTML = `<h2>Welcome</h2><p class="lead">This workbench turns exports from Delinea, KeePass, spreadsheets and other PAM tools into files ready to upload to Privilege Cloud. Nothing here connects to any system.</p>
      <div class="card"><h3>Get started</h3><ol>
        <li>Copy your export files into <code>${esc(STATE.inbox)}</code></li>
        <li>Go to <b>1. Load exports</b> and load them.</li>
        <li>Set up <b>2. Mapping rules</b>, check the results in <b>3. Review &amp; change</b>, then <b>4. Create upload files</b>.</li></ol>
        <button class="btn primary" data-go="load">Load exports</button></div>${securityNotice(true)}`;
    return;
  }
  const hints = (await api("/api/config")).hints || {};
  const c = STATE.status_counts || {};
  const open = (c.REVIEW || 0) - (STATE.approved || 0);
  const missing = (hints.types_without_platform || []).filter(Boolean);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const steps = [
    { n: 1, title: "Load exports", done: true, go: "load", label: "Load more",
      st: `${plural(STATE.records, "record", "records")} from ${plural(STATE.inputs.length, "file", "files")}.` },
    STATE.stale ? { n: 2, title: "Mapping rules", done: false, go: "rules-safes", label: "Open the rules",
      st: "Some loaded records haven't been mapped yet: click Save & apply on any rules page." }
    : missing.length ? { n: 2, title: "Mapping rules", done: false, go: "rules-platforms", label: "Give them a platform",
      st: `${plural(missing.length, "record type has", "record types have")} no platform yet: ${missing.map(esc).join(", ")}.` }
    : { n: 2, title: "Mapping rules", done: true, go: "rules-safes", label: "Open the rules", st: `Applied ${esc((STATE.mapped || "").slice(0, 16).replace("T", " "))} UTC.` },
    c.ERROR ? { n: 3, title: "Review & change", done: false, go: "review", view: "errors", label: "Show the errors",
      st: `${plural(c.ERROR, "account has an error", "accounts have errors")} and won't be uploaded${open ? `; ${open} need a look` : ""}.` }
    : open ? { n: 3, title: "Review & change", done: false, go: "review", view: "review_open", label: "Show them",
      st: `${plural(open, "account needs", "accounts need")} a look${STATE.approved ? ` (${STATE.approved} more approved by you)` : ""}.` }
    : { n: 3, title: "Review & change", done: true, go: "review-safes", label: "Open",
      st: STATE.approved ? `You approved all ${plural(STATE.approved, "account", "accounts")} that needed a look.` : "Nothing needs a look." },
    STATE.outputs.length ? { n: 4, title: "Create upload files", done: true, go: "output", label: "Create more",
      st: `${plural(STATE.outputs.length, "set", "sets")} created; the latest is ${esc(STATE.outputs[0].name)}.` }
    : { n: 4, title: "Create upload files", done: false, go: "output", label: "Create them", st: "Not created yet." },
  ];
  const next = steps.find(x => !x.done) || null;
  m.innerHTML = `<h2>Overview</h2><p class="lead">Where the migration stands and what to do next.</p>
    ${statusNotes()}
    <div class="card"><h3>Steps</h3><ol class="steps">
      ${steps.map(x => `<li class="${x.done ? "done" : "todo"}${x === next ? " next" : ""}"><span class="dot">${x.done ? "✓" : x.n}</span>
        <div style="flex:1"><b>${x.n}. ${esc(x.title)}</b><span class="st">${x.st}</span></div>
        <button class="btn${x === next ? " primary" : " small"}" data-go="${x.go}"${x.view ? ` data-review-view="${x.view}"` : ""}>${esc(x === next ? "Next: " + x.label : x.label)}</button></li>`).join("")}
    </ol></div>
    <div class="card"><h3>What the upload will hold</h3>${readyTiles()}</div>
    <p class="muted small">Workspace: <code>${esc(STATE.workspace)}</code></p>${securityNotice(false)}`;
  wireTiles();
};

// Warnings shown on the Overview and the Create upload files page.
function statusNotes() {
  let next = "";
  if (STATE.sanitized) next += `<div class="msg warn">${STATE.sanitized} accounts had forbidden characters: invisible or control characters were removed, or characters Privilege Cloud doesn't allow in Safe, platform or account names were replaced. <a href="#" data-go="review" data-review-view="sanitized">Show them</a>.</div>`;
  if (STATE.stale) next += `<div class="msg warn">Some loaded records haven't been mapped yet. Open <b>2. Mapping rules</b> and click Save &amp; apply.</div>`;
  return next;
}

/* The count tiles (the "ready check"): on the Overview and at the top of 4. Create upload files. Each opens its list. */
function readyTiles() {
  const c = STATE.status_counts || {};
  const tile = (attr, tip, n, label, color) => `<div class="stat link" ${attr} title="${esc(tip)}"><b${color ? ` style="color:${color}"` : ""}>${n}</b><span>${label}</span></div>`;
  return `<div class="stats">
      ${tile('data-view="upload"', "Show the accounts that will be uploaded", STATE.to_upload, "will be uploaded")}
      ${tile('data-view="review"', "Show the accounts that need a look. A green tick means you approved one.", c.REVIEW || 0,
        `need a look${STATE.approved ? ` · <span class="approved">✓</span> ${STATE.approved} approved` : ""}`, (c.REVIEW || 0) > (STATE.approved || 0) ? "var(--warn)" : "")}
      ${tile('data-view="errors"', "Show the accounts with errors", c.ERROR || 0, "errors (not uploaded)", c.ERROR ? "var(--err)" : "")}
      ${tile('data-view="excluded"', "Show the accounts you left out", STATE.excluded, "left out by you")}
      ${tile('data-goto="review-safes"', "Show the Safes and their members", STATE.safes, `Safes${STATE.invalid_safes ? ` (${STATE.invalid_safes} renamed)` : ""}`)}
      ${tile('data-view="edited"', "Show the accounts you changed", STATE.edits, "accounts you changed")}
      ${STATE.sanitized ? tile('data-view="sanitized"', "Show the accounts where forbidden characters were removed or replaced", STATE.sanitized, "forbidden characters changed", "var(--warn)") : ""}
      ${tile('data-view="all"', "Show all accounts", STATE.records, "records loaded")}
    </div>`;
}
function wireTiles() {
  document.querySelectorAll(".stat[data-view]").forEach(el => el.onclick = () => {
    REVIEW.view = el.dataset.view; REVIEW.filters = {}; REVIEW.page = 0; REVIEW.selected.clear(); go("review"); });
  document.querySelectorAll(".stat[data-goto]").forEach(el => el.onclick = () => go(el.dataset.goto));
}
// C. Finalize became the ready check at the top of step 4.
PAGES["review-finalize"] = async () => go("output");

/* ---------------- Security notice (bottom of the Overview) ---------------- */
// Plain-language summary of how the Workbench is built and how it treats your data.
// Keep it in step with imw/ui/server.py (security model), imw/protect.py and imw/owner.py.
// Shown open on the Welcome page, folded on the Overview.
const securityNotice = (open) => `<details class="card fold security-notice" style="margin-top:24px"${open ? " open" : ""}><summary>Security and data handling</summary>
  <p class="small"><b>How the Workbench is built.</b> It is a Python program (standard library only, nothing extra to install)
    that runs on this computer as the Windows user who started it. Nothing connects to Delinea, KeePass, Privilege Cloud or any
    other system, and nothing is sent over the internet. This page talks only to that program, at <code>https://127.0.0.1</code>.</p>
  <p class="small"><b>Where your data lives.</b> Everything stays in the workspace folder: the files you copy into <code>inbox</code>,
    the working database <code>migration.db</code> (SQLite), <code>config.json</code> with your rules, and the files you create in
    <code>output</code>. Account details such as names, addresses, usernames and folders are stored in the database as readable
    text so you can filter and change them. Passwords and keys are encrypted one by one with Windows DPAPI, which ties them to
    your Windows account on this computer: another user, or a copy of the database on another machine, cannot decrypt them.</p>
  <p class="small"><b>How it is secured.</b></p>
  <ul class="small">
    <li>Only you: the workspace folder is locked to your Windows account (and SYSTEM). The Workbench refuses to open a workspace
      created by another user, and refuses connections from other users' programs on this computer.</li>
    <li>Sign-in: Windows checks your password before anything is shown. The page locks after 10 minutes without activity, or when
      you click Lock session.</li>
    <li>Connection: HTTPS with a certificate made for this computer, a one-time start link, a session cookie scripts cannot read,
      and checks that every request comes from this page. The page runs no inline or outside scripts.</li>
    <li>Files you load: XML with DTDs or entities is refused, and spreadsheet parts have a size limit.</li>
    <li>Review files (<code>review</code> folder) never hold passwords. Values that Excel could run as formulas are written
      with a leading apostrophe.</li>
    <li>Every load, change, export and sign-in is written to the Activity log with the Windows user and time.</li>
  </ul>
  <div class="msg warn small"><b>Your responsibility.</b> If you tick <b>include secrets</b> in step 4, <code>upload/Accounts.csv</code>
    holds every password in <b>plain text</b>. That is what the Privilege Cloud API needs. Keep that file only as long as you need it,
    never email it or store it on a shared drive, and delete it from step 4 when the upload is done (it is overwritten before it is
    deleted). When the migration is finished, use <b>End session</b> and tick the box to securely delete the database.
    Keep the workspace on an encrypted drive (BitLocker or similar) on the migration host, and lock the computer when you step away: your Windows account protects everything else.</div>
</details>`;

/* ---------------- 1. Load ---------------- */
const SOURCE_NAMES = { delinea: "Delinea", keepass: "KeePass", table: "Spreadsheet (CSV / Excel)" };
function loadedFilesHtml() {
  const inputs = STATE.inputs || [];
  if (!inputs.length) return "";
  const repeat = inputs.some(i => i.repeat);
  return `<details class="card fold" id="loaded-files"${repeat ? " open" : ""}><summary>Loaded so far (${inputs.length} ${inputs.length === 1 ? "file" : "files"}, ${STATE.records} records)</summary>
    ${repeat ? `<div class="msg warn">Some files were loaded more than once. Loading a file with the same name again replaces its records (matched by record ID) and keeps your changes; records missing from the newer file stay from the earlier load. Loading the same content under a different file name loads every record a second time, which shows up as possible duplicates.</div>` : ""}
    <div class="tablewrap"><table class="small"><tr><th>#</th><th>Source</th><th>File</th><th>Records</th><th title="SHA-256 checksum of the file as it was loaded">Checksum</th><th>Loaded more than once?</th><th>Permissions file(s)</th><th>Loaded (UTC)</th><th>By</th></tr>
    ${inputs.map(i => `<tr><td>${i.id}</td><td>${esc(SOURCE_NAMES[i.source] || i.source)}</td><td title="${esc(i.path)}">${esc(i.file)}</td><td>${i.records}</td>
      <td><code title="${esc(i.sha256)}">${esc((i.sha256 || "").slice(0, 12))}…</code></td>
      <td>${i.repeat ? `<span class="pill ${/different|twice/.test(i.repeat) ? "REVIEW" : "OK"}">${/different/.test(i.repeat) ? "different content" : /twice/.test(i.repeat) ? "same content, other name" : "same content"}</span> ${esc(i.repeat)}` : '<span class="muted">first load</span>'}</td>
      <td>${i.permissions_path ? i.permissions_path.split(" | ").map((pth, k) => `${esc(pth.split(/[\\/]/).pop())} <code title="${esc((i.permissions_sha256 || "").split(" | ")[k] || "")}">${esc(((i.permissions_sha256 || "").split(" | ")[k] || "").slice(0, 8))}…</code>`).join("<br>") : '<span class="muted">none</span>'}</td>
      <td>${esc(String(i.loaded_utc || "").slice(0, 16).replace("T", " "))}</td><td>${esc(i.loaded_by)}</td></tr>`).join("")}</table></div></details>`;
}
/* Column picker: a spreadsheet whose headers the Workbench didn't recognise (no username or
   address found) gets a card to say which column holds what, instead of editing JSON. */
let COLUMN_PICK = null;   // {results, perm} from the last load, shown once on the Load page
const PICK_FIELDS = [["name", "Account name", "The account's display name, e.g. a Secret Name or Title column."],
  ["address", "Address", "Host name, IP address or URL the account is for, e.g. TargetHost or Server."],
  ["username", "Username", "The account's user name, e.g. SAMAccountName or Login."],
  ["folder", "Folder path", "Folder the account sits in; Safes are named from it, e.g. \\IT\\Windows."],
  ["type", "Record type", "A type or template column; the platform is chosen from it (step 2 C. Platforms)."],
  ["password", "Password", "The column holding the password. Never shown in the review files."],
  ["private_key", "SSH key", "A column holding a private SSH key, if any."],
  ["access", "Access groups", "Who has access, e.g. CORP\\DBA-Team=Owner; CORP\\Ops=View."],
  ["safe", "Target Safe", "Optional: a column that names each account's Safe directly."],
  ["platform", "Platform ID", "Optional: a column that names each account's platform directly."],
  ["id", "Record ID", "Optional: a unique ID per row. Without one, rows are numbered."]];
const FIELD_WORD = { username: "username", address: "address" };
function columnPickHtml() {
  if (!COLUMN_PICK) return "";
  return COLUMN_PICK.results.filter(x => x.columns).map((x, n) => `<div class="card col-pick-card" data-file="${esc(x.name)}">
    <h3>Which column holds what in ${esc(x.name)}?</h3>
    <div class="msg warn">No ${x.columns.missing.map(k => FIELD_WORD[k]).join(" or ")} was found in any row of ${esc(x.name)}, so its accounts can't be uploaded yet.
      The column names probably differ from the usual ones (Username, Address...). Pick the right column for each field and load the file again.</div>
    <table class="small col-pick"><tr><th>Field</th><th>Column in ${esc(x.name)}</th></tr>
    ${PICK_FIELDS.map(([k, label, tip]) => `<tr><td title="${esc(tip)}">${esc(label)}${x.columns.missing.includes(k) ? ' <span class="pill ERROR">not found</span>' : ""}</td>
      <td><select class="col-pick-sel" data-field="${k}" title="${esc(tip)} Automatic uses the usual column names for this field.">
        <option value="">${x.columns.current[k] ? `Automatic (now: ${esc(x.columns.current[k])})` : "Automatic (none found)"}</option>
        ${x.columns.headers.map(h => `<option value="${esc(h)}">${esc(h)}</option>`).join("")}</select></td></tr>`).join("")}</table>
    <p class="muted small">Your choice is used for every spreadsheet you load from now on. You can change it later under 2. Mapping rules, Advanced (sources → table → columns).</p>
    <div class="row"><button class="btn primary col-pick-go" data-n="${n}">Save and load ${esc(x.name)} again</button><span class="col-pick-msg"></span></div></div>`).join("");
}
function wireColumnPick() {
  const pick = COLUMN_PICK; COLUMN_PICK = null;
  if (!pick) return;
  document.querySelectorAll(".col-pick-card").forEach(card => {
    $(".col-pick-go", card).onclick = async () => {
      const chosen = {}; card.querySelectorAll(".col-pick-sel").forEach(sel => { if (sel.value) chosen[sel.dataset.field] = sel.value; });
      if (!Object.keys(chosen).length) return msg($(".col-pick-msg", card), "err", "Pick at least one column first.");
      try {
        const { config: cfg } = await api("/api/config");
        const sources = JSON.parse(JSON.stringify(cfg.sources));
        sources.table.columns = { ...(sources.table.columns || {}), ...chosen };
        await api("/api/config", { patch: { sources } });
        saved("main");
        const r = await api("/api/ingest", { files: [{ name: card.dataset.file, source: "table" }], permissions: pick.perm });
        await refresh();
        const x = r.results[0];
        LAST_LOAD = `<div class="msg ${x.columns ? "warn" : "ok"}">${esc(x.name)}: ${x.records} records loaded again with the columns you picked${x.columns ? `, but there is still no ${x.columns.missing.map(k => FIELD_WORD[k]).join(" or ")}. Check the picks below.` : ". Mapping rules applied."}</div>`;
        if (x.columns) COLUMN_PICK = { results: r.results, perm: pick.perm };
        await PAGES.load();
      } catch (e) { msg($(".col-pick-msg", card), "err", e.message); }
    };
  });
}
PAGES.load = async () => {
  await refresh();
  const files = STATE.inbox_files;
  const srcOpts = (sel) => `<option value="">Auto-detect${sel ? " (" + esc(SOURCE_NAMES[sel] || sel) + ")" : ""}</option>` +
    Object.entries(STATE.sources).map(([k, d]) => `<option value="${esc(k)}">${esc(SOURCE_NAMES[k] || k)}: ${esc(d)}</option>`).join("");
  const loadedSame = files.filter(f => f.loaded === "same");
  const status = (f) => f.loaded === "same" ? '<span class="pill OK" title="This file is loaded and hasn\'t changed since">loaded</span>'
    : f.loaded === "changed" ? '<span class="pill REVIEW" title="A file with this name was loaded, but its content has changed since. Load it again to update its records; your changes are kept.">changed since loaded</span>'
    : '<span class="muted small">not loaded</span>';
  $("#main").innerHTML = `<h2>1. Load exports</h2>
    <p class="lead">Copy export files into the inbox folder, tick the ones to load, then click Load.</p>
    <div class="card"><h3>Inbox: <a class="pathlink" id="open-inbox" title="Open this folder in Explorer"><code>${esc(STATE.inbox)}</code></a>
      <button class="btn small" id="open-inbox2">Open folder</button></h3>
    ${files.length ? `<table><tr><th title="Tick every file to use: exports and permissions files">Load</th><th>File</th><th>Status</th><th>Size</th><th title="Which kind of export this is. It is detected from the file; click change if the guess is wrong.">Type</th>
        <th class="has-tip" title="A permissions file lists groups per folder or record (columns: Folder Path, Secret Name, Secret ID, Group, Permission). Use one when the export itself has no access data, as with Delinea and KeePass. Tick several to merge them; a group listed in more than one file for the same folder is counted once.">Permissions file <span class="q">?</span></th><th></th></tr>
      ${files.map((f, i) => `<tr><td><input type="checkbox" class="pick" data-i="${i}" ${(f.guess || f.permissions) && f.loaded !== "same" ? "checked" : ""}></td>
        <td>${esc(f.name)}</td><td>${status(f)}</td><td class="nowrap">${(f.size / 1024).toFixed(1)} KB</td>
        <td>${f.guess ? `<span class="src-show">${esc(SOURCE_NAMES[f.guess] || f.guess)} <button class="linkbtn src-change" data-i="${i}">change</button></span>` : ""}
          <select class="src${f.guess ? " hidden" : ""}" data-i="${i}">${srcOpts(f.guess)}</select></td>
        <td><label class="inline"><input type="checkbox" class="perm" data-i="${i}" ${f.permissions ? "checked" : ""}>${f.permissions ? ' <span class="muted small">looks like one</span>' : ""}</label></td>
        <td class="x"><button class="btn small del" data-name="${esc(f.name)}" title="Securely delete ${esc(f.name)}: overwrite it, then delete it">✕</button></td></tr>`).join("")}</table>
      <div class="row" style="margin-top:12px"><button class="btn primary" id="go-load">Load selected files</button>
        <button class="btn" id="re">Refresh list</button>
        ${loadedSame.length ? `<button class="btn danger" id="del-loaded" title="Overwrite and delete the export files that are loaded and unchanged: ${esc(loadedSame.map(f => f.name).join(", "))}">Securely delete the loaded exports (${loadedSame.length})</button>` : ""}</div>`
      : `<p class="muted">The inbox is empty. Copy your export files into the folder above, then <button class="btn" id="re">Refresh</button></p>`}
    <div id="load-msg">${LAST_LOAD}</div></div>
    ${columnPickHtml()}
    ${loadedFilesHtml()}`;
  LAST_LOAD = "";
  wireColumnPick();
  $("#re").onclick = () => go("load");
  const openInbox = async () => {
    try { const r = await api("/api/open", { which: "inbox" }); if (!r.opened) alert("Open this folder yourself: " + r.path); }
    catch (e) { msg($("#load-msg"), "err", e.message); }
  };
  $("#open-inbox").onclick = openInbox; $("#open-inbox2").onclick = openInbox;
  document.querySelectorAll(".src-change").forEach(b => b.onclick = () => {
    b.parentElement.classList.add("hidden"); const sel = document.querySelector(`.src[data-i="${b.dataset.i}"]`); sel.classList.remove("hidden"); sel.focus(); });
  // "Load" says which files to use; "Permissions file" says how to use one. Ticking it as a permissions file also ticks Load.
  document.querySelectorAll(".perm").forEach(cb => cb.onchange = () => {
    const p = document.querySelector(`.pick[data-i="${cb.dataset.i}"]`); if (cb.checked && p) p.checked = true; });
  document.querySelectorAll(".del").forEach(b => b.onclick = async () => {
    if (!confirm(`Overwrite and delete ${b.dataset.name}? This can't be undone.`)) return;
    try { await api("/api/inbox/delete", { name: b.dataset.name }); go("load"); } catch (e) { msg($("#load-msg"), "err", e.message); }
  });
  if ($("#del-loaded")) $("#del-loaded").onclick = async () => {
    if (!confirm(`Overwrite and delete these loaded exports? This can't be undone.\n\n${loadedSame.map(f => f.name).join("\n")}`)) return;
    try { for (const f of loadedSame) await api("/api/inbox/delete", { name: f.name }); go("load"); }
    catch (e) { msg($("#load-msg"), "err", e.message); }
  };
  const btn = $("#go-load");
  if (btn) btn.onclick = async () => {
    const ticked = [...document.querySelectorAll(".pick:checked")].map(cb => cb.dataset.i);
    const isPerm = (i) => document.querySelector(`.perm[data-i="${i}"]`).checked;
    const perm = ticked.filter(isPerm).map(i => files[i].name);
    const picks = ticked.filter(i => !isPerm(i)).map(i => ({ name: files[i].name, source: document.querySelector(`.src[data-i="${i}"]`).value }));
    if (!picks.length) return msg($("#load-msg"), "err", perm.length ? "Tick at least one export file to load as well; permissions files only add access to the records of an export." : "Tick the files to load first.");
    try {
      const r = await api("/api/ingest", { files: picks, permissions: perm });
      await refresh();
      if (r.results.some(x => x.columns)) COLUMN_PICK = { results: r.results, perm };
      LAST_LOAD = `<div class="msg ok">${r.results.map(x => `${esc(x.name)}: ${x.records} records loaded as ${esc(SOURCE_NAMES[x.source] || x.source)}${x.replaced ? ` (${x.replaced} replaced)` : ""}${x.sanitized ? `; <b style="color:var(--warn)">${x.sanitized} with forbidden characters removed</b>` : ""}`).join("<br>")}
        ${perm.length ? `<br>Permissions merged from ${perm.map(esc).join(", ")}.` : ""}
        <br>Mapping rules applied.${STATE.protector === "dpapi" ? " Secrets are encrypted in the database now, so you can securely delete the loaded exports (button above)." : ""}</div>
        ${r.results.some(x => x.sanitized) ? `<div class="msg warn">Some values held invisible or control characters (for example zero-width spaces or line breaks inside a name). They were removed and each account notes which fields changed. <a href="#" data-go="review" data-review-view="sanitized">Show them</a></div>` : ""}
        <button class="btn primary" data-go="rules-safes">Next: 2. Mapping rules ›</button>`;
      await PAGES.load();   // shows each file as loaded, with the message below
    } catch (e) { msg($("#load-msg"), "err", e.message); }
  };
};

/* ---------------- 2. Rules ---------------- */
const PERM_GROUPS = [
  ["Access", [["useAccounts", "Use accounts"], ["retrieveAccounts", "Retrieve accounts"], ["listAccounts", "List accounts"]]],
  ["Account management", [["addAccounts", "Add accounts"], ["updateAccountContent", "Update account content"],
    ["updateAccountProperties", "Update account properties"], ["initiateCPMAccountManagementOperations", "Initiate CPM account management operations"],
    ["specifyNextAccountContent", "Specify next account content"], ["renameAccounts", "Rename accounts"],
    ["deleteAccounts", "Delete accounts"], ["unlockAccounts", "Unlock accounts"]]],
  ["Safe management", [["manageSafe", "Manage Safe"], ["manageSafeMembers", "Manage Safe members"], ["backupSafe", "Backup Safe"]]],
  ["Monitoring", [["viewAuditLog", "View audit log"], ["viewSafeMembers", "View Safe members"]]],
  ["Workflow", [["requestsAuthorizationLevel1", "Authorize account requests, level 1"],
    ["requestsAuthorizationLevel2", "Authorize account requests, level 2"], ["accessWithoutConfirmation", "Access Safe without confirmation"]]],
  ["Advanced", [["createFolders", "Create folders"], ["deleteFolders", "Delete folders"], ["moveAccountsAndFolders", "Move accounts and folders"]]],
];
const LAYER_FIELDS = ["folder_word", "folder_level", "folder", "platform", "username", "address", "name", "type", "source",
  "env", "tech", "flavor", "acct", "column:"];
let ROLE_NAMES = () => [];
let TABLES = {};
// Input tables start folded; the summary shows how many rows there are and opens them for editing.
function editBlock(summary, inner, id = "", open = false, cls = "", editLabel = "Edit") {
  return `<details class="edit-block${cls ? " " + cls : ""}"${id ? ` data-block="${esc(id)}"` : ""}${open ? " open" : ""}><summary><span class="arrow">▸</span>
    <span class="edit-sum">${summary}</span><span class="edit-btn"><span class="o">${esc(editLabel)}</span><span class="c">Done</span></span></summary>${inner}</details>`;
}
const rowCount = (n) => n ? `${n} ${n === 1 ? "row" : "rows"}` : '<span class="muted">none yet</span>';
// A preview table that shows its first 10 rows, with a button for the rest.
function firstRows(head, rows, n = 10) {
  const id = "fr" + Math.random().toString(36).slice(2, 8);
  return `<div class="tablewrap" style="margin-top:10px;max-height:60vh">${head}${rows.map((r, i) => i < n ? r : r.replace("<tr", `<tr class="hidden more-${id}"`)).join("")}</table></div>
    ${rows.length > n ? `<button class="linkbtn" data-show-more="${id}">Show all ${rows.length}</button>` : ""}`;
}
document.addEventListener("click", (e) => {
  const b = e.target.closest && e.target.closest("[data-show-more]");
  if (b) { document.querySelectorAll(".more-" + b.dataset.showMore).forEach(tr => tr.classList.remove("hidden")); b.remove(); }
});
// "How this page works": folded, so the inputs come first; the tooltips cover each field.
const explain = (inner, label = "How this page works") => `<details class="explain"><summary>${esc(label)}</summary>${inner}</details>`;
function editorTable(id, cols, rows, addLabel = "+ Add row", open = false) {
  TABLES[id] = cols;
  return editBlock(rowCount(rows.length), `<table class="editor" id="${esc(id)}"><tr>${cols.map(c => `<th${c.tip ? ` class="has-tip" title="${esc(c.tip)}"` : ""}>${esc(c.label)}${c.tip ? ' <span class="q">?</span>' : ""}</th>`).join("")}<th></th></tr>
    ${rows.map(r => editorRow(cols, r)).join("")}</table>
    <button class="btn small" data-add="${esc(id)}">${esc(addLabel)}</button>`, id, open, "", rows.length ? "Edit" : "+ Add");
}
function roleOptions(value, blank) {
  const names = ROLE_NAMES();
  const opts = (blank ? [""] : []).concat(names);
  if (value && !names.includes(value)) opts.push(value);
  return opts.map(o => `<option ${o === (value || "") ? "selected" : ""}>${esc(o)}</option>`).join("");
}
/* Match operators: most rules only need "contains", "starts with"... so the pattern columns
   show a picker and plain text, and the Workbench writes the regular expression. A pattern
   that isn't one of these simple forms opens as "Regex". Every pattern is case-insensitive. */
const MATCH_OPS = [["contains", "Contains"], ["starts", "Starts with"], ["ends", "Ends with"], ["equals", "Equals"], ["regex", "Regex (advanced)"]];
const MATCH_TIP = {
  contains: "Text to look for anywhere in the value. Upper/lower case is ignored. Example: unix",
  starts: "Text the value starts with. Upper/lower case is ignored. Example: svc_",
  ends: "Text the value ends with. Upper/lower case is ignored. Example: .corp.example.com",
  equals: "The whole value, exactly (upper/lower case is ignored). Example: Prod",
  regex: "A regular expression (Python syntax), upper/lower case ignored. ^ = starts with, $ = ends with, | = or, ( ) = a part you can reuse as {1}.\nExamples: ^prod$|^live$ · ^CORP\\\\APP-(.+)-Owners$",
};
const reEsc = (t) => String(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// The text of a pattern with no special characters (escaped ones allowed), or null.
function reLiteral(p) {
  let out = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "\\") { const n = p[i + 1]; if (n === undefined || /[A-Za-z0-9]/.test(n)) return null; out += n; i++; }
    else if (".*+?^${}()|[]".includes(c)) return null;
    else out += c;
  }
  return out;
}
function toPattern(op, text) {
  if (op === "regex" || !text) return text;
  const t = reEsc(text);
  return op === "starts" ? "^" + t : op === "ends" ? t + "$" : op === "equals" ? "^" + t + "$" : t;
}
function fromPattern(p) {
  p = String(p ?? "");
  if (!p) return ["contains", ""];
  const core = p.replace(/^\(\?i\)/, "");
  const tries = [["equals", /^\^(.*)\$$/], ["starts", /^\^(.*)$/], ["ends", /^(.*)\$$/], ["contains", /^(.*)$/]];
  for (const [op, re] of tries) {
    const m = core.match(re); if (!m) continue;
    const t = reLiteral(m[1]); if (t !== null && t !== "") return [op, t];
  }
  return ["regex", p];
}
// A Python pattern as a JavaScript RegExp (for previews only), or null.
function jsRegex(p) {
  try { return new RegExp(String(p).replace(/^\(\?i\)/, "").replace(/\(\?P</g, "(?<"), "i"); } catch (e) { return null; }
}
function matchCell(c, value, tt) {
  const [op, text] = fromPattern(value);
  return `<td class="match-cell"><div class="match"><select class="m-op" data-op-for="${c.key}" data-prev="${op}">${MATCH_OPS.map(([v, l]) => `<option value="${v}" ${v === op ? "selected" : ""}>${l}</option>`).join("")}</select><input type="text" data-k="${c.key}" data-match="1" title="${esc(MATCH_TIP[op])}" value="${esc(text)}" placeholder="${esc(op === "regex" ? c.ph || "" : c.phText || "")}"${c.size ? ` size="${c.size}"` : ""}></div></td>`;
}
// Changing the operator keeps what the rule does where it can: to Regex shows the pattern it was, from Regex shows the plain text when there is one.
document.addEventListener("change", (e) => {
  const sel = e.target.closest && e.target.closest("select.m-op"); if (!sel) return;
  const inp = sel.parentElement.querySelector("input[data-match]"), prev = sel.dataset.prev || "contains";
  if (sel.value === "regex" && prev !== "regex") inp.value = toPattern(prev, inp.value.trim());
  else if (sel.value !== "regex" && prev === "regex") { const [, t] = fromPattern(inp.value.trim()); if (fromPattern(inp.value.trim())[0] !== "regex") inp.value = t; }
  sel.dataset.prev = sel.value;
  inp.title = MATCH_TIP[sel.value];
  const col = (TABLES[sel.closest("table").id] || []).find(c => c.key === sel.dataset.opFor) || {};
  inp.placeholder = sel.value === "regex" ? col.ph || "" : col.phText || "";
  inp.dispatchEvent(new Event("input", { bubbles: true }));
});
document.addEventListener("focusin", (e) => { if (e.target.matches && e.target.matches("select.m-op")) e.target.dataset.prev = e.target.value; });
function editorRow(cols, r = {}) {
  const tt = (c) => c.tip ? ` title="${esc(c.tip)}"` : "";
  return `<tr>${cols.map(c => c.match ? matchCell(c, r[c.key], tt) : c.roles
    ? `<td><select class="role-select" data-blank="${c.blank ? 1 : ""}" data-k="${c.key}"${tt(c)}>${roleOptions(r[c.key] || "", c.blank)}</select></td>`
    : c.options
    ? `<td><select data-k="${c.key}"${tt(c)}>${c.options.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o];
        return `<option value="${esc(v)}" ${String(v) === String(r[c.key] ?? c.def ?? "") ? "selected" : ""}>${esc(l)}</option>`; }).join("")}</select></td>`
    : `<td><input type="text" data-k="${c.key}"${tt(c)} value="${esc(r[c.key] ?? "")}" placeholder="${esc(c.ph || "")}"${c.list ? ` list="${c.list}"` : ""}${c.size ? ` size="${c.size}"` : ""}${c.key === "safe" ? ' data-check="safe"' : c.key === "platform" ? ' data-check="platform"' : ""}></td>`).join("")}
    <td class="x"><button class="btn small row-del" title="Remove this row">✕</button></td></tr>`;
}
function readTable(id) {
  return [...document.querySelectorAll(`#${id} tr`)].slice(1).map(tr => {
    const o = {}; tr.querySelectorAll("[data-k]").forEach(i => {
      let v = i.value.trim();
      if (v && i.dataset.match) { const op = i.parentElement.querySelector("select.m-op"); v = toPattern(op ? op.value : "regex", v); }
      if (v) o[i.dataset.k] = v; }); return o;
  }).filter(o => Object.keys(o).length);
}
function wireAddButtons(root = document) {
  root.querySelectorAll("[data-add]").forEach(b => b.onclick = () => {
    $(`#${b.dataset.add}`).insertAdjacentHTML("beforeend", editorRow(TABLES[b.dataset.add]));
    updateBlockCount(b.dataset.add);
  });
}
function updateBlockCount(id) {
  const t = $(`#${id}`); if (!t) return;
  const d = t.closest("details.edit-block"); if (d) { const n = t.querySelectorAll("tr").length - 1;
    $(".edit-sum", d).innerHTML = rowCount(n); $(".edit-btn .o", d).textContent = n ? "Edit" : "+ Add"; }
  if (typeof onTableCount === "function") onTableCount(id);
}
let onTableCount = null;   // a page can listen for row counts changing (the Safes page's placeholder summaries)
const normName = (t) => String(t).toLowerCase().split(/[\s\-_/\\:;,.()\[\]{}"'&+]+/).filter(Boolean).join(" ");
const RULE_PAGES = [["rules-safes", "A. Safes"], ["rules-members", "B. Safe members"], ["rules-platforms", "C. Platforms"],
  ["rules-accounts", "D. Accounts"], ["rules-dir", "E. Member names (optional)"], ["rules-json", "Advanced: settings file (JSON)"]];

// One settings page: its own cards and its own Save & apply, which saves only its keys.
async function rulesPage(page, intro, render) {
  const data = await api("/api/config");
  TABLES = {};
  const title = RULE_PAGES.find(p => p[0] === page)[1];
  const at = RULE_PAGES.findIndex(p => p[0] === page);
  const [nextPage, nextTitle] = at < RULE_PAGES.length - 2 ? [RULE_PAGES[at + 1][0], "Next: " + RULE_PAGES[at + 1][1]]
    : ["review-safes", "Next: 3. Review & change"];
  const json = page === "rules-json";
  const view = render(data);
  $("#main").innerHTML = `<h2>2. Mapping rules · ${esc(title)}</h2>
    <p class="lead">${intro}</p>
    <datalist id="dl-groups">${(data.hints.groups || []).map(g => `<option value="${esc(g.name)}">${g.accounts} accounts</option>`).join("")}</datalist>
    <datalist id="dl-folders">${(data.hints.folders || []).map(g => `<option value="${esc(g.name)}">${g.accounts} accounts</option>`).join("")}</datalist>
    <datalist id="dl-types">${(data.hints.types || []).map(g => `<option value="${esc(g.name)}">${g.accounts} accounts</option>`).join("")}</datalist>
    <datalist id="dl-platforms">${(data.hints.platforms || []).map(p => `<option value="${esc(p.id)}">${esc(p.note)}</option>`).join("")}</datalist>
    <datalist id="dl-columns">${(data.hints.columns || []).map(c => `<option value="${esc(c.name)}">${c.filled} of ${c.records} records have a value</option>`).join("")}</datalist>
    <div id="rules-body">${view.html}</div>
    ${view.preview ? previewDockHtml(view.preview) : ""}
    <div class="floatbar"><button class="btn primary" id="save" title="Saves this page only and re-runs the rules on everything loaded. Your own changes in step 3 always win.">Save &amp; apply this page</button>
      <button class="btn" id="rules-next">${esc(nextTitle)} ›</button><span id="rules-msg"></span>
      ${json ? "" : '<a href="#" class="adv" data-go="rules-json" title="Every setting as JSON, for the few the pages don\'t cover">Advanced: settings file (JSON)</a>'}</div>`;
  $("#rules-next").onclick = () => go(nextPage);
  wireAddButtons();
  if (view.after) view.after();
  if (view.preview) wirePreviewDock(view);
  applyTips(); syncSave();
  $("#save").onclick = async () => {
    let patch;
    try { patch = view.collect(); } catch (e) { return msg($("#rules-msg"), "err", e.message); }
    try {
      const r = await api("/api/config", patch.__full ? { config: patch.__full } : { patch });
      saved("main");
      await refresh();
      $("#rules-msg").innerHTML = `<span class="msg ${r.cleaned ? "warn" : "ok"}">Saved${r.mapped ? ` and applied: ${STATE.to_upload} accounts will be uploaded, ${(STATE.status_counts || {}).ERROR || 0} errors` : ""}.${r.cleaned ? " " + esc(CLEANED) : ""}</span>`;
      if (view.refresh) view.refresh();   // the page's preview shows the saved result
    } catch (e) { msg($("#rules-msg"), "err", e.message); }
  };
}
PAGES.rules = async () => go("rules-safes");

/* The floating preview on every Mapping rules page: it stays at the bottom of the window above
   Save & apply, scrolls inside, and shows what the settings on the page give as you change
   them, before anything is saved. Source columns are on the left, the upload CSV columns they
   become on the right; cells your unsaved changes affect are highlighted. */
const CHG_TIP = "Different from what is saved and applied now";
// A cell's class and tip: highlighted when the field is in the row's changed list.
const chg = (x, key, cls = "") => {
  const on = (x.changed || []).includes(key);
  return ` class="${cls}${on ? " chg" : ""}"${on ? ` title="${CHG_TIP}"` : ""}`;
};
const SRC_HEAD = (n, label = "From the source") => `<th colspan="${n}" class="grp src">${label}</th>`;
const CSV_HEAD = (n, file) => `<th colspan="${n}" class="grp csv" title="Columns of ${file} in the upload files">→ ${file}</th>`;
// A line down the table where the upload CSV columns start (after the "From the source" group).
function markCsvColumn(table) {
  const grp = table && table.querySelector("thead tr:first-child");
  if (!grp || !grp.querySelector("th.csv")) return;
  let idx = 0;
  for (const th of grp.children) { if (th.classList.contains("csv")) break; idx += th.colSpan || 1; }
  table.querySelectorAll("thead tr:not(:first-child), tbody tr").forEach(tr => { const c = tr.children[idx]; if (c) c.classList.add("csv-first"); });
}
function previewDockHtml(pv) {
  let folded = false; try { folded = localStorage.getItem("imw-pv-folded") === "1"; } catch (e) { /* no storage */ }
  return `<section class="pv-dock${folded ? " folded" : ""}" id="pv-dock" aria-label="Preview">
    <div class="pv-head">
      <button class="linkbtn pv-toggle" id="pv-toggle" aria-expanded="${folded ? "false" : "true"}" title="Fold or unfold the preview"><span class="pv-arrow">▾</span> <b>Preview</b></button>
      <span class="muted small pv-what">${esc(pv.title)}</span>
      <input type="search" id="pv-filter" placeholder="Show rows containing…" size="22" title="Shows only the rows containing this text. Only filters the preview; not a setting.">
      <label class="inline small" title="Shows only the rows that your unsaved changes on this page affect"><input type="checkbox" id="pv-changed"> only rows my changes affect</label>
      <span class="muted small" id="pv-state"></span></div>
    <div class="pv-body" id="pv-out"><p class="muted">${STATE.has_db ? "Loading…" : "Load some exports to see a preview."}</p></div></section>`;
}
function wirePreviewDock(view) {
  const pv = view.preview, body = $("#rules-body"), dock = $("#pv-dock");
  let rows = [], meta = null, seq = 0, timer = null;
  const draw = () => {
    if (!meta) return;
    const q = $("#pv-filter").value.trim().toLowerCase(), onlyChg = $("#pv-changed").checked;
    const shown = rows.filter(x => (!onlyChg || (x.changed || []).length) &&
      (!q || JSON.stringify(x).toLowerCase().includes(q)));
    const changed = rows.filter(x => (x.changed || []).length).length;
    $("#pv-state").textContent = pv.summary(meta) + (changed ? ` · your changes affect ${changed} of ${rows.length} rows` : " · no unsaved changes") +
      (meta.total_rows > rows.length ? ` · first ${rows.length} of ${meta.total_rows} rows` : "");
    $("#pv-out").innerHTML = shown.length ? `<table class="small pv-table"><thead>${pv.head}</thead><tbody>${shown.map(pv.row).join("")}</tbody></table>`
      : `<p class="muted">${rows.length ? "No rows match." : "Nothing to show yet: load some exports first."}</p>`;
    markCsvColumn($("#pv-out table"));
  };
  const run = async () => {
    if (!document.body.contains(dock)) return;            // the page was left
    const mine = ++seq;
    let patch; try { patch = view.collect(); } catch (e) { $("#pv-state").textContent = ""; return msg($("#pv-out"), "err", e.message); }
    $("#pv-state").textContent = "Updating…";
    let r;
    try { r = await pv.load(patch); }
    catch (e) { if (mine === seq && document.body.contains(dock)) { $("#pv-state").textContent = ""; msg($("#pv-out"), "err", e.message); } return; }
    if (mine !== seq || !document.body.contains(dock)) return;   // a newer one is on its way, or the page was left
    if (view.previewed) view.previewed(r);
    rows = pv.rows ? pv.rows(r) : r.rows; meta = r;
    draw();
  };
  const schedule = () => { if (!STATE.has_db) return; clearTimeout(timer); timer = setTimeout(() => run().catch(() => {}), 450); };
  // Any change in the settings updates it: typing, picking, ticking, adding or removing rows.
  // The listeners sit on this page's own body, so they go when you leave the page.
  ["input", "change"].forEach(ev => body.addEventListener(ev, schedule));
  body.addEventListener("click", (e) => { if (e.target.closest("button")) schedule(); });
  $("#pv-filter").addEventListener("input", draw);
  $("#pv-changed").addEventListener("change", draw);
  $("#pv-toggle").onclick = () => {
    const folded = dock.classList.toggle("folded");
    $("#pv-toggle").setAttribute("aria-expanded", String(!folded));
    try { localStorage.setItem("imw-pv-folded", folded ? "1" : "0"); } catch (e) { /* no storage */ }
    queueFloat();
  };
  view.refresh = () => run().catch(() => {});
  if (STATE.has_db) run().catch(() => {});
}
const previewApi = (kind) => (patch) => api("/api/rules/preview", patch.__full ? { kind, config: patch.__full } : { kind, patch });
const countsSummary = (m) => `${m.accounts} accounts in ${m.safes} Safes`;

/* A. Directory sources */
PAGES["rules-dir"] = () => rulesPage("rules-dir",
  "How the users, groups and roles that have access in your source export become Safe members in Privilege Cloud. Each source is a rule: which members it takes, and how their names are converted to match Privilege Cloud.",
  ({ config: cfg }) => {
    const COLS = [{ key: "name", label: "Source name", ph: "Corporate AD", tip: DIR_TIP.name },
      { key: "match", label: "Matches members from", ph: "CORP, corp.example.com, * or re:^APP-", tip: DIR_TIP.match },
      { key: "search_in", label: "searchIn (optional)", ph: "empty = all directories", tip: DIR_TIP.search_in },
      { key: "strip_domain", label: "Drop CORP\\ / @domain", options: [["yes", "yes"], ["no", "no"]], tip: DIR_TIP.strip_domain },
      { key: "find", label: "Find", ph: "^GRP-", phText: "GRP-", match: true, tip: DIR_TIP.find }, { key: "replace", label: "Replace with", ph: "PAM-", tip: DIR_TIP.replace },
      { key: "add_prefix", label: "Add before", ph: "PAM-", tip: DIR_TIP.add_prefix }, { key: "add_suffix", label: "Add after", ph: "@corp.example.com", tip: DIR_TIP.add_suffix },
      { key: "case", label: "Case", options: [["keep", "keep"], ["lower", "lower"], ["upper", "UPPER"]], tip: DIR_TIP.case }];
    let sources = cfg.directory_sources || [];
    if (!sources.length) {
      const entries = Object.entries(cfg.directory_map || {}).sort((a, b) => (a[0] === "*") - (b[0] === "*"));
      sources = entries.filter(([d]) => d !== "*").map(([domain, dir]) => ({ name: domain, members: "both", match: domain, search_in: dir,
        strip_domain: cfg.strip_domain_prefix, case: "keep" }));
    }
    const rowsFor = (kind) => sources.filter(s => (s.members || "both") === "both" || s.members === kind)
      .map(s => ({ ...s, strip_domain: s.strip_domain === false || s.strip_domain === "no" ? "no" : "yes" }));
    const fallbackDir = (cfg.directory_map || {})["*"] || "";
    return {
      html: `${explain(`<p><b>How it works.</b> For each member in the export (for example <code>CORP\\DBA-Team</code>), the Workbench goes down the list of sources
          for that member's type and uses the <b>first</b> one whose "Matches members from" fits. That source decides the member's name in SafeMembers.csv (memberName) and, if you fill it in, the directory to look in (searchIn).
          A member no source matches uses the default at the top.</p>
          <p><b>Do I need any?</b> Often not: with no sources, CORP\\ is dropped from every name and Privilege Cloud searches all its directories. Add a source when names in Privilege Cloud differ from the export
          (for example groups renamed from <code>GRP-</code> to <code>PAM-</code>, or users that need <code>@corp.example.com</code>). Hover any column heading for what it does and an example.</p>
          <p><b>searchIn</b> can stay empty: Privilege Cloud then searches every directory it knows. Fill it only when the same name exists in more than one directory; it then needs that directory's ID from Identity.</p>`, "How it works")}
        <div class="card"><h3>Every member (the default)</h3><div class="row">
          <label class="inline">searchIn <input type="text" id="dir-fallback" value="${esc(fallbackDir)}" size="20" placeholder="empty = all directories"></label>
          <label class="inline"><input type="checkbox" id="dir-strip" ${cfg.strip_domain_prefix ? "checked" : ""}> Drop the CORP\\ prefix from names</label>
          <label class="inline">A member the export doesn't give a type is a <select id="dir-type">${MEMBER_TYPES.map(t => `<option ${cfg.default_member_type === t ? "selected" : ""}>${t}</option>`).join("")}</select></label></div></div>
        <div class="card"><h3>Exceptions: sources for some members <span class="muted small">(checked before the default above, top to bottom; the first match wins)</span></h3>
          <h4 style="margin:6px 0">Groups and roles</h4>${editorTable("t-dg", COLS, rowsFor("groups"), "+ Add group source")}
          <h4 style="margin:12px 0 6px">Users</h4>${editorTable("t-du", COLS, rowsFor("users"), "+ Add user source")}</div>`,
      collect() {
        const fix = (r, members) => ({ ...r, members, strip_domain: r.strip_domain !== "no", name: r.name || r.match || "" });
        const list = readTable("t-dg").map(r => fix(r, "groups")).concat(readTable("t-du").map(r => fix(r, "users")));
        return { directory_sources: list, directory_map: { "*": $("#dir-fallback").value.trim() },
                 strip_domain_prefix: $("#dir-strip").checked, default_member_type: $("#dir-type").value };
      },
      preview: {
        title: "each member in the export → its name in Privilege Cloud",
        load: (patch) => api("/api/members/preview", { patch }),
        rows: (r) => r.members, summary: (r) => `${r.members.length} members`,
        head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(3, "SafeMembers.csv")}<th class="grp"></th></tr>
          <tr><th>Member in the export</th><th>Accounts</th><th>memberName</th><th>memberType</th><th>searchIn</th><th>Source used</th></tr>`,
        row: (m) => `<tr><td>${esc(m.source)}</td><td>${m.accounts}</td><td${chg(m, "member_name")}><b>${esc(m.member_name)}</b></td>
          <td${chg(m, "type")}>${esc(m.type)}</td><td${chg(m, "search_in")}>${m.search_in ? esc(m.search_in) : '<span class="muted">(all directories)</span>'}</td>
          <td class="muted">${esc(/not matched/.test(m.directory_source || "") ? "the default" : m.directory_source)}</td></tr>`,
      },
    };
  });

/* B. Permissions: Safes */
PAGES["rules-safes"] = () => rulesPage("rules-safes",
  "Which Safe each account goes to, how Safes are named, and the settings each Safe is created with.",
  ({ config: cfg, hints, presets }) => {
    ROLE_NAMES = () => Object.keys(presets).concat(Object.keys(cfg.custom_roles || {}));
    const GR = [{ key: "group", label: "Group (exact name)", ph: "CORP\\Unix-Admins", list: "dl-groups" },
                { key: "group_pattern", label: "…or group names that match", ph: "^CORP\\\\APP-(.+)-Owners$", phText: "APP-", match: true },
                { key: "safe", label: "Target Safe", ph: "UNIX-Admins or APP-{1}" },
                { key: "min_role", label: "Only if role at least", roles: true, blank: true }];
    const FR = [{ key: "folder_prefix", label: "Folder (and everything under it)", ph: "\\IT\\Network", list: "dl-folders" },
                { key: "safe", label: "Target Safe", ph: "NET-Devices or {convention}" }];
    const AB = [{ key: "word", label: "Word or phrase" }, { key: "code", label: "Code (1-4 letters)", ph: "e.g. BOS" }];
    const SR = [{ key: "safe_pattern", label: "Safes whose name", ph: "^P-|^DB-", phText: "DB-", match: true }, { key: "managingCPM", label: "CPM", ph: "PasswordManager_DB" },
                { key: "description", label: "Description", ph: "{folder}" }, { key: "numberOfVersionsRetention", label: "Keep versions", size: 4 },
                { key: "numberOfDaysRetention", label: "or keep days", size: 4 }];
    const RULE = [{ key: "field", label: "Look at", list: "dl-fields", ph: "folder_word" }, { key: "pattern", label: "Matches", ph: "^prod$|^live$", phText: "prod", match: true },
                  { key: "field2", label: "and look at", list: "dl-fields" }, { key: "pattern2", label: "matches", ph: "^svc", phText: "svc_", match: true },
                  { key: "code", label: "Code", ph: "P", size: 6 }];
    const LEGACY = { owner: "Full", editor: "Accounts manager", user: "Read only", viewer: "List only" };
    const fixRole = (r) => r ? (LEGACY[String(r).toLowerCase()] && !(cfg.custom_roles || {})[r] ? LEGACY[String(r).toLowerCase()] : r) : "";
    const conv = cfg.safe_convention;
    const folderNames = new Set((hints.folders || []).flatMap(f => f.name.split("\\").filter(Boolean)).map(normName));
    const folderAbbr = Object.fromEntries(Object.entries(conv.abbreviations || {}).filter(([w]) => folderNames.has(normName(w))));
    const otherAbbr = Object.entries(conv.abbreviations || {}).filter(([w]) => !folderNames.has(normName(w))).map(([word, code]) => ({ word, code }));
    let layers = JSON.parse(JSON.stringify(conv.layers || {}));
    const BUILTIN = { env: "Environment", tech: "Technology", flavor: "Flavor", acct: "Account type" };
    const sd = cfg.safe_defaults, ad = cfg.account_defaults;
    const keepVersions = String(sd.numberOfVersionsRetention ?? "").trim() !== "";
    const fb = [["convention", "the folder structure, abbreviated (\\Applications\\Storefront\\Prod → APP-SF-P)"],
                ["folder_leaf", "the last folder only (Prod)"], ["folder_path", "the whole folder path (Applications-Storefront-Prod)"],
                ["unmapped", "nothing: use UNMAPPED so I decide"]];
    const layerSum = (name, label, n, def) => `<b><code>{${esc(name)}}</code></b> ${esc(label)}
      <span class="muted small">· ${n ? `${n} ${n === 1 ? "value" : "values"}` : "no values"} · if none match: ${def ? `<code>${esc(def)}</code>` : "left out"}${BUILTIN[name] ? " · built-in" : ""}</span>`;
    const layerBlock = (name, layer) => editBlock(layerSum(name, layer.label || BUILTIN[name] || name, (layer.rules || []).length, layer.default),
      `<div class="layer-body"><div class="row">
        <label class="inline">Label <input type="text" class="l-label" value="${esc(layer.label || BUILTIN[name] || name)}" size="16"></label>
        <label class="inline">If no value matches use <input type="text" class="l-default" value="${esc(layer.default || "")}" size="6" placeholder="nothing"></label>
        ${BUILTIN[name] ? "" : `<button class="btn small danger l-del">Remove {${esc(name)}}</button>`}</div>
      ${editorTable("t-layer-" + name, RULE, layer.rules || [], "+ Add value", true)}</div>`, "layer-" + name, false, "layer").replace("<details ", `<details data-layer="${esc(name)}" `);
    const layersTotal = () => { const names = Object.keys(layers); const vals = names.reduce((n, k) => n + ((layers[k].rules || []).length), 0);
      return `${names.length} placeholders, ${vals} values`; };
    const html = `
      <datalist id="dl-fields">${LAYER_FIELDS.filter(f => f !== "column:").map(f => `<option value="${f}">`).join("")}${(hints.columns || []).map(c => `<option value="column:${esc(c.name)}">source column, ${c.filled} records have a value</option>`).join("")}<option value="column:">column:&lt;any source column&gt;</option></datalist>
      <div class="card"><h3>Safe name <span class="muted small">(the default: object-oriented Safes that follow your existing folders)</span></h3>
        <div class="row"><label class="inline">Name each Safe after
          <select id="fallback">${fb.map(([v, l]) => `<option value="${v}" ${cfg.fallback_strategy === v ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>
          <label class="inline">Prefix every Safe with <input type="text" id="prefix" value="${esc(cfg.safe_name.prefix || "")}" size="8" placeholder="MIG-" data-check="safe"></label></div>
        <div id="conv-fields">
        <div class="row"><label class="inline">Pattern for accounts with folders <input type="text" id="conv-template" size="30" value="${esc(conv.template)}"></label>
          <label class="inline">with no folders <input type="text" id="conv-flat" size="30" value="${esc(conv.template_no_folders || "")}"></label></div>
        <div class="row"><label class="inline">Leave out folder levels <input type="text" id="conv-skip" size="24" value="${esc((conv.skip_folder_levels || []).join(", "))}" placeholder="e.g. Root"></label>
          <label class="inline">Flag Safes with more than <input type="text" id="max-acc" size="6" value="${esc(cfg.safe_max_accounts)}"> accounts</label></div></div>
        <p class="muted small">⚠ Safe names are always cut to ${cfg.safe_name.max_length} characters, and the characters <code>${esc(cfg.safe_name.invalid_chars)}</code> become "${esc(cfg.safe_name.replacement)}". The preview at the bottom of the window shows the result as you type.</p></div>
      <details class="card fold" data-block="codes"><summary>Codes used in names <span class="muted small" style="font-weight:400">· folder abbreviations, other words and placeholders such as {env}: most migrations leave these as they are</span></summary>
        <h4 style="margin:4px 0 6px">Folder abbreviations <span class="muted small">(taken from the folders you loaded; type a code to change one)</span></h4>
        <div id="conv-folders"><p class="muted small">${STATE.has_db ? "Loading…" : "Load some exports to see your folder names here."}</p></div>
        <h4 style="margin:12px 0 6px">Other words and phrases</h4>
        ${editorTable("t-ab", AB, otherAbbr)}
        <h4 style="margin:16px 0 6px">Placeholders and their values</h4>
        ${editBlock(`<span id="layers-sum"></span>`, `
        <p class="muted small">Each placeholder's code comes from the first of its rows that matches. Open a placeholder to see or change its values; hover "Look at" for what it can check.</p>
        <div id="layers"></div>
        <div class="row"><label class="inline">New placeholder <input type="text" id="new-layer" size="14" placeholder="region"></label>
          <button class="btn small" id="add-layer">+ Add placeholder</button>
          <button class="btn small" id="reset-layers">Restore the built-in values</button></div>`, "layers-all")}</details>
      <div class="card"><h3>Safe settings <span class="muted small">(every Safe, unless an exception below says otherwise)</span></h3>
        <div class="row"><label class="inline">Managing CPM <input type="text" id="s-cpm" value="${esc(sd.managingCPM || "")}" placeholder="PasswordManager" size="20"></label>
          <label class="inline">Description <input type="text" id="s-desc" value="${esc(sd.description || "")}" placeholder="Migrated from {folder}" size="34"></label></div>
        <div class="row"><span>Keep old passwords for</span>
          <label class="inline"><input type="radio" name="ret" value="versions" ${keepVersions ? "checked" : ""}> <input type="text" id="s-ver" size="4" value="${esc(keepVersions ? sd.numberOfVersionsRetention : 5)}"> versions</label>
          <label class="inline"><input type="radio" name="ret" value="days" ${keepVersions ? "" : "checked"}> <input type="text" id="s-days" size="4" value="${esc(sd.numberOfDaysRetention || 7)}"> days</label></div>
        <div class="row"><label class="inline"><input type="checkbox" id="a-auto" ${ad.automaticManagementEnabled ? "checked" : ""}> Let the CPM manage migrated accounts automatically</label>
          <label class="inline">otherwise the reason is <input type="text" id="a-reason" value="${esc(ad.manualManagementReason || "")}" size="40"></label></div></div>
      <div class="card"><h3>Exceptions <span class="muted small">(only for the Safes, folders or groups you list; empty unless you add rows)</span></h3>
        <h4 style="margin:6px 0">Send a folder to another Safe <span class="muted small">(the most specific folder wins)</span></h4>
        ${editorTable("t-fr", FR, cfg.folder_rules)}
        <h4 style="margin:14px 0 6px">Safe from access groups <span class="muted small">(role-oriented Safes: they scale worse than folder Safes; first match wins)</span></h4>
        ${editorTable("t-gr", GR, (cfg.group_rules || []).map(r => ({ ...r, min_role: fixRole(r.min_role) })))}
        <ul class="capture-pv muted" id="gr-capture" title="What each access-group row matches in your loaded data, and the Safe name it gives"></ul>
        <p><label class="inline"><input type="checkbox" id="gr-first" ${cfg.group_rules_first ? "checked" : ""}> Check access groups before the folder exceptions</label></p>
        <h4 style="margin:14px 0 6px">Different settings for some Safes <span class="muted small">(first match wins; empty cells keep the Safe settings above)</span></h4>
        ${editorTable("t-sr", SR, cfg.safe_rules || [])}</div>`;

    const renderLayers = () => {
      const order = ["env", "tech", "flavor", "acct"].concat(Object.keys(layers).filter(n => !BUILTIN[n]));
      $("#layers").innerHTML = order.filter(n => layers[n]).map(n => layerBlock(n, layers[n])).join("");
      $("#layers-sum").textContent = layersTotal();
      wireAddButtons($("#layers"));
      document.querySelectorAll(".l-del").forEach(b => b.onclick = () => {
        readLayers(); delete layers[b.closest(".layer").dataset.layer]; renderLayers(); DIRTY.main = true; syncSave(); });
    };
    const readLayers = () => {
      document.querySelectorAll("#layers details.layer").forEach(div => {
        const name = div.dataset.layer;
        layers[name] = { label: $(".l-label", div).value.trim(), default: $(".l-default", div).value.trim(),
          rules: readTable("t-layer-" + name).filter(r => r.field && r.pattern !== undefined || r.field).map(r => {
            const o = { field: r.field, pattern: r.pattern || "", code: r.code || "" };
            if (r.field2) { o.field2 = r.field2; o.pattern2 = r.pattern2 || ""; }
            return o; }) };
      });
      return layers;
    };
    const readFolderCodes = () => {
      document.querySelectorAll("#conv-folders input[data-folder]").forEach(i => {
        const code = i.value.trim(); if (code) folderAbbr[i.dataset.folder] = code; else delete folderAbbr[i.dataset.folder]; });
      return folderAbbr;
    };
    const renderFolderCodes = (rows) => {
      if (!rows.length) return;
      const yours = {}; Object.entries(folderAbbr).forEach(([w, c]) => yours[normName(w)] = [w, c]);
      const open = $("#conv-folders details") ? $("#conv-folders details").open : false;
      $("#conv-folders").innerHTML = editBlock(`${rows.length} folder names, ${Object.keys(yours).length} with your own code`, `<div class="tablewrap" style="max-height:40vh"><table class="small editor"><tr><th>Folder name</th><th>Accounts</th><th>Code</th><th></th></tr>
        ${rows.map(r => { const mine = yours[normName(r.folder)];
          return `<tr><td>${esc(r.folder)}</td><td>${r.accounts}</td>
          <td><input type="text" data-folder="${esc(mine ? mine[0] : r.folder)}" value="${esc(mine ? mine[1] : "")}" placeholder="${esc(mine ? "" : r.code)}"></td>
          <td class="small">${r.clash ? `<span class="pill ERROR">same code as ${esc(r.clash)}</span>` : r.automatic && !mine ? '<span class="muted">automatic</span>' : ""}</td></tr>`; }).join("")}</table></div>
        <div class="row" style="margin-top:6px"><button class="btn small" id="conv-keep">Keep all the suggested codes</button>
          <span class="muted small">writes them into your settings so they stay the same later</span></div>`);
      $("#conv-folders details").open = open;
      $("#conv-keep").onclick = () => document.querySelectorAll("#conv-folders input[data-folder]").forEach(i => { if (!i.value) i.value = i.placeholder; });
    };
    const collect = () => {
      const abbr = { ...readFolderCodes() };
      readTable("t-ab").filter(r => r.word && r.code).forEach(r => abbr[r.word] = r.code);
      const ret = document.querySelector("input[name=ret]:checked").value;
      const num = (v, what) => { if (!/^\d+$/.test(v)) throw new Error(`${what} must be a whole number.`); return Number(v); };
      const rules = readTable("t-sr").map(r => { if (!r.safe_pattern) throw new Error("Every 'Different settings' row needs a Safe pattern."); return r; });
      return {
        fallback_strategy: $("#fallback").value,
        safe_name: { ...cfg.safe_name, prefix: $("#prefix").value.trim() },
        folder_rules: readTable("t-fr"),
        group_rules: readTable("t-gr").map(r => { const o = { safe: r.safe }; if (r.group) o.group = r.group; else if (r.group_pattern) o.group_pattern = r.group_pattern; if (r.min_role) o.min_role = r.min_role; return o; }),
        group_rules_first: $("#gr-first").checked,
        safe_max_accounts: num($("#max-acc").value.trim(), "The account limit"),
        safe_convention: { ...conv, template: $("#conv-template").value.trim(), template_no_folders: $("#conv-flat").value.trim(),
          skip_folder_levels: $("#conv-skip").value.split(",").map(x => x.trim()).filter(Boolean), abbreviations: abbr,
          layers: readLayers(), default_environment: "" },
        safe_defaults: { ...sd, managingCPM: $("#s-cpm").value.trim(), description: $("#s-desc").value.trim(),
          numberOfVersionsRetention: ret === "versions" ? num($("#s-ver").value.trim(), "Versions") : "",
          numberOfDaysRetention: ret === "days" ? num($("#s-days").value.trim(), "Days") : "" },
        safe_rules: rules,
        account_defaults: { ...ad, automaticManagementEnabled: $("#a-auto").checked, manualManagementReason: $("#a-reason").value.trim() },
      };
    };
    return {
      html, collect,
      preview: {
        title: "each source folder → its Safe and that Safe's settings",
        load: previewApi("safes"), summary: countsSummary,
        head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(5, "Safes.csv")}<th class="grp"></th></tr>
          <tr><th title="The folder the accounts are in, in the source export">Folder</th><th title="Accounts from this folder that go to this Safe">Accounts</th>
          <th title="The Safe the accounts go to, with every rule, exception and your own changes applied">safeName</th>
          <th title="Characters in the Safe name (at most ${cfg.safe_name.max_length})">Length</th>
          <th title="The CPM that manages this Safe's accounts: the Safe settings, then the 'Different settings' exceptions, then your own Safe changes. Empty = no CPM">managingCPM</th>
          <th title="numberOfVersionsRetention or numberOfDaysRetention">Keeps</th><th>description</th>
          <th title="Things to check about this Safe">Notes</th></tr>`,
        row: (x) => `<tr><td>${esc(x.folder || "(no folder)")}</td><td>${x.accounts}</td>
          <td${chg(x, "safe", "nowrap")}><b>${esc(x.safe)}</b>${x.valid ? "" : ' <span class="pill REVIEW" title="Forbidden characters replaced or the name shortened">name changed</span>'}</td>
          <td>${x.length}</td><td${chg(x, "cpm", "nowrap")}>${x.cpm ? esc(x.cpm) : '<span class="muted">(no CPM)</span>'}</td>
          <td${chg(x, "keeps", "nowrap")}>${esc(x.keeps)}</td><td${chg(x, "description")}>${esc(x.description)}</td><td class="notes">${esc(x.issues)}</td></tr>`,
      },
      after() {
        // An older default environment becomes the {env} default so it shows here.
        if (conv.default_environment && layers.env && !layers.env.default) layers.env.default = conv.default_environment;
        renderLayers();
        const resum = () => {
          readLayers();
          document.querySelectorAll("#layers details.layer").forEach(dt => { const n = dt.dataset.layer, l = layers[n];
            $(":scope > summary .edit-sum", dt).innerHTML = layerSum(n, l.label || BUILTIN[n] || n,
              document.querySelectorAll(`#t-layer-${n} tr`).length - 1, l.default); });
          $("#layers-sum").textContent = layersTotal();
        };
        onTableCount = (id) => { if (id.startsWith("t-layer-")) resum(); };
        $("#layers").addEventListener("change", (e) => { if (e.target.matches(".l-label, .l-default")) resum(); });
        $("#add-layer").onclick = () => {
          const name = $("#new-layer").value.trim().replace(/^\{|\}$/g, "");
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return alert("Use letters, digits and _ only, for example region.");
          if (layers[name] || ["folder", "folder_leaf", "type", "convention"].includes(name)) return alert(`{${name}} already exists.`);
          readLayers(); layers[name] = { label: name, default: "", rules: [{ field: "address", pattern: "", code: "" }] };
          renderLayers(); $("#new-layer").value = "";
          const blk = $(`[data-block="layer-${name}"]`); if (blk) blk.open = true;
        };
        $("#reset-layers").onclick = async () => {
          if (!confirm("Put the built-in values back for {env}, {tech}, {flavor} and {acct}? Your own placeholders stay.")) return;
          readLayers(); const d = await api("/api/config"); Object.assign(layers, d.defaults.safe_convention.layers); renderLayers();
        };
        // Each access-group row: which group in the loaded data it matches first and the Safe that gives,
        // so {1}, {2} in "Target Safe" can be checked without guessing.
        const groups = hints.groups || [];
        const capture = () => {
          const out = [...document.querySelectorAll("#t-gr tr")].slice(1).map((tr, i) => {
            const v = (k) => { const el = tr.querySelector(`[data-k="${k}"]`); return el ? el.value.trim() : ""; };
            const op = tr.querySelector("select.m-op"), safe = v("safe") || "(no Target Safe yet)", row = `Row ${i + 1}: `;
            if (v("group")) {
              const g = groups.find(x => x.name.toLowerCase() === v("group").toLowerCase());
              return row + (g ? `<b>${esc(g.name)}</b> (${g.accounts} accounts) → <b>${esc(safe)}</b>` : `${esc(v("group"))} is not in your loaded data`);
            }
            if (!v("group_pattern")) return "";
            const re = jsRegex(toPattern(op ? op.value : "regex", v("group_pattern")));
            if (!re) return row + "this pattern can't be previewed here; the Safes preview below shows what it does";
            const hits = groups.filter(x => re.test(x.name));
            if (!hits.length) return row + "matches none of the access groups in your loaded data";
            const m = hits[0].name.match(re);
            let name = safe; m.slice(1).forEach((val, k) => { name = name.split(`{${k + 1}}`).join(val || ""); });
            const parts = m.length > 1 ? " · " + m.slice(1).map((val, k) => `{${k + 1}} = <code>${esc(val || "")}</code>`).join(", ") : (/\{\d\}/.test(safe) ? " · the pattern has no ( ) part, so {1} is empty" : "");
            return row + `${hits.length} ${hits.length === 1 ? "group matches" : "groups match"}, e.g. <b>${esc(hits[0].name)}</b>${parts} → <b>${esc(name)}</b>`;
          }).filter(Boolean);
          $("#gr-capture").innerHTML = out.map(x => `<li>${x}</li>`).join("");
        };
        ["input", "change"].forEach(ev => $("#t-gr").addEventListener(ev, capture));
        $("#t-gr").closest("details").addEventListener("click", () => setTimeout(capture, 0));
        capture();
        // Don't redraw the folder codes while you type in one of them.
        this.previewed = (r) => { if (!$("#conv-folders").contains(document.activeElement)) renderFolderCodes(r.folder_codes || []); };
        // The pattern fields matter only when Safes are named by the convention.
        const convOn = () => { const on = $("#fallback").value === "convention"; $("#conv-fields").style.opacity = on ? 1 : .5;
          $("#conv-fields").title = on ? "" : "Used only when Safes are named after the folder structure, abbreviated"; };
        $("#fallback").addEventListener("change", convOn); convOn();
      },
    };
  });

/* B. Permissions: Safe members */
PAGES["rules-members"] = () => rulesPage("rules-members",
  "How source permissions turn into Privilege Cloud permission presets or your own custom roles.",
  ({ config: cfg, presets }) => {
    const LEGACY = { owner: "Full", editor: "Accounts manager", user: "Read only", viewer: "List only" };
    let customRoles = Object.entries({ ...(cfg.role_permissions || {}), ...(cfg.custom_roles || {}) }).filter(([n]) => !presets[n])
      .map(([name, perms]) => ({ name, perms: new Set(perms) }));
    ROLE_NAMES = () => Object.keys(presets).concat(customRoles.map(r => r.name.trim()).filter(Boolean));
    const fixRole = (r) => r ? (LEGACY[String(r).toLowerCase()] && !customRoles.some(c => c.name === r) ? LEGACY[String(r).toLowerCase()] : r) : "";
    const PR = [{ key: "role", label: "Source permission word" }, { key: "to", label: "Privilege Cloud role", roles: true }];
    const html = `<div class="card"><h3>Source permission → role <span class="muted small">(a member with several permissions on one Safe gets the strongest role)</span></h3>
        ${editorTable("t-pr", PR, Object.entries(cfg.permission_map).map(([role, to]) => ({ role, to: fixRole(to) })), "+ Add row", true)}</div>
      <div class="card"><h3>Roles and their permissions <span class="muted small">(the five Privilege Cloud presets are fixed; add a custom role to choose every permission)</span></h3>
        ${editBlock(`5 presets, ${customRoles.length} custom ${customRoles.length === 1 ? "role" : "roles"}`, `<div class="tablewrap" style="margin-top:8px" id="roles"></div>
          <div class="row" style="margin-top:8px"><button class="btn small" id="role-add">+ New custom role</button>
            <label class="inline">starting from <select id="role-from">${["(nothing ticked)"].concat(Object.keys(presets)).map(n => `<option>${esc(n)}</option>`).join("")}</select></label></div>`, "roles", true)}</div>`;
    const refreshRoleSelects = () => document.querySelectorAll("select.role-select").forEach(sel => {
      const v = sel.value; sel.innerHTML = roleOptions(v, !!sel.dataset.blank); });
    const renderRoles = () => {
      const presetNames = Object.keys(presets);
      $("#roles").innerHTML = `<table class="small roles"><tr><th>Permission</th>
        ${presetNames.map(n => `<th title="Privilege Cloud preset">${esc(n)}</th>`).join("")}
        ${customRoles.map((r, i) => `<th><input type="text" class="role-name" data-i="${i}" value="${esc(r.name)}" placeholder="Role name" size="12">
          <button class="btn small" data-del="${i}" title="Delete this custom role">✕</button></th>`).join("")}</tr>
        ${PERM_GROUPS.map(([group, perms]) => `<tr><td colspan="${1 + presetNames.length + customRoles.length}" class="muted"><b>${esc(group)}</b></td></tr>` +
          perms.map(([key, label]) => `<tr><td>${esc(label)}</td>
            ${presetNames.map(n => `<td class="c">${presets[n].includes(key) ? '<span class="tick" title="Granted by this preset">✓</span>' : ""}</td>`).join("")}
            ${customRoles.map((r, i) => `<td class="c"><input type="checkbox" class="role-perm" data-i="${i}" data-p="${key}" ${r.perms.has(key) ? "checked" : ""}></td>`).join("")}</tr>`).join("")).join("")}
      </table>`;
      document.querySelectorAll(".role-name").forEach(inp => inp.oninput = () => { customRoles[+inp.dataset.i].name = inp.value; refreshRoleSelects(); });
      document.querySelectorAll(".role-perm").forEach(cb => cb.onchange = () => {
        const s = customRoles[+cb.dataset.i].perms; cb.checked ? s.add(cb.dataset.p) : s.delete(cb.dataset.p); });
      document.querySelectorAll("#roles [data-del]").forEach(b => b.onclick = () => {
        customRoles.splice(+b.dataset.del, 1); renderRoles(); refreshRoleSelects(); DIRTY.main = true; syncSave(); });
    };
    return {
      html,
      preview: {
        title: "each source member and permission → its Safe member and role",
        load: previewApi("members"), summary: (m) => `${m.total_rows} Safe members on ${m.safes} Safes`,
        head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(4, "SafeMembers.csv")}<th class="grp"></th></tr>
          <tr><th>Member in the export</th><th title="The permission the source gives (the strongest, when it has several)">Permission</th>
          <th>safeName</th><th>memberName</th><th>memberType</th><th title="The Privilege Cloud role: a preset or your custom role, from the table on this page">role</th><th>Notes</th></tr>`,
        row: (x) => `<tr${(x.changed || []).includes("new") ? ` class="chg-row" title="New compared with what is saved"` : ""}><td>${esc(x.source)}</td><td>${esc(x.permission)}</td>
          <td class="nowrap">${esc(x.safe)}</td><td${chg(x, "member_name")}>${esc(x.member_name)}</td><td${chg(x, "member_type")}>${esc(x.member_type)}</td>
          <td${chg(x, "role", "nowrap")}>${x.role === "UNMAPPED" ? '<span class="pill ERROR">no role</span>' : esc(x.role)}</td><td class="notes">${esc(x.notes)}</td></tr>`,
      },
      collect: () => ({
        permission_map: Object.fromEntries(readTable("t-pr").filter(r => r.role && r.to).map(r => [r.role, r.to])),
        custom_roles: Object.fromEntries(customRoles.map(r => [r.name.trim(), PERM_GROUPS.flatMap(g => g[1].map(p => p[0])).filter(p => r.perms.has(p))])),
        role_permissions: {},
      }),
      after() {
        renderRoles();
        $("#role-add").onclick = () => {
          const from = $("#role-from").value;
          let name = "Custom role", n = 1;
          while (ROLE_NAMES().includes(name)) name = `Custom role ${++n}`;
          customRoles.push({ name, perms: new Set(presets[from] || []) });
          renderRoles(); refreshRoleSelects();
          $('[data-block="roles"]').open = true;
          const inputs = document.querySelectorAll(".role-name"); inputs[inputs.length - 1].select();
        };
      },
    };
  });

/* C. Platforms */
PAGES["rules-platforms"] = () => rulesPage("rules-platforms",
  "Which Privilege Cloud platform each account uses. The platform decides how Privilege Cloud connects to the account and changes its password.",
  ({ config: cfg, hints }) => {
    const PM = [{ key: "type", label: "Record type / template", list: "dl-types", tip: "The record type exactly as in the export: a Delinea Secret Template (e.g. Windows Account), a KeePass or spreadsheet type column. Types found in your loaded data are suggested." },
                { key: "platform", label: "Platform ID", ph: "WinDomain", list: "dl-platforms", tip: "The platform ID exactly as in Privilege Cloud, as shown in Platform Management, e.g. WinDomain, WinServerLocal, UnixSSH, Oracle. Pick from the list (the usual Privilege Cloud IDs and the ones you already use) or type your own." }];
    const PRU = [{ key: "field", label: "Look at", options: [["type", "type"], ["folder", "folder"], ["name", "name"], ["address", "address"], ["username", "username"]]
                   .concat([...new Set((hints.columns || []).map(c => c.name).concat((cfg.platform_rules || []).map(r => r.field)
                     .filter(f => f && !["type", "folder", "name", "address", "username"].includes(f))))].map(c => [c, "column: " + c])),
                   tip: "Which part of the account is checked: its record type, folder path, name, address, username, or one of your export's other columns (listed as column: …)." },
                 { key: "pattern", label: "Matches", ph: "linux|unix", phText: "\\Unix\\", match: true, tip: "Pick how to compare, then type the text. Examples:\nContains \\Unix\\ (folder contains \\Unix\\)\nStarts with svc_ (username starts svc_)\nEnds with .db.corp.example.com (address)\nRegex linux|unix (either word)" },
                 { key: "platform", label: "Platform ID", ph: "UnixSSH", list: "dl-platforms", tip: "The platform ID exactly as in Privilege Cloud, e.g. UnixSSH. Pick from the list or type your own." }];
    const platRows = Object.entries(cfg.platform_map).map(([type, platform]) => ({ type, platform }));
    hints.types_without_platform.forEach(t => { if (t && !platRows.some(r => r.type.toLowerCase() === t.toLowerCase())) platRows.unshift({ type: t, platform: "" }); });
    return {
      html: `${hints.types_without_platform.length ? `<div class="msg warn">These record types have no platform yet, so their accounts can't be uploaded: ${hints.types_without_platform.map(esc).join(", ")}. Fill in the Platform ID below.</div>` : ""}
        ${explain(`<p><b>How a platform is chosen</b>, for each account, in this order:</p>
          <ol><li><b>Exceptions</b> (platform rules at the bottom), top to bottom. The first rule that matches decides.</li>
            <li>Otherwise the <b>record type</b> list: the account's type in the export (for example the Delinea template <i>Windows Account</i>) gives its platform.</li>
            <li>Otherwise the <b>default platform</b>. If that is empty, the account is flagged as an error and not uploaded.</li></ol>
          <p>For most exports the record type list is all you need. Add a rule only when accounts of one record type need different platforms, for example:</p>
          <ul><li>one <i>Windows Account</i> template holds both domain and local accounts: a rule on <b>address</b> or <b>folder</b> sends the domain ones to WinDomain;</li>
            <li>a KeePass file or spreadsheet has no useful type: rules on <b>folder</b> or <b>address</b> pick the platform;</li>
            <li>service accounts need their own platform: a rule on <b>username</b> such as <code>^svc_</code>.</li></ul>
          <p class="muted small">You can still change single accounts in step 3, and your changes there always win.</p>`, "How a platform is chosen")}
        <div class="card"><h3>Platform by record type <span class="muted small">(the default)</span></h3>${editorTable("t-pm", PM, platRows)}
        <p><label class="inline">Default platform for any other type <input type="text" id="defplat" list="dl-platforms" value="${esc(cfg.default_platform || "")}" placeholder="empty = flag as error" data-check="platform"></label></p></div>
        <div class="card"><h3>Exceptions: platform rules <span class="muted small">(checked before the record type list, top to bottom; the first match wins)</span></h3>${editorTable("t-pru", PRU, cfg.platform_rules || [])}</div>`,
      preview: {
        title: "each record type → the platform its accounts get",
        load: previewApi("platforms"), summary: countsSummary,
        head: `<tr>${SRC_HEAD(3)}${CSV_HEAD(1, "Accounts.csv")}<th class="grp" colspan="2"></th></tr>
          <tr><th>Record type</th><th>Folders</th><th>Accounts</th><th title="The platform ID the accounts get">platformId</th>
          <th title="Which setting chose the platform">Chosen by</th><th>Errors</th></tr>`,
        row: (x) => `<tr><td>${esc(x.type)}</td><td class="small">${esc(x.folders)}</td><td>${x.accounts}</td>
          <td${chg(x, "platform", "nowrap")}>${x.platform ? esc(x.platform) : '<span class="pill ERROR">no platform</span>'}${x.moved ? ` <span class="muted">(${x.moved} changed)</span>` : ""}</td>
          <td class="small">${esc(howChosen(x.how))}</td><td>${x.errors ? `<span class="pill ERROR">${x.errors}</span>` : ""}</td></tr>`,
      },
      after() {
        if (hints.types_without_platform.length) $('[data-block="t-pm"]').open = true;   // needs filling in
        // An empty platform is not an example value: mark it as needed.
        const need = (i) => { const empty = !i.value.trim(); i.classList.toggle("need", empty); i.placeholder = empty ? "needed: type the platform ID" : ""; };
        document.querySelectorAll('#t-pm [data-k="platform"]').forEach(i => { need(i); i.addEventListener("input", () => need(i)); });
      },
      collect: () => ({
        platform_rules: readTable("t-pru").filter(r => r.pattern && r.platform).map(r => ({ field: r.field || "type", pattern: r.pattern, platform: r.platform })),
        platform_map: Object.fromEntries(readTable("t-pm").filter(r => r.type && r.platform).map(r => [r.type, r.platform])),
        default_platform: $("#defplat").value.trim(),
      }),
    };
  });

/* D. Accounts */
PAGES["rules-accounts"] = () => rulesPage("rules-accounts",
  "How each account is named and which extra source columns become account properties.",
  ({ config: cfg }) => {
    const AP = [{ key: "column", label: "Source column", list: "dl-columns", ph: "Port", tip: "Column name exactly as in your export, e.g. Port or Notes. The columns found in your loaded exports are listed: click the box to pick one." },
                { key: "property", label: "Platform property", ph: "Port", tip: "Property name on the Privilege Cloud platform, e.g. Port. It must exist on the platform, or the upload rejects the account." }];
    const an = cfg.account_name || {};
    const none = String(an.mode || "").toLowerCase() === "none";
    return {
      html: `<div class="card"><h3>Account name</h3>
          <p class="muted small">Every account in a Safe has a name (the object name). It is optional on upload: with no name, Privilege Cloud makes one from the platform, address and username
            (for example <code>Operating System-WinDomain-srv01.corp.example.com-svc_backup</code>).</p>
          <label class="inline" style="display:block;margin:6px 0"><input type="radio" name="an-mode" value="pattern" ${none ? "" : "checked"}>
            <b>Build a name from a pattern</b> <span class="muted small">(recommended: a name you know lets you find the account, and refer to it later, for example for linked accounts)</span></label>
          <div class="row" id="an-pattern" style="margin-left:24px"><label class="inline">Name <input type="text" id="an-t" size="30" value="${esc(an.template || "{name}")}"></label>
            <label class="inline">if that comes out empty <input type="text" id="an-f" size="30" value="${esc(an.fallback || "{address}-{username}")}"></label></div>
          <p class="muted small" style="margin-left:24px">Placeholders: <code>{name}</code> (the name in the source, e.g. the Delinea Secret Name) <code>{address}</code> <code>{username}</code> <code>{platform}</code> <code>{safe}</code> <code>{folder_leaf}</code> <code>{type}</code> <code>{source_id}</code>.
            Invalid characters become _, and a name repeated in one Safe gets _2, _3.</p>
          <label class="inline" style="display:block;margin:6px 0"><input type="radio" name="an-mode" value="none" ${none ? "checked" : ""}>
            <b>Leave the name empty and let Privilege Cloud name each account</b></label>
          <p class="muted small" style="margin-left:24px">The <code>name</code> column in Accounts.csv stays empty. Two accounts with the same platform, address and username in one Safe would get the same generated name, so the second is rejected; those are flagged as possible duplicates.
            You can also leave single accounts unnamed in step 3 (<b>Let Privilege Cloud name them</b>).</p>
          <p><label class="inline"><input type="checkbox" id="url-host" ${cfg.url_address_to_host ? "checked" : ""}> Turn URL addresses into host names (https://fw01.example.com/login → fw01.example.com)</label></p></div>
        <div class="card"><h3>Extra account properties</h3>
          <p class="muted small">Source columns copied into platformAccountProperties. The property must exist on the target platform, or Privilege Cloud rejects the account.</p>
          ${editorTable("t-ap", AP, Object.entries(cfg.account_property_map || {}).map(([column, property]) => ({ column, property })))}</div>
        <p class="muted small">CPM management and Safe settings are on <a href="#" data-go="rules-safes">B. Permissions: Safes</a>.</p>`,
      preview: {
        title: "each source record → its account name, address and properties",
        load: previewApi("accounts"), summary: countsSummary,
        head: `<tr>${SRC_HEAD(3)}${CSV_HEAD(5, "Accounts.csv")}<th class="grp"></th></tr>
          <tr><th>Name</th><th>Address</th><th>Username</th><th>safeName</th><th>platformId</th>
          <th title="The account's name in its Safe; empty = Privilege Cloud names it">name</th><th>address</th>
          <th title="platformAccountProperties from the extra properties table">properties</th><th>Notes</th></tr>`,
        row: (x) => `<tr><td>${esc(x.source_name)}</td><td>${esc(x.source_address)}</td><td>${esc(x.username)}</td>
          <td class="nowrap">${esc(x.safe)}</td><td class="nowrap">${esc(x.platform)}</td>
          <td${chg(x, "account_name")}>${x.account_name ? esc(x.account_name) : PC_NAMES}</td><td${chg(x, "address")}>${esc(x.address)}</td>
          <td class="small">${esc(x.properties)}</td><td class="notes">${esc(x.notes)}</td></tr>`,
      },
      after() {
        const sync = () => { const off = document.querySelector('input[name="an-mode"]:checked').value === "none";
          ["#an-t", "#an-f"].forEach(k => { $(k).disabled = off; }); $("#an-pattern").style.opacity = off ? .5 : 1; };
        document.querySelectorAll('input[name="an-mode"]').forEach(r => r.onchange = sync); sync();
      },
      collect: () => ({
        account_name: { mode: document.querySelector('input[name="an-mode"]:checked').value,
                        template: $("#an-t").value.trim() || "{name}", fallback: $("#an-f").value.trim() || "{address}-{username}" },
        url_address_to_host: $("#url-host").checked,
        account_property_map: Object.fromEntries(readTable("t-ap").filter(r => r.column && r.property).map(r => [r.column, r.property])),
      }),
    };
  });

/* Settings file */
PAGES["rules-json"] = () => rulesPage("rules-json",
  "Every setting as JSON, for anything the other pages don't cover. Only change these if you know what you need.",
  ({ config: cfg }) => ({
    html: `<div class="card"><textarea id="json" rows="30">${esc(JSON.stringify(cfg, null, 2))}</textarea></div>`,
    preview: {
      title: "folders → Safes with the settings as typed (any valid JSON)",
      load: previewApi("safes"), summary: countsSummary,
      head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(3, "Safes.csv")}</tr><tr><th>Folder</th><th>Accounts</th><th>safeName</th><th>managingCPM</th><th>Keeps</th></tr>`,
      row: (x) => `<tr><td>${esc(x.folder || "(no folder)")}</td><td>${x.accounts}</td><td${chg(x, "safe", "nowrap")}><b>${esc(x.safe)}</b></td>
        <td${chg(x, "cpm")}>${esc(x.cpm)}</td><td${chg(x, "keeps")}>${esc(x.keeps)}</td></tr>`,
    },
    collect() {
      try { return { __full: JSON.parse($("#json").value) }; } catch (e) { throw new Error("The JSON is not valid: " + e.message); }
    },
  }));

/* ---------------- 3. Review ---------------- */
PAGES.review = async () => {
  await refresh();
  if (!STATE.has_db) return msg($("#main"), "warn", "Load some exports first (step 1).");
  const active = ["safe", "platform", "source", "status"].filter(k => REVIEW.filters[k]).length;
  $("#main").innerHTML = `<h2>3. Review &amp; change · B. Accounts &amp; platforms</h2>
    <p class="lead">Pick a list, tick accounts and change them, or click a row to see and change one account. Your changes are kept when the rules or exports change.</p>
    <div class="card" id="filters">
      <div class="row"><label class="inline"><b>Show</b> <select id="view">${Object.entries(STATE.views).map(([k, v]) => `<option value="${esc(k)}" ${k === REVIEW.view ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
        <input type="search" id="f-search" placeholder="Search name, user, address, folder…" size="28" value="${esc(REVIEW.filters.search || "")}">
        <button class="btn" id="more-filters" aria-expanded="${active ? "true" : "false"}">Filters${active ? ` (${active})` : ""}</button>
        <button class="btn${active || REVIEW.filters.search ? "" : " hidden"}" id="clear">Clear filters</button>
        <label class="inline" style="margin-left:auto" title="Review: the usual columns. Source → upload CSV: what the export had on the left, and the Accounts.csv columns it becomes on the right.">Columns
          <select id="cols-mode"><option value="review">Review</option><option value="csv" ${REVIEW.mode === "csv" ? "selected" : ""}>Source → upload CSV</option></select></label></div>
      <div class="row${active ? "" : " hidden"}" id="filter-row" style="margin-top:8px"><select id="f-safe"></select><select id="f-platform"></select><select id="f-source"></select><select id="f-status"></select></div>
    </div>
    <div id="list"></div>
    <div id="act-msg"></div>
    <div class="actionbar hidden" id="acts">
      <div class="row"><b id="selinfo">0 selected</b>
        <input type="text" id="reason" placeholder="Reason (optional, kept in the log)" size="30">
        <button class="linkbtn" id="unselect">Clear selection</button></div>
      <div class="row" style="margin-top:8px;align-items:flex-start">
        <span><input type="text" id="a-safe" list="dl-a-safes" size="22" placeholder="Safe name" data-check="safe">
          <button class="btn" data-act="safe">Move to this Safe</button></span>
        <span><input type="text" id="a-plat" list="dl-a-plats" size="18" placeholder="Platform ID or (none)" data-check="platform">
          <button class="btn" data-act="platform">Set this platform</button></span>
        <button class="btn" data-act="exclude">Leave out</button>
        <button class="btn" data-act="include">Include again</button>
        <button class="btn" data-act="approve" title="Mark the ticked accounts that need a look as checked by you. They keep the Needs a look label with a green tick. If anything about an account changes later, its approval goes away and it needs a look again.">✓ Approve</button>
        <button class="btn" data-act="unapprove" title="Take your approval back from the ticked accounts">Remove approval</button></div>
      <details class="explain" style="margin:8px 0 0;padding:4px 10px"><summary>More actions</summary>
        <div class="row" style="margin-top:6px"><span><input type="text" id="a-name" size="22" placeholder="New account name" data-check="account">
          <button class="btn" data-act="rename">Rename (one account)</button></span>
          <button class="btn" data-act="noname" title="Leave the name empty in Accounts.csv; Privilege Cloud generates one on upload. Works on many accounts at once.">Let Privilege Cloud name them</button>
          <button class="btn danger" data-act="undo">Undo my changes</button></div></details>
      <datalist id="dl-a-safes"></datalist><datalist id="dl-a-plats"></datalist></div>
    <div class="floatbar"><button class="btn" data-go="review-safes">‹ A. Safes &amp; members</button><button class="btn primary" data-go="output">Next: 4. Create upload files ›</button></div>`;
  $("#view").onchange = () => { REVIEW.view = $("#view").value; REVIEW.page = 0; loadList(); };
  $("#cols-mode").onchange = () => { REVIEW.mode = $("#cols-mode").value; loadList(); };
  ["safe", "platform", "source", "status"].forEach(k => $(`#f-${k}`).onchange = () => { REVIEW.filters[k] = $(`#f-${k}`).value; REVIEW.page = 0; syncFilters(); loadList(); });
  let t; $("#f-search").oninput = () => { clearTimeout(t); t = setTimeout(() => { if (!$("#f-search")) return;   // the page was left meanwhile
    REVIEW.filters.search = $("#f-search").value; REVIEW.page = 0; syncFilters(); loadList(); }, 300); };
  $("#more-filters").onclick = () => { const row = $("#filter-row"); row.classList.toggle("hidden"); $("#more-filters").setAttribute("aria-expanded", String(!row.classList.contains("hidden"))); };
  $("#clear").onclick = () => { REVIEW.filters = {}; $("#f-search").value = ""; REVIEW.page = 0; syncFilters(); loadList(); };
  $("#unselect").onclick = () => { REVIEW.all = false; document.querySelectorAll(".sel:checked").forEach(cb => { cb.checked = false; toggle(cb); }); if ($("#selall")) $("#selall").checked = false; updateSel(); };
  document.querySelectorAll("[data-act]").forEach(b => b.onclick = () => act(b.dataset.act));
  await loadList();
};
function syncFilters() {
  const active = ["safe", "platform", "source", "status"].filter(k => REVIEW.filters[k]).length;
  $("#more-filters").textContent = "Filters" + (active ? ` (${active})` : "");
  $("#clear").classList.toggle("hidden", !active && !REVIEW.filters.search);
}
async function loadList() {
  const d = await api("/api/accounts", { view: REVIEW.view, filters: REVIEW.filters, page: REVIEW.page, sort: REVIEW.sort, desc: REVIEW.desc });
  REVIEW.data = d; REVIEW.selected.clear(); REVIEW.all = false;
  const labels = { safe: "All Safes", platform: "All platforms", source: "All sources", status: "Any status" };
  for (const k of Object.keys(labels)) {
    const cur = REVIEW.filters[k] || "";
    $(`#f-${k}`).innerHTML = `<option value="">${labels[k]}</option>` + d.facets[k].filter(v => v !== "").map(v =>
      `<option ${v === cur ? "selected" : ""} value="${esc(v)}">${esc(k === "status" ? STATUS_LABEL[v] || v : k === "source" ? SOURCE_NAMES[v] || v : v)}</option>`).join("");
  }
  $("#dl-a-safes").innerHTML = d.facets.safe.filter(Boolean).map(v => `<option value="${esc(v)}">`).join("");
  $("#dl-a-plats").innerHTML = `<option value="(none)">no platform: the account is not uploaded</option>` + d.facets.platform.filter(Boolean).map(v => `<option value="${esc(v)}">`).join("");
  // The status column only says something when the list mixes statuses.
  const showStatus = REVIEW.view !== "errors";
  const csv = REVIEW.mode === "csv";
  const cols = csv
    ? [["folder", "Folder"], ["source_type", "Type"]].concat([["account_name", "name"], ["target_safe", "safeName"], ["platform_id", "platformId"], ["address", "address"], ["username", "userName"]])
    : [["account_name", "Account"], ["target_safe", "Safe"], ["platform_id", "Platform"], ["address", "Address"], ["username", "Username"]];
  const whyLabel = REVIEW.view === "errors" ? "Why it isn't uploaded" : ["review", "review_open", "approved"].includes(REVIEW.view) ? "Why it needs a look" : "Notes";
  const pages = Math.ceil(d.total / d.page_size);
  const sortTh = ([k, l], extra = "") => SORTABLE_COLS.has(k)
    ? `<th class="sort${extra}" data-k="${k}">${l}${REVIEW.sort === k ? (REVIEW.desc ? " ▼" : " ▲") : ""}</th>` : `<th${extra ? ` class="${extra.trim()}"` : ""}>${l}</th>`;
  const left = (r) => !showStatus && r.migrate === "N" ? ' <span class="pill N">left out</span>' : "";
  const head = csv
    ? `<tr><th></th>${SRC_HEAD(4)}${CSV_HEAD(6, "Accounts.csv")}<th class="grp" colspan="${showStatus ? 2 : 1}"></th></tr>
       <tr><th><input type="checkbox" id="selall" title="Tick every account on this page"></th><th>Name</th><th>Address</th>${sortTh(["folder", "Folder"])}<th>Type</th>
       ${sortTh(["target_safe", "safeName"])}${sortTh(["platform_id", "platformId"])}${sortTh(["account_name", "name"])}${sortTh(["address", "address"])}${sortTh(["username", "userName"])}<th>secretType</th>
       ${showStatus ? sortTh(["status", "Status"]) : ""}<th>${whyLabel}</th></tr>`
    : `<tr><th><input type="checkbox" id="selall" title="Tick every account on this page"></th>
      ${cols.concat(showStatus ? [["status", "Status"]] : []).map(c => sortTh(c)).join("")}
      <th title="What is wrong with this account itself. Notes about its Safe (for example no access groups or a shortened Safe name) are on 3A. Safes &amp; members.">${whyLabel}</th></tr>`;
  const ncols = csv ? 12 + (showStatus ? 1 : 0) : cols.length + 2 + (showStatus ? 1 : 0);
  const row = (r, i) => csv
    ? `<tr class="clickable" data-i="${i}"><td><input type="checkbox" class="sel" data-id="${esc(r.record_id)}"></td>
      <td>${esc(r.source_name)}</td><td>${esc(r.source_address)}</td><td class="small">${esc(r.folder)}</td><td class="small">${esc(r.source_type)}</td>
      <td class="nowrap">${esc(r.target_safe)}</td><td class="nowrap">${esc(r.platform_id) || '<span class="pill ERROR">no platform</span>'}</td>
      <td>${r.account_name ? esc(r.account_name) : PC_NAMES}${left(r)}</td><td>${esc(r.address)}</td><td>${esc(r.username)}</td><td class="small">${esc(r.secret_type)}</td>
      ${showStatus ? `<td class="nowrap">${statusPill(r.status, r.approved)}${r.migrate === "N" ? ' <span class="pill N">left out</span>' : ""}</td>` : ""}
      <td class="why">${esc(r.notes || "")}</td></tr>`
    : `<tr class="clickable" data-i="${i}">
      <td><input type="checkbox" class="sel" data-id="${esc(r.record_id)}"></td>
      <td>${r.account_name ? esc(r.account_name) : PC_NAMES}${left(r)}</td><td class="nowrap">${esc(r.target_safe)}</td>
      <td class="nowrap">${esc(r.platform_id) || '<span class="pill ERROR">no platform</span>'}</td><td>${esc(r.address)}</td><td>${esc(r.username)}</td>
      ${showStatus ? `<td class="nowrap">${statusPill(r.status, r.approved)}${r.migrate === "N" ? ' <span class="pill N">left out</span>' : ""}</td>` : ""}
      <td class="why">${esc(r.notes || "")}</td></tr>`;
  $("#list").innerHTML = `<p class="muted small">${d.total} accounts${pages > 1 ? ` · page ${d.page + 1} of ${pages}
      <button class="btn small" ${d.page ? "" : "disabled"} id="prev">‹ Prev</button> <button class="btn small" ${d.page + 1 < pages ? "" : "disabled"} id="next">Next ›</button>` : ""}
      ${d.total ? ` · <button class="linkbtn" id="allmatch-link" title="Tick every account in this list, on every page">Select all ${d.total} in this list</button>` : ""}
      ${csv ? " · secrets are never shown; secretType says what kind each one is" : ""}</p>
    <div class="tablewrap"><table id="acc-table"><thead>${head}</thead>
    <tbody>${d.rows.map(row).join("") || `<tr><td colspan="${ncols}" class="muted">Nothing in this list.</td></tr>`}</tbody></table></div>`;
  if (csv) markCsvColumn($("#acc-table"));
  if ($("#prev")) { $("#prev").onclick = () => { REVIEW.page--; loadList(); }; $("#next").onclick = () => { REVIEW.page++; loadList(); }; }
  document.querySelectorAll("th.sort").forEach(th => th.onclick = () => { REVIEW.desc = REVIEW.sort === th.dataset.k ? !REVIEW.desc : false; REVIEW.sort = th.dataset.k; loadList(); });
  $("#selall").onchange = () => document.querySelectorAll(".sel").forEach(cb => { cb.checked = $("#selall").checked; toggle(cb); });
  if ($("#allmatch-link")) $("#allmatch-link").onclick = () => { REVIEW.all = true; document.querySelectorAll(".sel").forEach(cb => { cb.checked = true; toggle(cb); }); updateSel(); };
  document.querySelectorAll(".sel").forEach(cb => { cb.onclick = (e) => e.stopPropagation(); cb.onchange = () => { if (!cb.checked) REVIEW.all = false; toggle(cb); }; });
  document.querySelectorAll("tr.clickable").forEach(tr => tr.onclick = () => showRecord(d.rows[tr.dataset.i].record_id));
  updateSel();
}
function toggle(cb) { cb.checked ? REVIEW.selected.add(cb.dataset.id) : REVIEW.selected.delete(cb.dataset.id); cb.closest("tr").classList.toggle("selected", cb.checked); updateSel(); }
// The action bar shows only once something is ticked.
function updateSel() {
  const all = REVIEW.all;
  $("#selinfo").textContent = all ? `All ${REVIEW.data ? REVIEW.data.total : 0} in this list` : `${REVIEW.selected.size} selected`;
  const show = all || REVIEW.selected.size > 0;
  $("#acts").classList.toggle("hidden", !show);
}
async function act(kind) {
  const all = REVIEW.all;
  const count = all ? REVIEW.data.total : REVIEW.selected.size;
  if (!count) return msg($("#act-msg"), "err", "Tick some accounts first, or click “Select all” above the list.");
  if (kind === "approve" || kind === "unapprove") {
    const body = all ? { view: REVIEW.view, filters: REVIEW.filters } : { ids: [...REVIEW.selected] };
    try {
      const r = await api("/api/approve", { ...body, approve: kind === "approve", reason: $("#reason").value });
      await loadList(); await refresh();
      const skipped = r.selected - r.changed;
      msg($("#act-msg"), r.changed ? "ok" : "warn", kind === "approve"
        ? `Approved ${r.changed} ${r.changed === 1 ? "account" : "accounts"}.${skipped ? ` ${skipped} didn't need a look (or had an error), so there was nothing to approve.` : ""} The approval goes away if anything about an account changes.`
        : `Took the approval back from ${r.changed} ${r.changed === 1 ? "account" : "accounts"}.`);
    } catch (e) { msg($("#act-msg"), "err", e.message); }
    return;
  }
  let values;
  if (kind === "exclude") values = { migrate: "N" };
  else if (kind === "include") values = { migrate: "Y" };
  else if (kind === "undo") { if (!confirm(`Remove all your changes from ${count} accounts?`)) return; values = { migrate: "", target_safe: "", platform_id: "", account_name: "" }; }
  else if (kind === "safe") { const v = $("#a-safe").value.trim(); if (!v) return msg($("#act-msg"), "err", "Type or pick the Safe to move them to."); values = { target_safe: v }; }
  else if (kind === "platform") {
    const v = $("#a-plat").value.trim(); if (!v) return msg($("#act-msg"), "err", "Type or pick a platform ID, or (none) for no platform.");
    if (v === "(none)" && !confirm(`Remove the platform from ${count} accounts? Accounts without a platform are not uploaded.`)) return;
    values = { platform_id: v }; }
  else if (kind === "noname") values = { account_name: "(none)" };
  else if (kind === "rename") { if (count !== 1 || all) return msg($("#act-msg"), "err", "Rename one account at a time."); const v = $("#a-name").value.trim(); if (!v) return msg($("#act-msg"), "err", "Type the new account name."); values = { account_name: v }; }
  if (all && count > 20 && !confirm(`This changes ${count} accounts. Continue?`)) return;
  const body = all ? { view: REVIEW.view, filters: REVIEW.filters, values, reason: $("#reason").value }
                   : { ids: [...REVIEW.selected], values, reason: $("#reason").value };
  try {
    const r = await api("/api/edit", body);
    saved("main");
    await loadList(); await refresh();
    ["#a-safe", "#a-plat", "#a-name"].forEach(k => { $(k).value = ""; checkInput($(k)); });
    okOrCleaned($("#act-msg"), r, `Changed ${r.changed} accounts. Rules re-applied.`);
  } catch (e) { msg($("#act-msg"), "err", e.message); }
}
function closeDrawer() { $("#drawer").classList.add("hidden"); }
async function showRecord(id) {
  if (!leaveOk("panel")) return;
  const r = await api("/api/record", { id });
  const p = r.plan || {};
  const dl = (o) => `<dl>${Object.entries(o).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
  const edited = Object.fromEntries(r.edits.map(e => [e.field, e]));
  const undo = (f) => edited[f] ? ` <button class="btn small" data-undo-field="${f}" title="Remove your change; the rules decide again">Undo</button>` : "";
  const tag = (f) => edited[f] ? ' <span class="pill REVIEW">your change</span>' : "";
  const noName = !p.account_name;
  $("#drawer").innerHTML = `<div class="row"><h3 style="margin:0;flex:1">${esc(p.account_name || r.name || "(no name)")}</h3><button class="btn" data-close-drawer="1">Close</button></div>
    <p>${statusPill(p.status, p.approved)} ${p.migrate === "N" ? '<span class="pill N">left out</span>' : ""}</p>
    ${p.notes ? `<div class="msg ${p.status === "ERROR" ? "err" : "warn"} small"><b>${p.status === "OK" ? "Note" : "Why"}:</b> ${esc(p.notes)}</div>` : ""}
    ${p.status === "REVIEW" ? (r.approval
      ? `<div class="msg ok small" title="${esc(APPROVED_TIP)}">✓ Approved by ${esc(r.approval.approved_by)}, ${esc((r.approval.approved_utc || "").slice(0, 16).replace("T", " "))} UTC${r.approval.reason ? ` · ${esc(r.approval.reason)}` : ""}.
          It goes away if anything about this account changes. <button class="btn small" id="ra-unapprove">Remove approval</button></div>`
      : `<div class="row"><button class="btn small" id="ra-approve" title="${esc(APPROVED_TIP)}">✓ Approve: I looked at it and it's fine</button></div>`) : ""}
    <h4 title="Change any value and click Save. Your changes win over the mapping rules and are kept when rules or exports change; Undo hands a value back to the rules.">Where it goes in Privilege Cloud</h4>
    <div class="bulk"><div>
      <label>Safe${tag("target_safe")} <input type="text" id="ra-safe" list="dl-a-safes" value="${esc(p.target_safe || "")}" data-check="safe"
        title="Safe this account goes to. Pick one or type a new name; forbidden characters \\ / : * ? &quot; < > | become -."></label>
      <p class="muted small">From ${esc(howChosen(p.safe_mapping_source))}${p.proposed_safe && p.proposed_safe !== p.target_safe ? ` · the rules proposed ${esc(p.proposed_safe)}` : ""}${undo("target_safe")}</p>
      <label>Platform ID${tag("platform_id")} <input type="text" id="ra-plat" list="dl-a-plats" value="${esc(p.platform_id || "")}" data-check="platform"
        title="Platform ID exactly as in Privilege Cloud (letters, digits, _ . -), e.g. WinDomain. (none) removes the platform, so the account is not uploaded."></label>
      <p class="muted small">From ${esc(howChosen(p.platform_source))}${undo("platform_id")}</p>
      <label>Account name${tag("account_name")} <input type="text" id="ra-name" value="${esc(p.account_name || "")}" data-check="account" ${noName ? 'placeholder="(Privilege Cloud names it)"' : ""}
        title="The account's name in its Safe. \\ / : * ? &quot; < > | become _. Leave the box ticked below to let Privilege Cloud name it."></label>
      <label class="inline" style="color:var(--ink)"><input type="checkbox" id="ra-noname" ${noName ? "checked" : ""} title="Leave the name empty in Accounts.csv; Privilege Cloud generates one on upload."> Let Privilege Cloud name it</label>
      <p class="muted small">${undo("account_name")}</p>
      <label>Migrate${tag("migrate")} <select id="ra-migrate" title="Yes = upload this account. No = leave it out of the upload files.">
        <option value="Y" ${p.migrate !== "N" ? "selected" : ""}>Yes, upload it</option><option value="N" ${p.migrate === "N" ? "selected" : ""}>No, leave it out</option></select></label>
      <p class="muted small">${undo("migrate")}</p>
      <label>Reason (optional) <input type="text" id="ra-reason" placeholder="kept in the activity log"></label>
      <div class="row"><button class="btn primary" id="ra-save">Save</button></div>
      <div id="ra-msg"></div></div></div>
    <div style="margin-top:12px">${dl({ Address: p.address, Username: p.username, Folder: r.folder })}</div>
    <details class="card fold" style="margin-top:12px"><summary>Access groups (${r.grants.length})</summary>${r.grants.length ? `<table><tr><th>Group</th><th>Permission</th></tr>${r.grants.map(g => `<tr><td>${esc(g.member)}</td><td>${esc(g.permission)}</td></tr>`).join("")}</table>` : '<p class="muted">None</p>'}
      <p class="muted small">Who gets access is set per Safe: <a href="#" id="ra-open-safe">open ${esc(p.target_safe || "the Safe")} in Safes &amp; members ›</a></p></details>
    <details class="card fold"${r.edits.length ? " open" : ""}><summary>Your changes (${r.edits.length})</summary>${r.edits.length ? `<table><tr><th>Field</th><th>Value</th><th>When / who</th><th>Reason</th></tr>${r.edits.map(e => `<tr><td>${esc(e.field)}</td><td>${esc(e.value)}</td><td class="small">${esc(e.changed_utc)}<br>${esc(e.changed_by)}</td><td>${esc(e.reason)}</td></tr>`).join("")}</table>` : '<p class="muted">None</p>'}</details>
    <details class="card fold"><summary>Everything from the source</summary>${dl({ "Record ID": r.record_id, Source: SOURCE_NAMES[r.source] || r.source, "Where": r.source_ref, Type: r.type, Folder: r.folder, Name: r.name, "Secret type": p.secret_type, "Secret present": p.has_secret === "Y" ? "yes (hidden)" : "no", ...r.extra })}</details>`;
  $("#drawer").classList.remove("hidden");
  const approve = async (yes) => {
    try {
      await api("/api/approve", { ids: [id], approve: yes, reason: $("#ra-reason").value });
      if (PAGE === "review") await loadList();
      await refresh(); await showRecord(id);
    } catch (e) { msg($("#ra-msg"), "err", e.message); }
  };
  if ($("#ra-approve")) $("#ra-approve").onclick = () => approve(true);
  if ($("#ra-unapprove")) $("#ra-unapprove").onclick = () => approve(false);
  const syncName = () => { $("#ra-name").disabled = $("#ra-noname").checked; };
  $("#ra-noname").onchange = syncName; syncName();
  const save = async (values, done) => {
    try {
      const r = await api("/api/edit", { ids: [id], values, reason: $("#ra-reason").value });
      saved("panel");
      if (PAGE === "review") await loadList();
      await refresh(); await showRecord(id);
      okOrCleaned($("#ra-msg"), r, done || "Saved. Rules re-applied.");
    } catch (e) { msg($("#ra-msg"), "err", e.message); }
  };
  $("#ra-save").onclick = () => {
    const values = {};
    const safe = $("#ra-safe").value.trim(), plat = $("#ra-plat").value.trim();
    const name = $("#ra-noname").checked ? "(none)" : $("#ra-name").value.trim();
    if (safe && safe !== (p.target_safe || "")) values.target_safe = safe;
    if (plat && plat !== (p.platform_id || "")) values.platform_id = plat;
    if (name === "(none)" ? !noName : name && name !== (p.account_name || "")) values.account_name = name;
    if (!$("#ra-noname").checked && !name && noName) return msg($("#ra-msg"), "err", "Type a name, or tick Let Privilege Cloud name it.");
    if ($("#ra-migrate").value !== (p.migrate === "N" ? "N" : "Y")) values.migrate = $("#ra-migrate").value;
    if (!Object.keys(values).length) return msg($("#ra-msg"), "warn", "Nothing changed.");
    if (values.platform_id === "(none)" && !confirm("Remove the platform? Accounts without a platform are not uploaded.")) return;
    save(values);
  };
  document.querySelectorAll("#drawer [data-undo-field]").forEach(b => b.onclick = () => save({ [b.dataset.undoField]: "" }, "Undone. The rules decide this value again."));
  $("#ra-open-safe").onclick = (e) => { e.preventDefault(); const safe = p.target_safe; go("review-safes"); if (PAGE === "review-safes" && safe) SAFES.panel = { kind: "safe", id: safe }; };
}

/* ---------------- 3A. Safes & Safe members ---------------- */
const SAFES = { selected: new Set(), members: new Set(), filter: "", nofull: false };
const NO_FULL = "no member with full permissions";   // the start of the Safe issue (imw/transform.py NO_FULL_MEMBER_NOTE)
const NO_FULL_TIP = "No user, group or role from your source has full permissions on this Safe (the Full role, or a custom role with every Full permission), so after the upload only the user who uploads it and the Privilege Cloud administrators can manage it and its members.";
PAGES.safes = async () => go("review-safes");
PAGES["review-safes"] = async () => {
  await refresh();
  if (!STATE.has_db) return msg($("#main"), "warn", "Load some exports first (step 1).");
  const d = await api("/api/safes");
  SAFES.data = d;
  const names = new Set(d.safes.map(s => s.safe_name));
  SAFES.selected = new Set([...SAFES.selected].filter(n => names.has(n)));
  SAFES.members.clear();
  const changed = d.people.filter(p => p.edited);
  const editsHtml = d.member_edits.length || changed.length ? `<details class="card fold" id="member-edits"><summary>Your member changes (${d.member_edits.length + changed.length})</summary>
      <p class="muted small">These are kept when the rules or exports change. Undo puts back what the rules give.</p>
      <div class="tablewrap" style="max-height:30vh"><table class="small"><tr><th>Safe</th><th>Member</th><th>Change</th><th>searchIn</th><th>Type</th><th>Role</th><th>When / who</th><th>Reason</th><th></th></tr>
      ${d.member_edits.map((e, i) => `<tr><td>${esc(e.safe_name)}</td><td>${esc(e.member_name)}</td><td>${e.action === "add" ? '<span class="pill OK">added</span>' : '<span class="pill REVIEW">removed</span>'}</td>
        <td>${esc(e.action === "add" ? e.search_in || "(all)" : "")}</td><td>${esc(e.action === "add" ? e.member_type : "")}</td><td>${esc(e.action === "add" ? e.role : "")}</td>
        <td>${esc(e.changed_utc)}<br>${esc(e.changed_by)}</td><td>${esc(e.reason)}</td>
        <td><button class="btn small" data-undo="${i}">Undo</button></td></tr>`).join("")}
      ${changed.map(p => `<tr><td class="muted">(every Safe)</td><td>${esc(p.source_member)}</td><td><span class="pill REVIEW">edited</span></td>
        <td>${esc(p.search_in || "(all)")}</td><td>${esc(p.member_type)}</td><td class="muted">name: ${esc(p.member_name)}</td>
        <td>${esc(p.override.changed_utc)}<br>${esc(p.override.changed_by)}</td><td>${esc(p.override.reason || "")}</td>
        <td><button class="btn small" data-undo-person="${esc(p.key)}">Undo</button></td></tr>`).join("")}</table></div></details>` : "";
  const memberCount = {};
  d.people.forEach(p => p.safes.forEach(x => { memberCount[x.safe_name] = (memberCount[x.safe_name] || 0) + 1; }));
  // A Safe that is uploaded needs at least one member with full permissions (the Full role, or a custom role with all of Full's).
  const noFull = (s) => (s.issues || "").includes(NO_FULL);
  const noFullCount = d.safes.filter(noFull).length;
  const membersCell = (s) => memberCount[s.safe_name]
    ? memberCount[s.safe_name] + (noFull(s) ? ` <span class="pill REVIEW" title="${esc(NO_FULL_TIP)}">no full member</span>` : "")
    : `<span class="pill REVIEW" title="Nobody from your source gets access to this Safe. ${esc(NO_FULL_TIP)}">none</span>`;
  const tab = SAFES.tab || "safes";
  const csvMode = SAFES.mode === "csv";
  const safeLink = (s) => `<a href="#" data-members-of="${esc(s.safe_name)}" title="Rename this Safe, change its settings or its members">${esc(s.safe_name)}</a>${s.override_json ? ' <span class="pill REVIEW" title="You changed this Safe\'s name or settings directly">changed by you</span>' : ""}${nameNote(s)}`;
  const nameNote = (s) => s.valid_safe_name !== "TRUE"
    ? ` <span class="pill REVIEW" title="${esc(`The rules proposed ${s.proposed_names}: ${s.issues}`)}">name changed</span>`
    : s.issues ? ` <span class="pill REVIEW" title="${esc(s.issues)}">⚠</span>` : "";
  $("#main").innerHTML = `<h2>3. Review &amp; change · A. Safes &amp; members</h2>
    <p class="lead">The Safes the upload will create and who gets access. Click a Safe or a member to see and change it. To change how Safes are named or who gets access everywhere, use the rules in step 2
      (<a href="#" data-go="rules-safes">Safes</a>, <a href="#" data-go="rules-members">Safe members</a>, <a href="#" data-go="rules-dir">member names</a>).</p>
    ${safeEditsHtml(d)}${editsHtml}
    <div class="tabs" role="tablist"><button data-tab="safes" class="${tab === "safes" ? "on" : ""}" role="tab">Safes (${d.safes.length})</button>
      <button data-tab="members" class="${tab === "members" ? "on" : ""}" role="tab">Members (${d.people.length})</button><label class="inline small" style="margin-left:auto;align-self:center" title="Review: the usual columns. Source → upload CSV: what the export had on the left, and the Safes.csv / SafeMembers.csv columns it becomes on the right.">Columns
      <select id="s-cols-mode"><option value="review">Review</option><option value="csv" ${csvMode ? "selected" : ""}>Source → upload CSV</option></select></label></div>
    <div id="tab-safes" class="${tab === "safes" ? "" : "hidden"}">
      ${noFullCount ? `<div class="msg warn">${noFullCount} ${noFullCount === 1 ? "Safe has" : "Safes have"} no member with full permissions, so nobody from your source could manage ${noFullCount === 1 ? "it" : "them"} or ${noFullCount === 1 ? "its" : "their"} members after the upload.
        Give one user, group or role the <b>Full</b> role: tick the Safes, then <b>Add to ticked Safes</b> with role Full; or map a source permission to Full in <a href="#" data-go="rules-members">B. Safe members</a>.
        <label class="inline" style="margin-left:8px"><input type="checkbox" id="s-nofull" ${SAFES.nofull ? "checked" : ""}> show only these Safes</label></div>` : ""}
      <div class="row" style="margin-bottom:8px"><input type="search" id="s-filter" placeholder="Show Safes containing…" size="28" value="${esc(SAFES.filter)}">
        <button class="btn small" id="s-tick-shown">Tick the Safes shown</button>
        <span class="muted small" id="s-count"></span></div>
      <div class="tablewrap"><table id="safes-table">${csvMode ? `<thead><tr><th></th>${SRC_HEAD(2)}${CSV_HEAD(7, "Safes.csv")}<th class="grp" colspan="2"></th></tr>
        <tr><th></th><th title="The source folders whose accounts go to this Safe">Folders</th><th title="The name the rules gave, before cleanup or your rename">Rules proposed</th>
        <th>safeName</th><th>managingCPM</th><th title="numberOfVersionsRetention or numberOfDaysRetention">Keeps</th><th>description</th><th>location</th><th>olacEnabled</th><th>autoPurgeEnabled</th>
        <th>Accounts</th><th>Members</th></tr></thead><tbody>` : `<tr><th></th><th>Safe</th><th>Accounts</th><th>To upload</th><th>Members</th><th>CPM</th><th>Keeps</th><th>Description</th></tr>`}
      ${d.safes.map(s => csvMode ? `<tr data-name="${esc((s.safe_name + " " + (s.source_folders || "")).toLowerCase())}"${noFull(s) ? ' data-nofull="1"' : ""}><td><input type="checkbox" class="s-sel" value="${esc(s.safe_name)}" ${SAFES.selected.has(s.safe_name) ? "checked" : ""}></td>
        <td class="small">${esc(s.source_folders || "").split(" | ").join("<br>")}</td><td class="small">${esc(s.proposed_names || "")}</td>
        <td class="nowrap">${safeLink(s)}</td><td class="small">${esc(s.managing_cpm || "")}</td><td class="small nowrap">${esc(s.retention || "")}</td><td class="small">${esc(s.description || "")}</td>
        <td class="small">${esc(s.location || "")}</td><td class="small">${esc(s.olac_enabled || "")}</td><td class="small">${esc(s.auto_purge || "")}</td>
        <td><a href="#" data-safe="${esc(s.safe_name)}" title="Show this Safe's accounts in B. Accounts &amp; platforms">${s.accounts}</a></td>
        <td class="nowrap">${membersCell(s)}</td></tr>`
        : `<tr data-name="${esc(s.safe_name.toLowerCase())}"${noFull(s) ? ' data-nofull="1"' : ""}><td><input type="checkbox" class="s-sel" value="${esc(s.safe_name)}" ${SAFES.selected.has(s.safe_name) ? "checked" : ""}></td>
        <td class="nowrap">${safeLink(s)}</td>
        <td><a href="#" data-safe="${esc(s.safe_name)}" title="Show this Safe's accounts in B. Accounts &amp; platforms">${s.accounts}</a></td><td>${s.accounts_to_upload}</td>
        <td class="nowrap">${membersCell(s)}</td>
        <td class="small">${esc(s.managing_cpm || "")}</td><td class="small nowrap">${esc(s.retention || "")}</td><td class="small">${esc(s.description || "")}</td></tr>`).join("")}${csvMode ? "</tbody>" : ""}</table></div>
      <div class="actionbar hidden" id="s-acts"><div class="row"><b id="s-selinfo"></b><input type="text" id="m-reason" placeholder="Reason (optional, kept in the log)" size="30">
          <button class="linkbtn" id="s-untick">Untick all</button></div>
        <div class="bulk" style="margin-top:8px">
          <div><h4>Add a member to the ticked Safes</h4>
            <label>Member name <input type="text" id="m-name" list="dl-members" placeholder="PAM-Auditors" data-check="member"></label>
            <label>searchIn (optional) <input type="text" id="m-dir" list="dl-dirs" value="" placeholder="empty = all directories"></label>
            <div class="row"><label style="flex:1">Type <select id="m-type">${MEMBER_TYPES.map(t => `<option>${t}</option>`).join("")}</select></label>
              <label style="flex:1">Role <select id="m-role">${d.roles.map(r => `<option>${esc(r)}</option>`).join("")}</select></label></div>
            <button class="btn primary" id="m-add">Add to ticked Safes</button></div>
          <div><h4>Remove a member from the ticked Safes</h4>
            <label>Member name <input type="text" id="m-rname" list="dl-members" placeholder="CORP\\Old-Team"></label>
            <p class="muted small">Takes the member off those Safes even when the rules or the export give it access.</p>
            <button class="btn danger" id="m-remove">Remove from ticked Safes</button></div>
        </div></div>
      <div id="m-msg"></div>
      <datalist id="dl-members">${d.known_members.map(m => `<option value="${esc(m)}">`).join("")}</datalist>
      <datalist id="dl-dirs">${d.directories.map(m => `<option value="${esc(m)}">`).join("")}</datalist></div>
    <div id="tab-members" class="${tab === "members" ? "" : "hidden"}">
      <p class="muted small">Every user, group and role: those on a Safe, and those in your export whose accounts are not being uploaded.</p>
      <div class="row" style="margin-bottom:8px"><input type="search" id="p-filter" placeholder="Show members containing…" size="28" value="${esc(SAFES.pfilter || "")}">
        <label class="inline${csvMode ? " hidden" : ""}"><input type="checkbox" id="p-nosafe" ${SAFES.nosafe ? "checked" : ""}> only members on no Safe</label><span class="muted small" id="p-count"></span></div>
      ${csvMode ? `<div class="tablewrap"><table id="sm-table"><thead><tr>${SRC_HEAD(2)}${CSV_HEAD(5, "SafeMembers.csv")}<th class="grp" colspan="2"></th></tr>
        <tr><th>Member in the export</th><th title="The permission the source gives (the strongest, when it has several)">Permission</th><th>safeName</th><th>memberName</th><th>memberType</th><th>searchIn</th><th>role</th><th>Accounts</th><th>Notes</th></tr></thead>
        <tbody>${d.members.map(m => `<tr class="clickable" data-sm-safe="${esc(m.safe_name)}" data-name="${esc([m.source_member, m.member_name, m.safe_name].join(" ").toLowerCase())}">
          <td>${esc(m.source_member || "")}</td><td>${esc(m.source_permission || "")}</td><td class="nowrap">${esc(m.safe_name)}</td><td>${esc(m.member_name)}</td><td>${esc(m.member_type)}</td>
          <td>${m.search_in ? esc(m.search_in) : '<span class="muted">(all)</span>'}</td><td class="nowrap">${m.role === "UNMAPPED" ? '<span class="pill ERROR">no role</span>' : esc(m.role)}</td>
          <td>${m.accounts}</td><td class="notes">${esc(m.notes || "")}</td></tr>`).join("") || '<tr><td colspan="9" class="muted">No members.</td></tr>'}</tbody></table></div>` : ""}
      <div class="tablewrap${csvMode ? " hidden" : ""}"><table id="people-table"><tr><th>Member</th><th>Type</th><th>searchIn</th><th>Safes</th><th>In the export as</th><th>Export accounts</th></tr>
      ${d.people.map((m, i) => `<tr class="clickable" data-person="${i}" data-name="${esc((m.member_name + " " + m.source_member).toLowerCase())}" data-nosafe="${m.safes.length ? "" : 1}">
        <td><a href="#" data-person-link="${i}">${esc(m.member_name)}</a>${m.edited ? ' <span class="pill REVIEW">edited</span>' : ""}</td><td>${esc(m.member_type)}</td>
        <td>${m.search_in ? esc(m.search_in) : '<span class="muted">(all)</span>'}</td>
        <td>${m.safes.length ? m.safes.length : '<span class="pill REVIEW">no Safe</span>'}</td>
        <td class="small">${esc(m.source_member || "")}</td><td>${m.export_accounts || ""}</td></tr>`).join("")}</table></div></div>
    <div class="floatbar"><button class="btn primary" data-go="review">Next: B. Accounts &amp; platforms ›</button></div>`;
  document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => {
    SAFES.tab = b.dataset.tab;
    document.querySelectorAll("[data-tab]").forEach(x => x.classList.toggle("on", x === b));
    $("#tab-safes").classList.toggle("hidden", SAFES.tab !== "safes"); $("#tab-members").classList.toggle("hidden", SAFES.tab !== "members");
  });
  const showInfo = () => { $("#s-selinfo").textContent = `${SAFES.selected.size} of ${d.safes.length} Safes ticked`;
    $("#s-acts").classList.toggle("hidden", !SAFES.selected.size); };
  const applyFilter = () => {
    const f = SAFES.filter.toLowerCase(), only = !!(SAFES.nofull && noFullCount); let n = 0;
    document.querySelectorAll("#safes-table tr[data-name]").forEach(tr => { const hit = (!f || tr.dataset.name.includes(f)) && (!only || tr.dataset.nofull === "1"); tr.classList.toggle("hidden", !hit); n += hit; });
    $("#s-count").textContent = f || only ? `${n} shown` : "";
  };
  document.querySelectorAll(".s-sel").forEach(cb => cb.onchange = () => { cb.checked ? SAFES.selected.add(cb.value) : SAFES.selected.delete(cb.value); cb.closest("tr").classList.toggle("selected", cb.checked); showInfo(); });
  document.querySelectorAll(".s-sel:checked").forEach(cb => cb.closest("tr").classList.add("selected"));
  $("#s-filter").oninput = () => { SAFES.filter = $("#s-filter").value; applyFilter(); };
  if ($("#s-nofull")) $("#s-nofull").onchange = () => { SAFES.nofull = $("#s-nofull").checked; applyFilter(); };
  $("#s-tick-shown").onclick = () => { document.querySelectorAll("#safes-table tr[data-name]:not(.hidden) .s-sel").forEach(cb => { cb.checked = true; cb.onchange(); }); };
  $("#s-untick").onclick = () => { document.querySelectorAll(".s-sel:checked").forEach(cb => { cb.checked = false; cb.onchange(); }); };
  applyFilter(); showInfo();
  const send = async (body, done) => {
    try {
      const r = await api("/api/members/edit", { ...body, reason: $("#m-reason").value });
      saved("main");
      await PAGES["review-safes"]();
      okOrCleaned($("#m-msg"), r, done(r.changed));
    } catch (e) { msg($("#m-msg"), "err", e.message); }
  };
  $("#m-add").onclick = () => {
    const name = $("#m-name").value.trim();
    if (!SAFES.selected.size) return msg($("#m-msg"), "err", "Tick the Safes first.");
    if (!name) return msg($("#m-msg"), "err", "Type the member's name.");
    const role = $("#m-role").value;
    send({ action: "add", member_name: name, safes: [...SAFES.selected], search_in: $("#m-dir").value.trim(),
           member_type: $("#m-type").value, role }, n => `${name} added to ${n} Safes with the role ${role}. Only Safes with accounts to upload get members.`);
  };
  $("#m-remove").onclick = () => {
    const name = $("#m-rname").value.trim();
    if (!SAFES.selected.size) return msg($("#m-msg"), "err", "Tick the Safes first.");
    if (!name) return msg($("#m-msg"), "err", "Type the member's name.");
    if (!confirm(`Remove ${name} from ${SAFES.selected.size} Safes?`)) return;
    send({ action: "remove", member_name: name, safes: [...SAFES.selected] }, n => `${name} removed from ${n} Safes.`);
  };
  // Members list: filter, and click a member or a Safe to open its panel on the right
  const pFilter = () => {
    const f = (SAFES.pfilter || "").toLowerCase(); let n = 0;
    document.querySelectorAll(csvMode ? "#sm-table tr[data-sm-safe]" : "#people-table tr[data-person]").forEach(tr => {
      const hit = (!f || tr.dataset.name.includes(f)) && (csvMode || !SAFES.nosafe || tr.dataset.nosafe); tr.classList.toggle("hidden", !hit); n += hit; });
    $("#p-count").textContent = f || (SAFES.nosafe && !csvMode) ? `${n} shown` : "";
  };
  $("#p-filter").oninput = () => { SAFES.pfilter = $("#p-filter").value; pFilter(); };
  $("#p-nosafe").onchange = () => { SAFES.nosafe = $("#p-nosafe").checked; pFilter(); };
  pFilter();
  document.querySelectorAll("#people-table tr[data-person]").forEach(tr => tr.onclick = (e) => { e.preventDefault(); showPerson(d, d.people[tr.dataset.person]); });
  document.querySelectorAll("#sm-table tr[data-sm-safe]").forEach(tr => tr.onclick = () => showSafe(d, tr.dataset.smSafe));
  $("#s-cols-mode").onchange = () => { SAFES.mode = $("#s-cols-mode").value; PAGES["review-safes"](); };
  if (csvMode) { markCsvColumn($("#safes-table")); markCsvColumn($("#sm-table")); }
  document.querySelectorAll("[data-members-of]").forEach(a => a.onclick = (e) => { e.preventDefault(); showSafe(d, a.dataset.membersOf); });
  document.querySelectorAll("[data-undo-person]").forEach(b => b.onclick = async () => {
    try { await api("/api/members/change", { key: b.dataset.undoPerson, undo: true }); await PAGES["review-safes"](); msg($("#m-msg"), "ok", "Member change undone."); }
    catch (e) { msg($("#m-msg"), "err", e.message); }
  });
  if (SAFES.panel && SAFES.panel.kind === "safe" && d.safes.some(x => x.safe_name === SAFES.panel.id)) showSafe(d, SAFES.panel.id);
  if (SAFES.panel && SAFES.panel.kind === "person") { const p = d.people.find(x => x.key === SAFES.panel.id); if (p) showPerson(d, p); }
  document.querySelectorAll("[data-undo]").forEach(b => b.onclick = () => {
    const e = d.member_edits[b.dataset.undo];
    send({ action: "undo", pairs: [[e.safe_name, e.member_name]] }, () => `Undone: ${e.member_name} on ${e.safe_name}.`);
  });
  document.querySelectorAll("[data-safe]").forEach(a => a.onclick = (e) => { e.preventDefault(); REVIEW.view = "all"; REVIEW.filters = { safe: a.dataset.safe }; REVIEW.page = 0; go("review"); });
  document.querySelectorAll("[data-undo-safe]").forEach(b => b.onclick = async () => {
    const o = d.safe_overrides[b.dataset.undoSafe];
    const now = safeNowNamed(d, o);
    try {
      await api("/api/safes/change", { key: o.rule_name || o.key, current: now ? now.safe_name : "", undo: true });
      await PAGES["review-safes"](); msg($("#s-msg"), "ok", "Safe change undone: back to what the rules give.");
    } catch (e) { msg($("#s-msg"), "err", e.message); }
  });
};

/* Your direct changes to whole Safes (name and settings), listed above the Safes table with Undo. */
const SAFE_FIELD_LABELS = { new_name: "name", description: "description", location: "location", managingCPM: "CPM",
  numberOfVersionsRetention: "keeps versions", numberOfDaysRetention: "keeps days", olacEnabled: "OLAC", autoPurgeEnabled: "auto purge" };
function safeNowNamed(d, o) {
  return d.safes.find(s => (s.rule_names || "").split(" | ").some(n => n.toLowerCase() === o.key));
}
function safeEditsHtml(d) {
  const list = d.safe_overrides || [];
  if (!list.length) return '<div id="s-msg"></div>';
  return `<details class="card fold" id="safe-edits"><summary>Your Safe changes (${list.length})</summary>
    <p class="muted small">Safes you renamed or whose settings you changed directly. They win over the rules and are kept when the rules or exports change. Undo puts back what the rules give.</p>
    <div class="tablewrap" style="max-height:30vh"><table class="small"><tr><th>Safe from the rules</th><th>Now</th><th>Changes</th><th>When / who</th><th>Reason</th><th></th></tr>
    ${list.map((o, i) => { const now = safeNowNamed(d, o); o.rule_name = now ? (now.rule_names.split(" | ").find(n => n.toLowerCase() === o.key) || o.key) : o.key;
      return `<tr><td>${esc(o.rule_name)}</td><td>${now ? `<a href="#" data-members-of="${esc(now.safe_name)}">${esc(now.safe_name)}</a>` : '<span class="muted" title="The rules no longer give a Safe with this name, so this change does nothing now">(no longer in the plan)</span>'}</td>
        <td>${Object.keys(SAFE_FIELD_LABELS).filter(k => o[k] !== undefined && o[k] !== "").map(k => `${SAFE_FIELD_LABELS[k]}: <b>${esc(k === "olacEnabled" || k === "autoPurgeEnabled" ? (o[k] ? "Yes" : "No") : o[k])}</b>`).join("<br>")}</td>
        <td>${esc(o.changed_utc)}<br>${esc(o.changed_by)}</td><td>${esc(o.reason || "")}</td>
        <td><button class="btn small" data-undo-safe="${i}">Undo</button></td></tr>`; }).join("")}</table></div><div id="s-msg"></div></details>`;
}

/* Side panels on the Safes & Safe members page: one Safe with its members, one member with its Safes. */
const roleSelect = (d, value, attrs) => `<select ${attrs}>${d.roles.concat(d.roles.includes(value) || !value ? [] : [value])
  .map(r => `<option ${r === value ? "selected" : ""}>${esc(r)}</option>`).join("")}</select>`;
async function memberEdit(body, again) {
  try {
    const r = await api("/api/members/edit", body);
    saved("panel");
    await PAGES["review-safes"]();
    again();
    okOrCleaned($("#panel-msg"), r, "Saved. Rules re-applied.");
  } catch (e) { msg($("#panel-msg") || $("#m-msg"), "err", e.message); }
}
function showSafe(d, safe) {
  if (!leaveOk("panel")) return;
  SAFES.panel = { kind: "safe", id: safe };
  const s = d.safes.find(x => x.safe_name === safe) || {};
  const people = d.people.filter(p => p.safes.some(x => x.safe_name === safe));
  document.querySelectorAll("#safes-table tr[data-name]").forEach(tr => tr.classList.toggle("current", tr.dataset.name === safe.toLowerCase()));
  $("#drawer").innerHTML = `<div class="row"><h3 style="margin:0;flex:1">Safe ${esc(safe)}</h3><button class="btn" id="panel-close">Close</button></div>
    <p class="muted small">${s.accounts_to_upload ?? 0} accounts to upload${s.description ? " · " + esc(s.description) : ""}.
      Named by ${esc(howChosen(s.mapping_sources))}${s.valid_safe_name !== "TRUE" ? `; the rules proposed <b>${esc(s.proposed_names)}</b>, changed because ${esc(s.issues)}` : s.issues ? `; ⚠ ${esc(s.issues)}` : ""}.</p>
    ${safeSettingsForm(s)}
    <h4>Members (${people.length})</h4>
    <p class="muted small">Change a member's role here, or click a member to see all its Safes.</p>
    ${people.length ? `<table class="small"><tr><th>Member</th><th>Type</th><th>Role</th><th></th></tr>
      ${people.map((p, i) => { const m = p.safes.find(x => x.safe_name === safe);
        return `<tr><td><a href="#" data-open-person="${esc(p.key)}">${esc(p.member_name)}</a><div class="muted">${esc(p.search_in || "searchIn: all")}</div></td><td>${esc(p.member_type)}</td>
          <td>${roleSelect(d, m.role, `class="pr-role" data-key="${esc(p.source_member || p.member_name)}" title="Role this member gets on this Safe"`)}</td>
          <td><button class="btn small danger" data-remove="${esc(p.source_member || p.member_name)}" title="Take this member off this Safe">Remove</button></td></tr>`; }).join("")}</table>`
      : '<p class="muted">No members. Tick this Safe in the list to add one.</p>'}
    <p><a href="#" id="panel-accounts">Show this Safe's accounts ›</a></p><div id="panel-msg"></div>`;
  $("#drawer").classList.remove("hidden");
  $("#panel-close").onclick = () => { if (leaveOk("panel")) { SAFES.panel = null; closeDrawer(); } };
  $("#panel-accounts").onclick = (e) => { e.preventDefault(); REVIEW.view = "all"; REVIEW.filters = { safe }; REVIEW.page = 0; go("review"); };
  const again = () => showSafe(SAFES.data, safe);
  wireSafeSettings(s);
  document.querySelectorAll("#drawer [data-open-person]").forEach(a => a.onclick = (e) => { e.preventDefault(); showPerson(d, d.people.find(p => p.key === a.dataset.openPerson)); });
  document.querySelectorAll("#drawer .pr-role").forEach(sel => sel.onchange = () =>
    memberEdit({ action: "add", pairs: [[safe, sel.dataset.key]], role: sel.value }, again));
  document.querySelectorAll("#drawer [data-remove]").forEach(b => b.onclick = () => {
    if (confirm(`Remove this member from ${safe}?`)) memberEdit({ action: "remove", pairs: [[safe, b.dataset.remove]] }, again); });
}
// One Safe's own name and settings. Empty = what the rules give (shown greyed as the placeholder).
// When other Safes were renamed into this one, the panel edits this Safe's own change, not theirs.
function safeRuleName(s) {
  const names = (s.rule_names || s.safe_name).split(" | ");
  const ov = s.override_json ? JSON.parse(s.override_json) : null;
  return names.find(n => n.toLowerCase() === s.safe_name.toLowerCase()) || (ov && names.find(n => n.toLowerCase() === ov.key)) || names[0];
}
// The other Safes (as the rules name them) that you renamed into this one.
const mergedInto = (s) => (s.rule_names || s.safe_name).split(" | ").filter(n => n && n !== safeRuleName(s));
function safeSettingsForm(s) {
  const ov = s.override_json ? JSON.parse(s.override_json) : {};
  const rules = s.rules_json ? JSON.parse(s.rules_json) : {};
  const ruleName = safeRuleName(s);
  const yn = (v) => v === true || String(v).toLowerCase() === "true" ? "Yes" : "No";
  const keepRule = String(rules.numberOfVersionsRetention ?? "").trim() ? `${rules.numberOfVersionsRetention} versions`
    : String(rules.numberOfDaysRetention ?? "").trim() ? `${rules.numberOfDaysRetention} days` : "Privilege Cloud default";
  const kind = ov.numberOfVersionsRetention ? "versions" : ov.numberOfDaysRetention ? "days" : "";
  const tri = (id, key, tip) => `<select id="${id}" title="${esc(tip)}"><option value="">As the rules say (${yn(rules[key])})</option>
    <option value="true" ${ov[key] === true ? "selected" : ""}>Yes</option><option value="false" ${ov[key] === false ? "selected" : ""}>No</option></select>`;
  const merged = mergedInto(s);
  return `<details class="edit-block" ${s.override_json || merged.length ? "open" : ""}><summary><span class="arrow">▸</span>
      <span class="edit-sum"><b>Name and settings</b> ${s.override_json ? '<span class="pill REVIEW">changed by you</span>' : '<span class="muted small">as the rules give them</span>'}
        ${merged.length ? `<span class="pill REVIEW">holds ${merged.length} renamed ${merged.length === 1 ? "Safe" : "Safes"}</span>` : ""}</span>
      <span class="edit-btn"><span class="o">Edit</span><span class="c">Done</span></span></summary>
    <div class="form-grid">
      <p class="muted small">Change this one Safe directly. What you set here wins over the rules in step 2 and is kept when the rules or exports change.
        Leave a field empty to keep what the rules give (shown in grey).</p>
      <label>Safe name <input type="text" id="sv-name" value="${esc(s.safe_name)}" placeholder="${esc(ruleName)}" data-check="safe" maxlength="28"
        title="The Safe's name in Privilege Cloud: at most 28 characters, none of \\ / : * ? &quot; < > | . Its accounts and members move with it. The rules named it ${esc(ruleName)}. Typing another existing Safe's name puts both into one Safe, with that Safe's settings."></label>
      <label>Description <input type="text" id="sv-desc" value="${esc(ov.description || "")}" placeholder="${esc(rules.description || "(none)")}" maxlength="100"
        title="Free text shown in Privilege Cloud, at most 100 characters. {folder} is replaced with the Safe's first source folder."></label>
      <label>Location <input type="text" id="sv-loc" value="${esc(ov.location || "")}" placeholder="${esc(rules.location || "(root)")}"
        title="Vault location (folder) for the Safe, for example \\Windows. Empty puts it at the root."></label>
      <label>Managing CPM <input type="text" id="sv-cpm" value="${esc(ov.managingCPM || "")}" placeholder="${esc(rules.managingCPM || "(no CPM: passwords are not managed)")}" maxlength="20"
        title="Name of the CPM that manages this Safe's passwords, for example PasswordManager. Empty in the rules means no automatic password management."></label>
      <label>Keeps <span class="row" style="gap:6px;flex-wrap:nowrap">
        <select id="sv-keep-kind" title="How long the Safe keeps old passwords: a number of versions or a number of days. Privilege Cloud uses one or the other."><option value="">As the rules say (${esc(keepRule)})</option>
          <option value="versions" ${kind === "versions" ? "selected" : ""}>versions</option><option value="days" ${kind === "days" ? "selected" : ""}>days</option></select>
        <input type="text" id="sv-keep" size="5" value="${esc(ov.numberOfVersionsRetention || ov.numberOfDaysRetention || "")}" placeholder="7"
          title="Whole number: versions 1-999 or days 1-3650." style="width:80px"></span></label>
      <label>Object level access control (OLAC) ${tri("sv-olac", "olacEnabled", "OLAC lets you give access to single accounts inside the Safe. It can't be turned off again once on.")}</label>
      <label>Auto purge ${tri("sv-purge", "autoPurgeEnabled", "Delete expired password versions automatically.")}</label>
      <label>Reason (optional, kept in the log) <input type="text" id="sv-reason"></label>
      ${merged.length ? `<div class="msg warn small">This Safe also holds ${merged.map(n => `<b>${esc(n)}</b>
        <button class="btn small" data-split="${esc(n)}" title="Undo the rename of ${esc(n)}: its accounts and the member changes that came with it go back to a Safe of their own">Split back out</button>`).join(", ")}
        (renamed into it by you). This Safe's own settings apply to all of them.</div>` : ""}
      <div class="row" style="margin-top:8px"><button class="btn primary" id="sv-save">Save this Safe</button>
        ${s.override_json ? '<button class="btn" id="sv-undo" title="Forget your changes to this Safe and use what the rules give">Undo my changes</button>' : ""}</div>
      <div id="sv-msg"></div>
    </div></details>`;
}
function wireSafeSettings(s) {
  const key = safeRuleName(s);
  const done = async (r, text) => {
    saved("panel");
    await PAGES["review-safes"]();
    const now = SAFES.data.safes.find(x => x.safe_name.toLowerCase() === String(r.safe_name).toLowerCase());
    if (now) { showSafe(SAFES.data, now.safe_name); okOrCleaned($("#sv-msg"), r, text); }
  };
  $("#sv-save").onclick = async () => {
    const name = $("#sv-name").value.trim();
    const settings = { new_name: name, description: $("#sv-desc").value, location: $("#sv-loc").value, managingCPM: $("#sv-cpm").value,
      retention_kind: $("#sv-keep-kind").value, retention_value: $("#sv-keep").value, olacEnabled: $("#sv-olac").value, autoPurgeEnabled: $("#sv-purge").value };
    if (settings.retention_kind && !settings.retention_value.trim()) return msg($("#sv-msg"), "err", "Type how many versions or days the Safe keeps.");
    if ($("#sv-olac").value === "true" && !confirm("OLAC can't be turned off again in Privilege Cloud once the Safe is created with it. Turn it on for this Safe?")) return;
    try {
      const r = await api("/api/safes/change", { key, current: s.safe_name, settings, reason: $("#sv-reason").value });
      await done(r, "Saved. Rules re-applied; your values win for this Safe.");
    } catch (e) { msg($("#sv-msg"), "err", e.message); }
  };
  document.querySelectorAll("#drawer [data-split]").forEach(b => b.onclick = async () => {
    if (!confirm(`Split ${b.dataset.split} back out of ${s.safe_name}? Your rename of ${b.dataset.split} and its other changes are undone.`)) return;
    try {
      await api("/api/safes/change", { key: b.dataset.split, current: s.safe_name, undo: true });
      await done({ safe_name: s.safe_name }, `${b.dataset.split} is a Safe of its own again.`);
    } catch (e) { msg($("#sv-msg"), "err", e.message); }
  });
  if ($("#sv-undo")) $("#sv-undo").onclick = async () => {
    try { const r = await api("/api/safes/change", { key, current: s.safe_name, undo: true }); await done(r, "Back to what the rules give."); }
    catch (e) { msg($("#sv-msg"), "err", e.message); }
  };
}
function showPerson(d, p) {
  if (!p || !leaveOk("panel")) return;
  SAFES.panel = { kind: "person", id: p.key };
  document.querySelectorAll("#safes-table tr.current").forEach(tr => tr.classList.remove("current"));
  const others = d.safes.map(s => s.safe_name).filter(n => !p.safes.some(x => x.safe_name === n));
  $("#drawer").innerHTML = `<div class="row"><h3 style="margin:0;flex:1">${esc(p.member_name)}</h3><button class="btn" id="panel-close">Close</button></div>
    <p class="muted small">${p.source_member && p.source_member !== p.member_name ? `In the export as <b>${esc(p.source_member)}</b>. ` : ""}Named by ${/^(default|\(not matched)/.test(p.directory_source || "default") ? "the default member rule" : "the member source " + esc(p.directory_source)}.
      ${p.export_accounts ? `Has access to ${p.export_accounts} accounts in the export.` : ""}</p>
    <h4>How Privilege Cloud finds this member</h4>
    <div class="bulk"><div>
      <label>memberName <input type="text" id="pe-name" value="${esc(p.member_name)}" data-check="member" title="The member's name exactly as Privilege Cloud will search for it, e.g. PAM-Auditors or jdoe@corp.example.com."></label>
      <div class="row"><label style="flex:1">memberType <select id="pe-type" title="User = one person's account; Group = a directory or Privilege Cloud group; Role = an Identity role.">${MEMBER_TYPES.map(t => `<option ${t === p.member_type ? "selected" : ""}>${t}</option>`).join("")}</select></label>
        <label style="flex:2">searchIn (optional) <input type="text" id="pe-dir" list="dl-dirs" value="${esc(p.search_in || "")}" placeholder="empty = all directories"
          title="Leave empty so Privilege Cloud searches every directory. Fill it only if the name exists in more than one directory: the directory's ID (GUID) from Identity, or Vault."></label></div>
      <label>Reason (optional) <input type="text" id="pe-reason" placeholder="kept in the activity log"></label>
      <div class="row"><button class="btn primary" id="pe-save">Save for every Safe</button>${p.edited ? '<button class="btn" id="pe-undo">Undo my changes</button>' : ""}</div>
      <p class="muted small">Your change replaces what the directory source rules give, on every Safe, and is kept when rules or exports change.</p></div></div>
    <h4>Safes (${p.safes.length})</h4>
    ${p.safes.length ? `<table class="small"><tr><th>Safe</th><th>Role</th><th>In the export</th><th></th></tr>
      ${p.safes.map(x => `<tr><td><a href="#" data-open-safe="${esc(x.safe_name)}">${esc(x.safe_name)}</a></td>
        <td>${roleSelect(d, x.role, `class="ps-role" data-safe="${esc(x.safe_name)}" title="Role this member gets on this Safe"`)}</td>
        <td class="small">${esc(x.source_permission || "")}</td>
        <td><button class="btn small danger" data-remove-from="${esc(x.safe_name)}" title="Take this member off this Safe">Remove</button></td></tr>`).join("")}</table>`
      : `<p class="muted">On no Safe. ${p.export_accounts ? "Its accounts in the export are not being uploaded (left out, or errors), or another rule removed it." : ""}</p>`}
    ${others.length ? `<h4>Add to a Safe</h4><div class="row"><select id="pa-safe" title="Safe to add this member to">${others.map(n => `<option>${esc(n)}</option>`).join("")}</select>
      ${roleSelect(d, d.roles[0], 'id="pa-role" title="Role on that Safe"')}<button class="btn" id="pa-add">Add</button></div>` : ""}
    <div id="panel-msg"></div>`;
  $("#drawer").classList.remove("hidden");
  $("#panel-close").onclick = () => { if (leaveOk("panel")) { SAFES.panel = null; closeDrawer(); } };
  const again = () => { const q = SAFES.data.people.find(x => x.key === p.key); if (q) showPerson(SAFES.data, q); };
  $("#pe-save").onclick = async () => {
    const name = $("#pe-name").value.trim();
    if (!name) return msg($("#panel-msg"), "err", "The member name can't be empty.");
    try {
      const r = await api("/api/members/change", { key: p.key, member_name: name, member_type: $("#pe-type").value, search_in: $("#pe-dir").value.trim(), reason: $("#pe-reason").value });
      saved("panel");
      await PAGES["review-safes"](); again(); okOrCleaned($("#panel-msg"), r, "Saved for every Safe. Rules re-applied.");
    } catch (e) { msg($("#panel-msg"), "err", e.message); }
  };
  if ($("#pe-undo")) $("#pe-undo").onclick = async () => {
    try { await api("/api/members/change", { key: p.key, undo: true }); saved("panel"); await PAGES["review-safes"](); again(); msg($("#panel-msg"), "ok", "Back to what the rules give."); }
    catch (e) { msg($("#panel-msg"), "err", e.message); }
  };
  document.querySelectorAll("#drawer [data-open-safe]").forEach(a => a.onclick = (e) => { e.preventDefault(); showSafe(d, a.dataset.openSafe); });
  document.querySelectorAll("#drawer .ps-role").forEach(sel => sel.onchange = () =>
    memberEdit({ action: "add", pairs: [[sel.dataset.safe, p.source_member || p.member_name]], role: sel.value }, again));
  document.querySelectorAll("#drawer [data-remove-from]").forEach(b => b.onclick = () => {
    if (confirm(`Remove ${p.member_name} from ${b.dataset.removeFrom}?`)) memberEdit({ action: "remove", pairs: [[b.dataset.removeFrom, p.source_member || p.member_name]] }, again); });
  if ($("#pa-add")) $("#pa-add").onclick = () => memberEdit({ action: "add", pairs: [[$("#pa-safe").value, p.member_name]], role: $("#pa-role").value,
    member_type: p.member_type, search_in: p.search_in || "" }, again);
}

/* ---------------- 4. Output ---------------- */
PAGES.output = async () => {
  await refresh();
  if (!STATE.has_db) return msg($("#main"), "warn", "Load some exports first (step 1).");
  const facets = (await api("/api/accounts", { view: "all", page: 0 })).facets;
  const secretsOk = STATE.protector !== "none";
  $("#main").innerHTML = `<h2>4. Create upload files</h2>
    <p class="lead" title="Also written: the review files (no secrets), FileCategories.csv (every account property column in Accounts.csv) and PlatformProperties.csv (which of them each platform uses).">Writes <code>Safes.csv</code>, <code>SafeMembers.csv</code> and <code>Accounts.csv</code> for the Privilege Cloud API, plus review files and platform lists. Accounts with errors or left out by you are always left out.</p>
    ${statusNotes()}
    <div class="card"><h3>Ready check <span class="muted small">(click a number to open that list)</span></h3>${readyTiles()}</div>
    <div class="card">
      <h3>What to include</h3>
      <p><label class="inline"><input type="radio" name="scope" value="all" checked> Everything (${STATE.to_upload} accounts)</label></p>
      <p><label class="inline"><input type="radio" name="scope" value="filter"> Only a wave:</label>
        <select id="o-safe"><option value="">any Safe</option>${facets.safe.map(v => `<option>${esc(v)}</option>`).join("")}</select>
        <select id="o-platform"><option value="">any platform</option>${facets.platform.map(v => `<option>${esc(v)}</option>`).join("")}</select>
        <select id="o-source"><option value="">any source</option>${facets.source.map(v => `<option>${esc(v)}</option>`).join("")}</select></p>
      <h3>Secrets</h3>
      <p><label class="inline"><input type="radio" name="sec" value="0" checked> <b>Dry run</b>: leave the secret column empty (safe to share and check)</label></p>
      <p><label class="inline"><input type="radio" name="sec" value="1" ${secretsOk ? "" : "disabled"}> <b>Upload-ready</b>: decrypt the secrets into Accounts.csv</label>
        ${secretsOk ? "" : '<span class="muted small">(this database holds no secrets)</span>'}</p>
      <div id="sec-confirm" class="msg warn hidden">Accounts.csv will hold <b>plaintext secrets</b>. Keep it on this machine's encrypted disk, don't open it in Excel, and delete it after the upload (button below).<br>
        Type <b>INCLUDE SECRETS</b> to confirm: <input type="text" id="confirm" size="18"></div>
      <h3>Folder name</h3>
      <p class="row"><input type="text" id="o-name" size="28"> <label class="inline"><input type="checkbox" id="o-replace"> Replace if it exists</label></p>
      <button class="btn primary" id="extract">Create files</button><div id="out-msg"></div>
    </div>
    <div class="card"><h3>Earlier outputs in <code>${esc(STATE.output)}</code></h3>
      ${STATE.outputs.length ? `<table><tr><th>Name</th><th>Created</th><th>Accounts</th><th>Secrets</th><th></th></tr>
        ${STATE.outputs.map(o => `<tr><td>${esc(o.name)}</td><td>${esc(o.created)}</td><td>${o.counts.accounts ?? ""}</td>
          <td>${o.secrets && o.has_upload ? '<span class="pill ERROR">plaintext</span>' : o.secrets ? "deleted" : "none"}</td>
          <td>${o.has_upload ? `<button class="btn danger" data-del="${esc(o.name)}">Securely delete upload files</button>` : ""}</td></tr>`).join("")}</table>` : '<p class="muted">None yet.</p>'}</div>`;
  if (LAST_OUT) { $("#out-msg").innerHTML = LAST_OUT; LAST_OUT = ""; }
  wireTiles();
  // A ready-made folder name (date, what is in it, dry run or not), until you type your own.
  let typed = false;
  const autoName = () => {
    if (typed) return;
    const day = new Date().toISOString().slice(0, 10);
    const wave = document.querySelector("input[name=scope]:checked").value === "filter"
      ? [$("#o-safe").value, $("#o-platform").value, $("#o-source").value].filter(Boolean).join("-").replace(/[^A-Za-z0-9_-]+/g, "-") || "wave" : "all";
    const base = `${day}-${wave}-${document.querySelector("input[name=sec]:checked").value === "1" ? "upload" : "dryrun"}`;
    const taken = new Set(STATE.outputs.map(o => o.name));
    let name = base, n = 1; while (taken.has(name)) name = `${base}-${++n}`;
    $("#o-name").value = name;
  };
  $("#o-name").addEventListener("input", () => { typed = !!$("#o-name").value.trim(); });
  document.querySelectorAll("input[name=scope], input[name=sec], #o-safe, #o-platform, #o-source").forEach(el => el.addEventListener("change", () => setTimeout(autoName, 0)));
  autoName();
  document.querySelectorAll("input[name=sec]").forEach(r => r.onchange = () => $("#sec-confirm").classList.toggle("hidden", r.value !== "1" || !r.checked));
  ["safe", "platform", "source"].forEach(k => $(`#o-${k}`).onchange = () => { document.querySelector("input[name=scope][value=filter]").checked = true; });
  document.querySelectorAll("[data-del]").forEach(b => b.onclick = async () => {
    if (!confirm(`Overwrite and delete the upload files of ${b.dataset.del}? The review files and manifest are kept.`)) return;
    try { await api("/api/output/delete", { name: b.dataset.del, what: "upload" }); go("output"); } catch (e) { msg($("#out-msg"), "err", e.message); }
  });
  $("#extract").onclick = async () => {
    const scope = document.querySelector("input[name=scope]:checked").value;
    const include = document.querySelector("input[name=sec]:checked").value === "1";
    const filters = { safe: $("#o-safe").value, platform: $("#o-platform").value, source: $("#o-source").value };
    try {
      const r = await api("/api/extract", { scope, view: "all", filters, include_secrets: include, confirm: $("#confirm").value,
                                            name: $("#o-name").value, replace: $("#o-replace").checked });
      LAST_OUT = `<div class="msg ok">Created <b>${esc(r.name)}</b>: ${r.counts.safes} Safes, ${r.counts.members} members, ${r.counts.accounts} accounts${include ? " (with secrets)" : " (dry run)"}.<br>
        Folder: <code>${esc(r.path)}</code><br>${r.files.map(esc).join(" · ")}</div>`;
      go("output");
    } catch (e) { msg($("#out-msg"), "err", e.message); }
  };
};

/* ---------------- Activity ---------------- */
// One log entry as a sentence instead of raw JSON with full paths.
function describeAudit(action, detail) {
  let d = {}; try { d = JSON.parse(detail || "{}"); } catch (e) { return detail || ""; }
  const file = (p) => String(p || "").split(/[\\/]/).pop();
  const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;
  const why = d.reason ? ` (reason: ${d.reason})` : "";
  const vals = (o) => Object.entries(o || {}).map(([k, v]) => `${({ migrate: "migrate", target_safe: "Safe", platform_id: "platform", account_name: "name" })[k] || k} ${v === "" ? "back to the rules" : "→ " + v}`).join(", ");
  switch (action) {
    case "ingest": return `Loaded ${file(d.path)}: ${n(d.records, "record", "records")} as ${SOURCE_NAMES[d.source] || d.source}${d.replaced ? `, ${d.replaced} replaced` : ""}${d.sanitized ? `, ${d.sanitized} with forbidden characters removed` : ""}${d.permissions ? `; permissions from ${String(d.permissions).split(" | ").map(file).join(", ")}` : ""}.`;
    case "map": return `Rules applied to ${n(d.accounts, "account", "accounts")}.`;
    case "set": return `Changed ${n(d.records, "account", "accounts")}: ${vals(d.values)}${why}.`;
    case "approve": return `Approved ${n(d.records, "account", "accounts")} that needed a look${why}.`;
    case "unapprove": return `Took the approval back from ${n(d.records, "account", "accounts")}${why}.`;
    case "approval_cleared": return `${n(d.records, "approval", "approvals")} dropped because the account changed after it was approved.`;
    case "extract": return `Created ${file(d.output)}: ${n(d.accounts, "account", "accounts")}, ${d.include_secrets ? "with secrets" : "dry run"}${d.where && d.where !== "everything" ? " (a wave)" : ""}.`;
    case "member_add": return `Added ${d.member} to ${n((d.safes || []).length, "Safe", "Safes")} as ${d.role}${why}.`;
    case "member_remove": return `Removed ${d.member} from ${n((d.safes || []).length, "Safe", "Safes")}${why}.`;
    case "member_undo": return `Undid the changes to member ${d.member}.`;
    case "member_change": return `Member ${d.member} now ${[d.member_name && "named " + d.member_name, d.member_type, d.search_in ? "searchIn " + d.search_in : ""].filter(Boolean).join(", ")}${why}.`;
    case "safe_change": return `Changed Safe ${d.safe}${why}.`;
    case "safe_undo": return `Undid the changes to Safe ${d.safe}.`;
    case "sign_in": return `Signed in.`;
    case "sign_in_failed": return `Wrong password (${n(d.failures, "failure", "failures")} in a row).`;
    case "lock": return d.reason === "idle" ? "Locked after inactivity." : "Locked.";
    case "end_session": return `Session ended; database ${d.database}.`;
    case "export_log": return `Exported the ${d.what === "edits" ? "account changes" : "activity log"} (${n(d.rows, "row", "rows")}).`;
    default: return Object.entries(d).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(", ");
  }
}
const ACTION_NAMES = { ingest: "Load", map: "Rules applied", set: "Account change", approve: "Approved", unapprove: "Approval removed", approval_cleared: "Approval dropped", extract: "Upload files", member_add: "Member added",
  member_remove: "Member removed", member_undo: "Member undo", member_change: "Member change", safe_change: "Safe change", safe_undo: "Safe undo",
  sign_in: "Sign-in", sign_in_failed: "Failed sign-in", lock: "Lock", end_session: "End session", export_log: "Export", refused_connection: "Refused connection" };
PAGES.activity = async () => {
  if (!STATE.has_db) await refresh();
  if (!STATE.has_db) return msg($("#main"), "warn", "Nothing has happened yet.");
  const d = await api("/api/audit");
  const sm = d.summary;
  $("#main").innerHTML = `<h2>Activity log</h2><p class="lead">Everything done to this database. The tables show the latest entries; the exports hold every entry.</p>
    <div class="stats">
      <div class="stat"><b>${sm.entries}</b><span>log entries since ${esc((sm.first || "").slice(0, 16).replace("T", " "))}</span></div>
      <div class="stat"><b>${sm.by_user.length}</b><span>${sm.by_user.length === 1 ? "person" : "people"}: ${sm.by_user.map(u => esc(u.user)).join(", ")}</span></div>
      <div class="stat"><b>${sm.edits}</b><span>changes to ${sm.edited_accounts} accounts</span></div>
      <div class="stat"><b>${(sm.by_action.find(a => a.action === "extract") || { count: 0 }).count}</b><span>upload files created</span></div>
    </div>
    <div class="row" style="margin:12px 0"><a class="btn" href="#" data-export="audit">Export the activity log (CSV)</a>
      <a class="btn" href="#" data-export="edits">Export the account changes (CSV)</a>
      <span class="muted small">Exporting is itself logged.</span></div>
    <details class="card fold"><summary>Summary by action and person</summary><div class="row" style="align-items:flex-start;gap:16px">
      <div style="flex:1;min-width:280px"><h3>By action</h3><table class="small"><tr><th>Action</th><th>Times</th><th>Last (UTC)</th></tr>
        ${sm.by_action.map(a => `<tr><td>${esc(ACTION_NAMES[a.action] || a.action)}</td><td>${a.count}</td><td>${esc(a.last)}</td></tr>`).join("")}</table></div>
      <div style="flex:1;min-width:280px"><h3>By person</h3><table class="small"><tr><th>Who</th><th>Entries</th><th>First</th><th>Last</th></tr>
        ${sm.by_user.map(u => `<tr><td>${esc(u.user)}</td><td>${u.count}</td><td>${esc(u.first)}</td><td>${esc(u.last)}</td></tr>`).join("")}</table>
        ${sm.edits_by_field.length ? `<h3 style="margin-top:12px">Changes by field</h3><table class="small"><tr><th>Field</th><th>Changes</th></tr>${sm.edits_by_field.map(f => `<tr><td>${esc(f.field)}</td><td>${f.count}</td></tr>`).join("")}</table>` : ""}</div></div></details>
    <div class="card"><h3>Latest entries</h3><div class="tablewrap"><table><tr><th>When (UTC)</th><th>Who</th><th>What</th><th>Details</th></tr>
      ${d.audit.map(a => `<tr><td class="small nowrap">${esc(String(a.ts || "").slice(0, 19).replace("T", " "))}</td><td>${esc(a.user)}</td><td class="nowrap">${esc(ACTION_NAMES[a.action] || a.action)}</td><td title="${esc(a.detail)}">${esc(describeAudit(a.action, a.detail))}</td></tr>`).join("")}</table></div></div>
    <div class="card"><h3>Your changes to accounts</h3><div class="tablewrap"><table><tr><th>Account</th><th>Field</th><th>Value</th><th>When</th><th>Who</th><th>Reason</th></tr>
      ${d.edits.map(e => `<tr><td class="small">${esc(e.record_id)}</td><td>${esc(e.field)}</td><td>${esc(e.value)}</td><td class="small">${esc(e.changed_utc)}</td><td>${esc(e.changed_by)}</td><td>${esc(e.reason)}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">None</td></tr>'}</table></div></div>`;
  // Fetched by the page itself, then saved: works the same with a self-signed certificate.
  document.querySelectorAll("[data-export]").forEach(a => a.onclick = async (e) => {
    e.preventDefault();
    const r = await fetch(`/api/export/${a.dataset.export}.csv`, { headers: { "X-IMW": "1" } });
    if (r.status === 423) return showLogin("Locked after inactivity. Sign in again to continue.");
    if (!r.ok) return alert("Export failed: " + r.statusText);
    const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const url = URL.createObjectURL(await r.blob());
    const link = Object.assign(document.createElement("a"), { href: url, download: name ? name[1] : a.dataset.export + ".csv" });
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  });
};

// Links and buttons in generated markup use data-* attributes instead of inline onclick
// handlers, so the page's Content-Security-Policy can refuse every inline script.
document.addEventListener("click", (e) => {
  const g = e.target.closest("[data-go]");
  if (g) {
    e.preventDefault();
    if (g.dataset.reviewView) { REVIEW.view = g.dataset.reviewView; REVIEW.filters = {}; REVIEW.page = 0; }
    go(g.dataset.go);
    return;
  }
  const del = e.target.closest("button.row-del");
  if (del) { const t = del.closest("table"); del.closest("tr").remove(); updateBlockCount(t.id); return; }
  if (e.target.closest("[data-close-drawer]") && leaveOk("panel")) closeDrawer();
});

/* ---------------- Floating bar height and the "more below" arrow ---------------- */
function updateFloat() {
  const fb = document.querySelector("#main .floatbar");
  const h = fb ? fb.offsetHeight : 0;
  document.documentElement.style.setProperty("--fb-h", h + "px");
  const dock = document.querySelector("#main .pv-dock");
  document.documentElement.style.setProperty("--fb-off", h + (dock ? dock.offsetHeight + 8 : 0) + "px");
  // More below = some of the page's own content ends under the bottom edge (or under the floating bar).
  let bottom = 0;
  for (const el of $("#main").children) if (!el.classList.contains("floatbar") && !el.classList.contains("pv-dock")) bottom = Math.max(bottom, el.getBoundingClientRect().bottom);
  $("#more-below").classList.toggle("hidden", LOCKED || bottom <= window.innerHeight - h + 4);
}
let FLOAT_T;
const queueFloat = () => { clearTimeout(FLOAT_T); FLOAT_T = setTimeout(updateFloat, 30); };
window.addEventListener("scroll", queueFloat, { passive: true });
window.addEventListener("resize", queueFloat);
new ResizeObserver(queueFloat).observe(document.body);
new MutationObserver(queueFloat).observe($("#main"), { childList: true, subtree: true });
document.addEventListener("toggle", queueFloat, true);   // folding blocks open or shut
$("#more-below").onclick = () => window.scrollBy({ top: Math.round(window.innerHeight * 0.75), behavior: "smooth" });

start();
