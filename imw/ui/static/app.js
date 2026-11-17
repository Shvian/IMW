"use strict";
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let STATE = {}, PAGE = "overview", LAST_OUT = "", LAST_LOAD = "";
const REVIEW = { view: "review", filters: {}, page: 0, sort: "target_safe", desc: false, selected: new Set(), data: null };

// Bumped on every page change. A page fetch that started before the latest page change is stale:
// it is dropped, so a slow page can't draw over the page you went to after it.
let NAV_SEQ = 0;
async function api(path, body) {
  const seq = NAV_SEQ;
  const opts = body === undefined ? { headers: { "X-IMW": "1" } }
    : { method: "POST", headers: { "Content-Type": "application/json", "X-IMW": "1" }, body: JSON.stringify(body) };
  $("#busy").classList.toggle("hidden", body === undefined || path === "/api/ping");
  try {
    const r = await fetch(path, opts);
    const data = await r.json().catch(() => ({ error: "Unexpected response" }));
    if (r.status === 401) { document.body.innerHTML = "<p style='padding:30px'>Session ended. Restart the Workbench to get a new link.</p>"; throw new Error("session"); }
    if (r.status === 423) { showLogin("Locked after inactivity. Sign in again to continue."); throw new Error("session"); }
    if (!r.ok) throw new Error(data.error || r.statusText);
    if (body === undefined && seq !== NAV_SEQ) throw new Error("stale");
    return data;
  } finally { $("#busy").classList.add("hidden"); }
}
function msg(el, kind, text) { if (!el || text === "stale") return; el.innerHTML = `<div class="msg ${kind}">${esc(text)}</div>`; }
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
  "pv-filter", "pv-changed", "cols-mode", "s-cols-mode", "d-show", "d-group", "d-safe", "d-reason", "d-selall"]);
function trackDirty(e) {
  const el = e.target;
  if (!el.matches || !el.matches("input, select, textarea") || el.type === "search" || el.name === "sec" || el.name === "scope") return;
  if (NOT_A_CHANGE.has(el.id) || ["s-sel", "sel", "m-sel", "pick", "perm", "d-sel", "d-dec"].some(c => el.classList.contains(c))) return;
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
  const decide = scope !== "panel" && DECIDE.pending.size > 0;   // user access decisions not saved yet
  const dirty = scope === "panel" ? DIRTY.panel : DIRTY.main || DIRTY.panel || decide;
  if (!dirty) return true;
  const where = scope === "panel" || !(DIRTY.main || decide) ? "in this panel" : "on this page";
  if (!confirm(`You have changes ${where} that are not saved yet.\n\nLeave without saving them? Click Cancel to go back and save.`)) return false;
  DIRTY.panel = false; if (scope !== "panel") { DIRTY.main = false; DECIDE.pending.clear(); }
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
window.addEventListener("beforeunload", (e) => { if (!LOCKED && (DIRTY.main || DIRTY.panel || DECIDE.pending.size)) { e.preventDefault(); e.returnValue = ""; } });

// The four steps in the left menu, and the pages each one holds (shown under it while you are in it).
const NAV_GROUP = { "rules-safes": "rules", "rules-members": "rules", "rules-dir": "rules", "rules-platforms": "rules",
  "rules-accounts": "rules", "rules-json": "rules", "review-safes": "review", "review": "review" };
function go(page) {
  if (page === "members-decide") { if (PAGE === "review-safes" && SAFES.tab === "decide") return; SAFES.tab = "decide"; page = "review-safes"; }   // Confirm user access: a tab of Safes & members
  if (!leaveOk()) return;
  DIRTY.main = DIRTY.panel = false;
  PAGE = page; NAV_SEQ++; onTableCount = null; if (typeof SAFES !== "undefined") SAFES.panel = null;
  document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("active",
    b.dataset.group ? NAV_GROUP[page] === b.dataset.group : b.dataset.page === page));
  $("#nav").dataset.open = NAV_GROUP[page] || "";
  closeDrawer();
  PAGES[page]().then(() => applyTips()).catch(e => { if (e.message !== "session" && e.message !== "stale") msg($("#main"), "err", e.message); });
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
  "max-acc": "Safes with more accounts than this are flagged for a look, or split (see the choice next to it). CyberArk recommends roughly 3000-5000 at most.",
  "split": "flag them: a Safe over the limit is only marked for a look.\nsplit them: its accounts are spread over numbered Safes of about the same size (P-SVR-WIN-LA-01, -02…), sorted by address so one server's accounts stay together. Safes named in the source or by you are never split. Adding accounts later can move accounts between the numbered Safes.",
  "std-apply": "Which Safes get the standard member groups. Recommended: only Safes the source gives no members, so Safes with members from the source stay as they are. Every Safe: the standard groups are added next to the source's members.",
  "flat-field": "Where the codes for the new part come from: a column in your loaded file, the domain part of each address, or the record type. Each distinct value gets its own code.",
  "flat-name": "Name of the placeholder for this part, letters, digits and _ only. It goes into the pattern as {name}. Use env to add to the built-in environment part.",
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
const SM_TIP = {
  name: "The member's name on each Safe. {safe} becomes the Safe's final name (after splitting, cleanup and your renames).\nExamples: {safe}-Owners → P-BOS-SVR-WIN-LA-Owners · PAM-{safe}-Users · CORP\\{safe}-Approvers (C. Safe members then converts the domain) · PAM-Vault-Admins (no {safe}: the same member on every Safe)",
  member_type: "Group = a directory or Privilege Cloud group (the usual choice); Role = a CyberArk Identity role; User = one person's account.",
  role: "Permission preset or custom role this member gets on every Safe. At least one row should be Full, so someone can manage each Safe and its members.",
  search_in: "Optional searchIn for these members. Leave empty so Privilege Cloud searches every directory. Fill it only when the name exists in more than one directory: the directory's ID (GUID) from Identity, or Vault.",
};
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
      "folder_rule": `the folder exception for ${what}`, "personal": `the personal Safe pattern (personal folders in ${what})`, "group_rule": `the access-group rule for ${what}`,
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
  dm_from: "The domain(s) of members in the export this row converts. Separate several with commas to send them all to one output domain.\nA domain matches both forms: CORP matches CORP\\jdoe and jdoe@corp.example.com.\n* = every member, also names with no domain.\nExamples: CORP · CORP, EMEA, APAC · emea.corp.example.com",
  dm_to: "The output domain. The name becomes UPN format: name@domain.\nLeave empty to drop the domain (CORP\\jdoe → jdoe).\nExamples: corp.example.com turns CORP\\jdoe into jdoe@corp.example.com",
  dm_members: "Which members this row converts: users (the usual case for UPN names), groups, roles, or a combination: users and groups, groups and roles, or all three.",
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
  perm: "This file lists access groups per folder or record (the Workbench layout or a Delinea folder-permissions report). Ticking it also ticks Load.",
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
        <li>Copy your exports and reports into <code>${esc(STATE.inbox)}</code>. For Delinea: the secrets export, the
          all-secrets report with each secret's template, the folder-permission reports and the users list.</li>
        <li>Go to <b>1. Load exports</b>: each file is recognised from its columns, and one click loads them all.</li>
        <li>Check the <b>2. Mapping rules</b> (Safes, permissions, members, platforms, accounts), look over the result in
          <b>3. Review &amp; change</b>, then <b>4. Create upload files</b>.</li></ol>
        <button class="btn primary" data-go="load">Load exports</button></div>${securityNotice(true)}`;
    return;
  }
  const hints = (await api("/api/config")).hints || {};
  const c = STATE.status_counts || {};
  const open = (c.REVIEW || 0) - (STATE.approved || 0);
  const missing = (hints.types_without_platform || []).filter(Boolean);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const refs = STATE.references || {};
  const steps = [
    { n: 1, title: "Load exports", done: true, go: "load", label: "Load more",
      st: `${plural(STATE.records, "account", "accounts")} from ${plural(STATE.inputs.filter(i => !(i.source in (STATE.kinds || {}))).length, "export", "exports")}`
        + (refs.templates ? `; templates for ${plural(refs.templates, "secret", "secrets")}` : "")
        + (refs.users ? `; ${plural(refs.users, "user", "users")} in the users list` : "") + "." },
    STATE.stale ? { n: 2, title: "Mapping rules", done: false, go: "rules-safes", label: "Apply the rules",
      st: "Some loaded accounts haven't been mapped yet: click Save & apply on any rules page." }
    : missing.length ? { n: 2, title: "Mapping rules", done: false, go: "rules-platforms", label: "Give them a platform",
      st: `${plural(missing.length, "record type has", "record types have")} no platform yet: ${missing.map(esc).join(", ")}.` }
    : { n: 2, title: "Mapping rules", done: true, go: "rules-safes", label: "Open",
      st: `${plural(STATE.safes, "Safe", "Safes")}${STATE.invalid_safes ? `, ${STATE.invalid_safes} with a name changed to fit Privilege Cloud` : ""}; every record type has a platform.` },
    STATE.undecided ? { n: 3, title: "Review & change", done: false, go: "members-decide", label: "Decide on them",
      st: `${plural(STATE.undecided, "user may get its", "users may get their")} access through a group: include or leave out each one.` }
    : c.ERROR ? { n: 3, title: "Review & change", done: false, go: "review", view: "errors", label: "Show the errors",
      st: `${plural(c.ERROR, "account has an error", "accounts have errors")} and won't be uploaded${open ? `; ${open} need a look` : ""}.` }
    : open ? { n: 3, title: "Review & change", done: false, go: "review", view: "review_open", label: "Show them",
      st: `${plural(open, "account needs", "accounts need")} a look${STATE.approved ? ` (${STATE.approved} more approved by you)` : ""}.` }
    : { n: 3, title: "Review & change", done: true, go: "review-safes", label: "Open", st: "Nothing needs a look." },
    STATE.outputs.length ? { n: 4, title: "Create upload files", done: true, go: "output", label: "Create more",
      st: `${plural(STATE.outputs.length, "set", "sets")} of upload files created; the latest is ${esc(STATE.outputs[0].name)}.` }
    : { n: 4, title: "Create upload files", done: false, go: "output", label: "Create the upload files", st: "The upload files are not created yet." },
  ];
  const next = steps.find(x => !x.done) || null;
  // A plain accounts list (no folders, no permissions): the short guided path to Safes and members.
  const plainList = (hints.records || 0) > 0 && (hints.without_folder || 0) === hints.records && !(hints.with_grants || 0);
  const guide = plainList ? `<div class="card" id="plain-guide"><h3>Your data is an accounts list only</h3>
      <p class="small">None of the ${plural(hints.records, "account", "accounts")} has a folder or permissions, so the Workbench builds the Safes and their members for you. Three settings do it:</p>
      <ol class="small">
        <li><b>Safe names from account details</b>: add parts such as Site or Application from your columns; environment, technology and account type already come from each account.
          <a href="#" data-go="rules-safes">2. Mapping rules · A. Safes</a></li>
        <li><b>Safe size</b>: Safes over the account limit (3000 unless you change it) can be split into numbered Safes automatically, on the same page.</li>
        <li><b>Members for each Safe</b>: one click adds Owners, Users and Approvers groups named after each Safe.
          <a href="#" data-go="rules-members">2. Mapping rules · B. Safe permissions</a></li></ol>
      <p class="muted small">Step 4 then writes the list of groups to create in your directory next to the review files.</p></div>` : "";
  m.innerHTML = `<h2>Overview</h2><p class="lead">Where the migration stands and what to do next.</p>
    ${statusNotes()}${guide}
    <div class="card"><h3>Steps</h3><ol class="steps">
      ${steps.map(x => `<li class="${x.done ? "done" : "todo"}${x === next ? " next" : ""}"><span class="dot">${x.done ? "✓" : x.n}</span>
        <div style="flex:1"><b>${x.n}. ${esc(x.title)}</b><span class="st">${x.st}</span></div>
        <button class="btn${x === next ? " primary" : " small"}" data-go="${x.go}"${x.view ? ` data-review-view="${x.view}"` : ""}>${esc(x === next ? "Next: " + x.label : x.label)}</button></li>`).join("")}
    </ol></div>
    <div class="card"><h3>What the upload will hold</h3>${readyTiles()}</div>
    <p class="muted small">Workspace: <code>${esc(STATE.workspace)}</code> · <a href="#" data-go="activity" title="Everything done to this database: loads, changes, exports and sign-ins">Activity log</a></p>${securityNotice(false)}`;
  wireTiles();
};

// Warnings shown on the Overview and the Create upload files page.
function statusNotes() {
  let next = "";
  if (STATE.sanitized) next += `<div class="msg warn">${STATE.sanitized} accounts had forbidden characters: invisible or control characters were removed, or characters Privilege Cloud doesn't allow in Safe, platform or account names were replaced. <a href="#" data-go="review" data-review-view="sanitized">Show them</a>.</div>`;
  if (STATE.stale) next += `<div class="msg warn">Some loaded records haven't been mapped yet. Open <b>2. Mapping rules</b> and click Save &amp; apply.</div>`;
  if (STATE.undecided) next += `<div class="msg warn">${STATE.undecided} ${STATE.undecided === 1 ? "user still needs a decision: it" : "users still need a decision: they"} may get their access through a group, so they are not uploaded as Safe members until you add them. <a href="#" data-go="members-decide">Decide on them</a>.</div>`;
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
const SOURCE_NAMES = { delinea: "Delinea", keepass: "KeePass", table: "Spreadsheet (CSV / Excel)", templates: "Template for each secret", users: "Users list" };
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
  ["type", "Record type", "A type or template column; the platform is chosen from it (2. Mapping rules · D. Platforms)."],
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
    <p class="muted small">Your choice is used for every spreadsheet you load from now on. You can change it later under Advanced: settings file (sources → table → columns), linked at the bottom of every settings page.</p>
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
        LAST_LOAD = `<div class="msg ${x.columns ? "warn" : "ok"}">${esc(x.name)}: ${x.records} accounts loaded again with the columns you picked${x.columns ? `, but there is still no ${x.columns.missing.map(k => FIELD_WORD[k]).join(" or ")}. Check the picks below.` : ". Rules applied."}</div>`;
        if (x.columns) COLUMN_PICK = { results: r.results, perm: pick.perm };
        await PAGES.load();
      } catch (e) { msg($(".col-pick-msg", card), "err", e.message); }
    };
  });
}
// What each kind of file is, for the "What it is" picker on the Load exports page.
const FILE_KINDS = [["accounts", "Accounts export"], ["permissions", "Folder permissions report"], ["templates", "Template for each secret"],
  ["users", "Users list (full name to UPN)"], ["skip", "Not needed: skip it"]];
const KIND_TIPS = {
  accounts: "The accounts with their passwords: Delinea's secrets export (CSV or XML), a KeePass export or any spreadsheet with one account per row. Secrets are encrypted as they load.",
  permissions: "Who may use the secrets in each folder: Delinea's \"What folder permissions exist for groups?\" (groups become Safe members) and \"What folders can all users see?\" (users get their own membership only where no group explains their access; the others wait for your decision under 3. Review & change). Applied to the accounts exports as they load, so the exports load again with them.",
  skip: "Recognised, but it adds nothing the upload needs.",
};
const kindTip = (k) => KIND_TIPS[k] || ((STATE.kinds || {})[k] || {}).help || "";
// The files to export from each source, in the order they matter. need: "yes", "recommended", "optional", "no".
const RECOMMENDED = [
  ["Delinea Secret Server (CSV export and reports)", [
    ["secrets-export.csv", "yes", "The secrets export: Secret Name, Folder (the full path), Username, Password, Domain, Notes. The accounts and their passwords."],
    ["allsecrets.csv", "yes", "Report of all secrets with their template (Name, Secret template, Folder). The secrets export has no template column, and the template picks the platform."],
    ["whatfolderpermissionsexistforgroups.csv", "recommended", "Report \"What folder permissions exist for groups?\". The groups on each folder become Safe members."],
    ["whatfolderscanalluserssee.csv", "recommended", "Report \"What folders can all users see?\". Users with their own access; those a group may explain wait for your decision."],
    ["lauserslist.csv", "recommended", "The users list (Username, Display name). Turns the full names in the folder reports into UPNs, and names personal Safes."],
    ["lagroups.csv · secret-template-list.csv · role reports", "no", "Recognised, but not needed: groups come from the folder report, templates from allsecrets.csv, and roles are about Secret Server itself."]]],
  ["Delinea Secret Server (XML export)", [
    ["The XML export (ImportFile)", "yes", "Folders, templates, secrets and permissions in one file. Delinea's KeePass migration tool writes the same format."],
    ["lauserslist.csv", "optional", "Only when its permissions name users by their full name."]]],
  ["KeePass", [
    ["The KeePass 2 XML export", "yes", "Groups become folders, entries become accounts. Protected fields are treated as secrets."],
    ["A folder permissions CSV", "optional", "KeePass has no permissions: give them per folder (Folder Path, Group, Permission), or use the standard member groups under B. Safe permissions."]]],
  ["Spreadsheet (CSV, TSV or Excel)", [
    ["One sheet, one account per row", "yes", "Columns such as Name, Address, Username, Password, Type or Platform, Folder or Site. Columns with other names can be picked after loading."],
    ["A folder permissions CSV", "optional", "When the sheet has no access columns; or use the standard member groups under B. Safe permissions."]]],
];
const NEED_LABEL = { yes: ["OK", "needed"], recommended: ["REVIEW", "recommended"], optional: ["", "optional"], no: ["", "not needed"] };
function recommendedHtml(files) {
  const names = new Set(files.map(f => f.name.toLowerCase()).concat((STATE.inputs || []).map(i => String(i.path || "").split(/[\\/]/).pop().toLowerCase())));
  return `<details class="card fold" id="recommended"><summary>Recommended files for each source <span class="muted small" style="font-weight:400">· what to export before you start</span></summary>
    ${RECOMMENDED.map(([src, rows]) => `<details class="rec-src"><summary><b>${esc(src)}</b></summary>
      <table class="small"><tr><th>File</th><th></th><th>What it gives</th></tr>
      ${rows.map(([f, need, what]) => { const here = names.has(f.toLowerCase());
        return `<tr${need === "no" ? ' class="muted"' : ""}><td>${here ? "✓ " : ""}<code>${esc(f)}</code>${here ? ' <span class="muted small">here</span>' : ""}</td>
          <td><span class="pill ${NEED_LABEL[need][0]}">${NEED_LABEL[need][1]}</span></td><td>${esc(what)}</td></tr>`; }).join("")}</table></details>`).join("")}
    <p class="muted small">File names are Delinea's defaults; any name works, because each file is recognised from its columns.</p></details>`;
}
PAGES.load = async () => {
  await refresh();
  const files = STATE.inbox_files;
  const kinds = STATE.kinds || {};
  const refs = STATE.references || {};
  const startKind = (f) => f.kind in kinds ? (kinds[f.kind].used ? f.kind : "skip") : f.kind || "accounts";
  const srcOpts = (sel) => `<option value="">Detect${sel ? " (" + esc(SOURCE_NAMES[sel] || sel) + ")" : ""}</option>` +
    Object.entries(STATE.sources).map(([k, d]) => `<option value="${esc(k)}">${esc(SOURCE_NAMES[k] || k)}</option>`).join("");
  const loadedSame = files.filter(f => f.loaded === "same" && startKind(f) === "accounts");
  const status = (f) => f.loaded === "same" ? '<span class="pill OK" title="This file is loaded and hasn\'t changed since">loaded</span>'
    : f.loaded === "changed" ? '<span class="pill REVIEW" title="A file with this name was loaded, but its content has changed since. Load it again to update; your changes are kept.">changed since loaded</span>'
    : '<span class="muted small">new</span>';
  // The checklist: what a Delinea migration needs, and whether the Workbench has it.
  const have = (k) => files.some(f => startKind(f) === k);
  const loadedAccounts = (STATE.inputs || []).filter(i => !(i.source in kinds)).length;
  const loadedPerms = (STATE.inputs || []).some(i => i.permissions_path);
  const check = [
    ["Accounts export", loadedAccounts || have("accounts"), loadedAccounts ? `${STATE.records} accounts loaded` : have("accounts") ? "in the inbox, not loaded yet" : "missing", kindTip("accounts")],
    ["Template for each secret", refs.templates || have("templates"), refs.templates ? `${refs.templates} secrets listed` : have("templates") ? "in the inbox, not loaded yet" : "only needed when the export has no template column (Delinea's secrets export has none)", kindTip("templates")],
    ["Folder permissions report", loadedPerms || have("permissions"), loadedPerms ? "loaded with the accounts" : have("permissions") ? "in the inbox, not loaded yet" : "missing: without it, Safes get no members from the source", kindTip("permissions")],
    ["Users list", refs.users || have("users"), refs.users ? `${refs.users} users listed` : have("users") ? "in the inbox, not loaded yet" : "needed when the folder reports name users by their full name", kindTip("users")],
  ];
  $("#main").innerHTML = `<h2>1. Load exports</h2>
    <p class="lead">Copy your exports and reports into the inbox folder. Each file is recognised from its columns, so you can see what it is and what it adds before you load it.</p>
    <div class="card"><h3>What the Workbench has</h3>
      <ul class="checklist">${check.map(([t, ok, st, tip]) => `<li class="${ok ? "ok" : "todo"}" title="${esc(tip)}"><span class="dot">${ok ? "✓" : "○"}</span><b>${esc(t)}</b> <span class="muted small">${esc(st)}</span></li>`).join("")}</ul></div>
    ${recommendedHtml(files)}
    <div class="card"><h3>Inbox: <a class="pathlink" id="open-inbox" title="Open this folder in Explorer"><code>${esc(STATE.inbox)}</code></a>
      <button class="btn small" id="open-inbox2">Open folder</button>
      <button class="btn small" data-copy="${esc(STATE.inbox)}" title="Copy the folder path, to paste into File Explorer's address bar or a file dialog">Copy path</button></h3>
    ${files.length ? `<div class="tablewrap"><table><tr><th title="Ticked files are loaded when you click Load. New and changed files are ticked for you.">Load</th><th>File</th>
        <th class="has-tip" title="Recognised from the file's columns. Change it if the guess is wrong.">What it is <span class="q">?</span></th><th>What it adds</th><th>Status</th><th>Size</th><th></th></tr>
      ${files.map((f, i) => { const k = startKind(f); return `<tr${k === "skip" ? ' class="muted"' : ""}><td><input type="checkbox" class="pick" data-i="${i}" ${k !== "skip" && f.loaded !== "same" ? "checked" : ""}></td>
        <td>${esc(f.name)}</td>
        <td><select class="kind" data-i="${i}" title="What this file is">${FILE_KINDS.map(([v, l]) => `<option value="${v}" ${v === k ? "selected" : ""}>${esc(v === "skip" && f.kind in kinds && !kinds[f.kind].used ? kinds[f.kind].label : l)}</option>`).join("")}</select>
          <select class="src${k === "accounts" ? "" : " hidden"}" data-i="${i}" title="Which kind of accounts export. Detect works for Delinea, KeePass and spreadsheets.">${srcOpts(f.guess)}</select></td>
        <td class="small adds" data-i="${i}">${esc(kindTip(f.kind in kinds && !kinds[f.kind].used ? f.kind : k))}</td>
        <td>${status(f)}</td><td class="nowrap">${(f.size / 1024).toFixed(1)} KB</td>
        <td class="x"><button class="btn small del" data-name="${esc(f.name)}" title="Securely delete ${esc(f.name)}: overwrite it, then delete it">✕</button></td></tr>`; }).join("")}</table></div>
      <p class="muted small">Permissions reports are applied to the accounts as they load, so loading a new or changed report also loads the accounts exports you loaded before again. Your changes are kept.</p>
      <div class="row" style="margin-top:12px"><button class="btn primary" id="go-load">Load ticked files</button>
        <button class="btn" id="re">Refresh list</button>
        ${loadedSame.length ? `<button class="btn danger" id="del-loaded" title="Overwrite and delete the accounts exports that are loaded and unchanged (they hold passwords): ${esc(loadedSame.map(f => f.name).join(", "))}">Securely delete the loaded exports (${loadedSame.length})</button>` : ""}</div>`
      : `<p class="muted">The inbox is empty. Copy your files into the folder above, then <button class="btn" id="re">Refresh</button></p>`}
    <div id="load-msg">${LAST_LOAD}</div></div>
    ${columnPickHtml()}
    ${loadedFilesHtml()}
    <div class="floatbar"><button class="btn" data-go="rules-safes">Next: 2. Mapping rules ›</button></div>`;
  LAST_LOAD = "";
  wireColumnPick();
  $("#re").onclick = () => go("load");
  const openInbox = async () => {
    try { const r = await api("/api/open", { which: "inbox" }); if (!r.opened) alert("Open this folder yourself: " + r.path); }
    catch (e) { msg($("#load-msg"), "err", e.message); }
  };
  $("#open-inbox").onclick = openInbox; $("#open-inbox2").onclick = openInbox;
  wireCopy($("#main"));
  document.querySelectorAll(".kind").forEach(sel => sel.onchange = () => {
    const i = sel.dataset.i;
    document.querySelector(`.src[data-i="${i}"]`).classList.toggle("hidden", sel.value !== "accounts");
    document.querySelector(`.adds[data-i="${i}"]`).textContent = kindTip(sel.value);
    document.querySelector(`.pick[data-i="${i}"]`).checked = sel.value !== "skip";
  });
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
    const kindOf = (i) => document.querySelector(`.kind[data-i="${i}"]`).value;
    const ticked = new Set([...document.querySelectorAll(".pick:checked")].map(cb => cb.dataset.i));
    const all = files.map((f, i) => String(i));
    // Every permissions report in the inbox applies to the accounts; a new one loads the accounts again.
    const perm = all.filter(i => kindOf(i) === "permissions").map(i => files[i].name);
    const permNew = all.some(i => kindOf(i) === "permissions" && ticked.has(i));
    // An accounts export loaded earlier loads again with a new report; one you never loaded stays as you ticked it.
    const accounts = all.filter(i => kindOf(i) === "accounts" && (ticked.has(i) || permNew && files[i].loaded));
    const picks = accounts.map(i => ({ name: files[i].name, source: document.querySelector(`.src[data-i="${i}"]`).value }));
    const references = [...ticked].filter(i => kindOf(i) === "templates" || kindOf(i) === "users").map(i => ({ name: files[i].name, kind: kindOf(i) }));
    if (!picks.length && !references.length)
      return msg($("#load-msg"), "err", permNew ? "A permissions report adds access to the accounts of an export: copy the accounts export into the inbox too." : "Tick the files to load first.");
    try {
      const r = await api("/api/ingest", { files: picks, permissions: picks.length ? perm : [], references });
      await refresh();
      if (r.results.some(x => x.columns)) COLUMN_PICK = { results: r.results, perm };
      const what = (x) => x.source in kinds ? `${x.records} rows loaded as the ${esc(kinds[x.source].label.charAt(0).toLowerCase() + kinds[x.source].label.slice(1))}` : `${x.records} accounts loaded as ${esc(SOURCE_NAMES[x.source] || x.source)}${x.replaced ? ` (${x.replaced} replaced)` : ""}`;
      LAST_LOAD = `<div class="msg ok">${r.results.map(x => `${esc(x.name)}: ${what(x)}${x.sanitized ? `; <b style="color:var(--warn)">${x.sanitized} with forbidden characters removed</b>` : ""}`).join("<br>")}
        ${picks.length && perm.length ? `<br>Permissions from ${perm.map(esc).join(", ")}.` : ""}
        <br>Rules applied.${picks.length && STATE.protector === "dpapi" ? " Passwords are encrypted in the database now, so you can securely delete the loaded exports (button above)." : ""}</div>
        ${r.results.some(x => x.sanitized) ? `<div class="msg warn">Some values held invisible or control characters (for example zero-width spaces or line breaks inside a name). They were removed and each account notes which fields changed. <a href="#" data-go="review" data-review-view="sanitized">Show them</a></div>` : ""}
        ${STATE.undecided ? `<div class="msg warn">${STATE.undecided} ${STATE.undecided === 1 ? "user" : "users"} from the users report may get their access through a group. <a href="#" data-go="members-decide">Decide on them</a> under 3. Review &amp; change · A. Safes &amp; members, <b>Confirm user access</b>.</div>` : ""}`;
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
const LAYER_FIELDS = ["folder_word", "folder_level", "folder", "platform", "username", "address", "address_domain", "name", "type", "source",
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
/* "Copy path" buttons: the path goes to the clipboard, to paste into File Explorer's address bar
   (Windows may open a folder behind the browser; a pasted path always comes to the front). */
async function copyText(btn, text) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); } finally { t.remove(); }
  }
  const was = btn.textContent; btn.textContent = "Copied"; setTimeout(() => { btn.textContent = was; }, 1500);
}
function wireCopy(root) { root.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => copyText(b, b.dataset.copy)); }
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
const RULE_PAGES = [["rules-safes", "2. Mapping rules · A. Safes"], ["rules-members", "2. Mapping rules · B. Safe permissions"],
  ["rules-dir", "2. Mapping rules · C. Safe members"], ["rules-platforms", "2. Mapping rules · D. Platforms"], ["rules-accounts", "2. Mapping rules · E. Accounts"],
  ["rules-json", "2. Mapping rules · Advanced: settings file (JSON)"]];
// The Next button at the bottom of each page: the steps in order.
const NEXT_PAGE = { "rules-safes": ["rules-members", "Next: B. Safe permissions"], "rules-members": ["rules-dir", "Next: C. Safe members"],
  "rules-dir": ["rules-platforms", "Next: D. Platforms"], "rules-platforms": ["rules-accounts", "Next: E. Accounts"],
  "rules-accounts": ["review-safes", "Next: 3. Review & change"], "rules-json": ["review-safes", "Next: 3. Review & change"] };

// One settings page: its own cards and its own Save & apply, which saves only its keys.
async function rulesPage(page, intro, render) {
  const data = await api("/api/config");
  TABLES = {};
  const title = RULE_PAGES.find(p => p[0] === page)[1];
  const [nextPage, nextTitle] = NEXT_PAGE[page];
  const json = page === "rules-json";
  const view = render(data);
  $("#main").innerHTML = `<h2>${esc(title)}</h2>
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
PAGES.rules = async () => go("rules-platforms");

/* ---------------- 3. Review & change · A. Safes & members · Confirm user access ----------------
   Delinea's "What folders can all users see?" lists each user's effective access, including access
   that comes through a group. A user whose access no group on the folder explains is a Safe member
   on its own. These are the others: a group on the same folder gives the same or stronger access,
   so the user may not need its own membership. Nothing is assumed: you choose for each one.
   Choices are staged on the tab and kept only when you click Save decisions. */
const DECIDE = { group: "", safe: "", show: "open", selected: new Set(), pending: new Map(), rows: [] };
const DECISION_LABEL = { "": "not decided", include: "add as member", exclude: "rely on the group" };
const decideKey = (r) => r.folder + "\n" + r.member;   // a line break: kept in an HTML attribute, never in a folder or name
const decideGroups = (r) => (r.groups || "").split(", ").filter(Boolean);
const decideNow = (r) => DECIDE.pending.has(decideKey(r)) ? DECIDE.pending.get(decideKey(r)) : r.decision;
function stageDecision(r, decision) {
  if (decision === r.decision) DECIDE.pending.delete(decideKey(r)); else DECIDE.pending.set(decideKey(r), decision);
}
function decideHtml(rows) {
  const shown = rows.filter(r => (DECIDE.show === "all" || !r.decision)
    && (!DECIDE.group || (DECIDE.group === "(none)" ? !r.groups : decideGroups(r).includes(DECIDE.group)))
    && (!DECIDE.safe || r.safe_name === DECIDE.safe));
  // Per likely group: how many users and folders, to choose for all of them at once.
  const byGroup = new Map();
  rows.forEach(r => (decideGroups(r).length ? decideGroups(r) : ["(none)"]).forEach(g => {
    const x = byGroup.get(g) || { users: new Set(), folders: new Set(), open: 0 };
    x.users.add(r.member.toLowerCase()); x.folders.add(r.folder); if (!decideNow(r)) x.open++; byGroup.set(g, x); }));
  const safes = [...new Set(rows.map(r => r.safe_name))].sort();
  const open = rows.filter(r => !r.decision).length;
  const opt = (v, cur) => `<option value="${v}" ${v === cur ? "selected" : ""}>${DECISION_LABEL[v]}</option>`;
  return `<p class="muted small">These users come from Delinea's <b>What folders can all users see?</b> report, which lists every user's access, including access they only get through a group.
      For each user here, a group on the same folder gives the same or stronger access, so the user may not need a Safe membership of their own. The Workbench doesn't guess: choose <b>Add as member</b> or <b>Rely on the group</b> for each one, then <b>Save decisions</b>.</p>
    <details class="card fold explain"><summary>How this tab works</summary>
      <ul class="small">
        <li><b>Already added for you:</b> a user whose access is stronger than every group's on that folder, or who is on a folder no group can see. Their access can't come from a group, so they are Safe members (noted "direct access").</li>
        <li><b>Listed here:</b> every other user in that report. The <b>Groups with this access</b> column shows the groups on the same folder that give at least the same access: the user is probably a member of one of them.</li>
        <li><b>Add as member</b> adds the user to that Safe as well, with their own role. <b>Rely on the group</b> leaves the user out: they keep their access through the group. Users without a decision are not uploaded, and step 4 warns until none are left.</li>
        <li>Your choices are kept only when you click <b>Save decisions</b>. They are kept per folder and user, so they survive loading the files again. A group membership list (for example from Active Directory) is the sure way to settle them.</li></ul></details>
    <div class="card"><h3>By likely group <span class="muted small">(choose for all of a group's undecided users at once)</span></h3>
      <div class="tablewrap"><table class="small"><tr><th>Group with the same access</th><th>Users</th><th>Folders</th><th>Not decided</th><th></th></tr>
      ${[...byGroup.entries()].sort((a, b) => b[1].open - a[1].open || a[0].localeCompare(b[0])).map(([g, x]) => `<tr><td>${g === "(none)" ? '<span class="muted">no group report loaded</span>' : esc(g)}</td>
        <td>${x.users.size}</td><td>${x.folders.size}</td><td>${x.open}</td>
        <td class="nowrap"><button class="btn small g-show" data-g="${esc(g)}">Show</button>
          <button class="btn small g-dec" data-g="${esc(g)}" data-d="exclude" title="Every undecided user this group may explain keeps their access through the group. Saved when you click Save decisions.">All rely on the group</button>
          <button class="btn small g-dec" data-g="${esc(g)}" data-d="include" title="Give every undecided user listed for this group their own Safe membership too. Saved when you click Save decisions.">Add all as members</button></td></tr>`).join("")}</table></div></div>
    <div class="card">
      <div class="row" style="margin-bottom:8px">
        <label class="inline">Show <select id="d-show"><option value="open">not decided (${open})</option><option value="all" ${DECIDE.show === "all" ? "selected" : ""}>all (${rows.length})</option></select></label>
        <label class="inline">Group <select id="d-group"><option value="">any</option>${[...byGroup.keys()].sort().map(g => `<option ${g === DECIDE.group ? "selected" : ""}>${esc(g)}</option>`).join("")}</select></label>
        <label class="inline">Safe <select id="d-safe"><option value="">any</option>${safes.map(x => `<option ${x === DECIDE.safe ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>
        <span class="muted small">${shown.length} shown</span></div>
      <div class="tablewrap"><table id="decide-table"><tr><th><input type="checkbox" id="d-selall" title="Tick every user shown"></th><th title="The full name in the report, and the name that will be uploaded (the UPN from the users list)">User</th><th>Folder</th><th>Safe</th>
        <th title="The user's access to the folder, as the report gives it">Access</th><th title="Groups on the same folder with the same or stronger access">Groups with this access</th><th>Accounts</th><th title="Change it here, then click Save decisions">Decision</th></tr>
      ${shown.map(r => { const k = decideKey(r), now = decideNow(r);
        return `<tr><td><input type="checkbox" class="d-sel" data-k="${esc(k)}" ${DECIDE.selected.has(k) ? "checked" : ""}></td>
        <td>${esc(r.member)}${r.member_name !== r.member ? `<br><span class="muted small">→ ${esc(r.member_name)}</span>` : ""}${r.notes ? ` <span class="pill REVIEW" title="${esc(r.notes)}">⚠</span>` : ""}</td>
        <td>${esc(r.folder)}</td><td>${esc(r.safe_name)}</td><td>${esc(r.permission)}</td><td>${esc(r.groups) || '<span class="muted">unknown: no group report</span>'}</td><td>${r.accounts}</td>
        <td class="nowrap"><select class="d-dec" data-k="${esc(k)}">${opt("", now)}${opt("include", now)}${opt("exclude", now)}</select>${DECIDE.pending.has(k) ? ' <span class="pill REVIEW" title="Not saved yet: click Save decisions">not saved</span>' : ""}</td></tr>`; }).join("")}</table></div>
      <div class="row" style="margin-top:10px"><span class="muted small">Ticked users:</span>
        <button class="btn" id="d-inc" title="Give the ticked users their own Safe membership">Add as members</button>
        <button class="btn" id="d-exc" title="Leave the ticked users out: they keep their access through the group">Rely on the group</button>
        <button class="btn" id="d-undo" title="Take the decision back: the users wait again">Not decided</button>
        <label class="inline">Reason (optional) <input type="text" id="d-reason" size="24" placeholder="kept in the activity log" value="${esc(DECIDE.reason || "")}"></label></div>
      <div id="d-msg"></div></div>`;
}
// Draws the tab again after a filter or a staged change, and keeps the Save button and the unsaved mark in step.
function drawDecide() {
  const el = $("#tab-decide"); if (!el) return;
  el.innerHTML = decideHtml(DECIDE.rows);
  bindDecide();
  syncDecideSave();
}
function syncDecideSave() {
  const n = DECIDE.pending.size, b = $("#d-save");
  if (b) { b.disabled = !n; b.textContent = n ? `Save ${n} ${n === 1 ? "decision" : "decisions"}` : "Decisions saved"; }
}
function bindDecide() {
  const rows = DECIDE.rows, byKey = new Map(rows.map(r => [decideKey(r), r]));
  $("#d-show").onchange = () => { DECIDE.show = $("#d-show").value; drawDecide(); };
  $("#d-group").onchange = () => { DECIDE.group = $("#d-group").value; drawDecide(); };
  $("#d-safe").onchange = () => { DECIDE.safe = $("#d-safe").value; drawDecide(); };
  $("#d-reason").oninput = () => { DECIDE.reason = $("#d-reason").value; };
  document.querySelectorAll(".g-show").forEach(b => b.onclick = () => { DECIDE.group = b.dataset.g; DECIDE.show = "all"; drawDecide(); });
  document.querySelectorAll(".d-sel").forEach(cb => cb.onchange = () => cb.checked ? DECIDE.selected.add(cb.dataset.k) : DECIDE.selected.delete(cb.dataset.k));
  $("#d-selall").onchange = () => document.querySelectorAll(".d-sel").forEach(cb => { cb.checked = $("#d-selall").checked; cb.onchange(); });
  document.querySelectorAll(".d-dec").forEach(s => s.onchange = () => { stageDecision(byKey.get(s.dataset.k), s.value); drawDecide(); });
  const stage = (list, decision) => {
    if (!list.length) return msg($("#d-msg"), "err", "Tick at least one user first.");
    list.forEach(r => stageDecision(r, decision));
    DECIDE.selected.clear(); drawDecide();
    msg($("#d-msg"), "warn", `${list.length} ${list.length === 1 ? "user" : "users"}: ${DECISION_LABEL[decision]}. Not saved yet: click Save decisions.`);
  };
  const ticked = () => rows.filter(r => DECIDE.selected.has(decideKey(r)));
  $("#d-inc").onclick = () => stage(ticked(), "include");
  $("#d-exc").onclick = () => stage(ticked(), "exclude");
  $("#d-undo").onclick = () => stage(ticked(), "");
  document.querySelectorAll(".g-dec").forEach(b => b.onclick = () => {
    const g = b.dataset.g;
    const list = rows.filter(r => !r.decision && (g === "(none)" ? !r.groups : decideGroups(r).includes(g)));
    if (!list.length) return msg($("#d-msg"), "ok", "Every user for this group is decided already.");
    stage(list, b.dataset.d);
  });
}
async function saveDecisions() {
  const byKey = new Map(DECIDE.rows.map(r => [decideKey(r), r])), byDecision = new Map();
  for (const [k, d] of DECIDE.pending) { const r = byKey.get(k); if (!r) continue;
    if (!byDecision.has(d)) byDecision.set(d, []); byDecision.get(d).push({ folder: r.folder, member: r.member }); }
  if (!byDecision.size) return;
  try {
    const counts = [];
    for (const [decision, items] of byDecision) {
      const r = await api("/api/decide", { items, decision, reason: DECIDE.reason || "" });
      counts.push(`${r.changed} ${DECISION_LABEL[decision]}`);
    }
    DECIDE.pending.clear(); DECIDE.reason = ""; DIRTY.main = false;
    await PAGES["review-safes"]();
    msg($("#d-msg"), "ok", `Decisions saved (${counts.join(", ")}). Rules applied.`);
  } catch (e) { msg($("#d-msg"), "err", e.message); }
}

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

/* C. Safe members: member names, domain conversion and directory sources */
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
    const DM_COLS = [{ key: "from", label: "Source domain(s)", ph: "CORP, EMEA", tip: DIR_TIP.dm_from },
      { key: "to", label: "Output domain (UPN)", ph: "corp.example.com, or empty to drop", tip: DIR_TIP.dm_to },
      { key: "members", label: "Applies to", options: [["users", "users"], ["groups", "groups"], ["roles", "roles"], ["users+groups", "users and groups"],
        ["groups+roles", "groups and roles"], ["all", "users, groups and roles"]], tip: DIR_TIP.dm_members }];
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
        <div class="card"><h3>Domain conversion <span class="muted small">(checked before the default above, top to bottom; the first match wins)</span></h3>
          <p class="small">Drop a domain, or change it and give the name in UPN format (<code>name@domain</code>). One row per output domain: list several source domains on one row to send them all to the same domain (<code>CORP, EMEA → corp.example.com</code>), or add a row per source domain to send each to its own. Example: <code>CORP\\jdoe</code> → <code>jdoe@corp.example.com</code>. A member no row matches keeps the default above. A source below still applies its find and replace, added text and case to the converted name.</p>
          ${editorTable("t-dm", DM_COLS, cfg.domain_map || [], "+ Add domain conversion", true)}</div>
        <div class="card"><h3>Exceptions: sources for some members <span class="muted small">(checked before the default above, top to bottom; the first match wins)</span></h3>
          <h4 style="margin:6px 0">Groups and roles</h4>${editorTable("t-dg", COLS, rowsFor("groups"), "+ Add group source")}
          <h4 style="margin:12px 0 6px">Users</h4>${editorTable("t-du", COLS, rowsFor("users"), "+ Add user source")}</div>`,
      collect() {
        const fix = (r, members) => ({ ...r, members, strip_domain: r.strip_domain !== "no", name: r.name || r.match || "" });
        const list = readTable("t-dg").map(r => fix(r, "groups")).concat(readTable("t-du").map(r => fix(r, "users")));
        const domainMap = readTable("t-dm").filter(r => r.from || r.to).map(r => ({ from: r.from || "", to: (r.to || "").replace(/^@/, ""), members: r.members || "users" }));
        return { directory_sources: list, directory_map: { "*": $("#dir-fallback").value.trim() }, domain_map: domainMap,
                 strip_domain_prefix: $("#dir-strip").checked, default_member_type: $("#dir-type").value };
      },
      preview: {
        title: "each member in the export → its name in Privilege Cloud",
        load: (patch) => api("/api/members/preview", { patch }),
        rows: (r) => r.members, summary: (r) => `${r.members.length} members`,
        head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(3, "SafeMembers.csv")}<th class="grp"></th></tr>
          <tr><th>Member in the export</th><th>Accounts</th><th>MemberName</th><th>MemberType</th><th>SearchIn</th><th>Source used</th></tr>`,
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
    const PS = [{ key: "folder", label: "Personal folder", ph: "\\Personal Folders", list: "dl-folders",
                  tip: "The folder that holds personal folders, such as Delinea's \\Personal Folders. Everything in it and under it goes to personal Safes." },
                { key: "person", label: "Whose (optional)", ph: "empty: each folder under it is one person's",
                  tip: "Leave empty when each folder directly under this one is named after its person (Delinea: \\Personal Folders\\Jane Smith).\nOr give one person's name (or UPN) when this whole folder belongs to that person.\nExample: Jane Smith" }];
    const ps = cfg.personal_safes || { template: "P-{user}", folders: [] };
    // Top folders that look like Delinea's personal folders and aren't marked yet.
    const marked = new Set((ps.folders || []).map(r => normName(r.folder || "")));
    const personalTops = [...new Set((hints.folders || []).map(f => String(f.name || "").replace(/^\\+/, "").split("\\")[0])
      .filter(t => /personal/i.test(t)).map(t => "\\" + t))].filter(t => !marked.has(normName(t)));
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
    // Accounts with no folders (a plain accounts list): build the Safe name from account details.
    const flat = hints.without_folder || 0, total = hints.records || 0;
    const FLAT_SOURCES = (hints.columns || []).filter(c => c.filled).map(c => [`column:${c.name}`, `the ${c.name} column (${c.filled} accounts have a value)`])
      .concat([["address_domain", "the address's domain (srv01.boston.corp.example.com → boston…)"], ["type", "the record type / template"]]);
    const flatCard = `<details class="card fold" data-block="flat" id="flat-card"${flat ? " open" : ""}><summary>Accounts without folders: build Safe names from account details
        <span class="muted small" style="font-weight:400">· ${total ? `${flat} of ${total} loaded accounts have no folder` : "for plain accounts lists, such as a spreadsheet"}</span></summary>
      <p class="small">With no folders, each Safe name is built from the pattern <b>with no folders</b> above, one short code per part, for example
        <code>{env}-{site}-{tech}-{flavor}-{acct}</code> → <code>P-BOS-SVR-WIN-LA</code>. <code>{tech}</code>, <code>{flavor}</code> and <code>{acct}</code>
        come from each account's platform and username already. Add a part from any column in your file (Environment, Site, Application…): the Workbench
        lists its values and suggests a 1-4 letter code for each, which you can change. Fewer parts = fewer, bigger Safes; more parts = smaller Safes, closer to least privilege.</p>
      <div class="row"><label class="inline">Take codes from <select id="flat-field">${FLAT_SOURCES.length ? "" : "<option value=\"\">(load a file first)</option>"}${FLAT_SOURCES.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("")}</select></label>
        <label class="inline">as placeholder <input type="text" id="flat-name" size="12" placeholder="site"></label>
        <button class="btn small" id="flat-add" title="Lists the values found there, gives each a suggested code, and adds the placeholder to the pattern for accounts with no folders. Nothing is saved until you click Save & apply.">Add to the Safe name</button></div>
      <div id="flat-msg"></div>
      <p class="muted small" id="flat-size"></p></details>`;
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
          <label class="inline">Safes with more than <input type="text" id="max-acc" size="6" value="${esc(cfg.safe_max_accounts)}"> accounts:
            <select id="split">${[["", "flag them for a look"], ["1", "split them into numbered Safes (-01, -02…)"]].map(([v, l]) => `<option value="${v}" ${(cfg.safe_split_over_max ? "1" : "") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label></div></div>
        <p class="muted small">Step 4 also writes <code>review/SafeNamingConvention.csv</code> with every set of upload files: the parts of every Safe name, to keep naming new Safes the same way after the migration.</p>
        <p class="muted small">⚠ Safe names are always cut to ${cfg.safe_name.max_length} characters, and the characters <code>${esc(cfg.safe_name.invalid_chars)}</code> become "${esc(cfg.safe_name.replacement)}". The preview at the bottom of the window shows the result as you type.</p></div>
      ${flatCard}
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
      <div class="card"><h3>Personal Safes <span class="muted small">(folders that hold one person's secrets: named after the person, not abbreviated)</span></h3>
        <p class="muted small">Without this, a folder such as <code>\\Personal Folders\\Jane Smith</code> becomes a Safe named from abbreviations of the person's name. Mark the personal folders here and their Safes are named with your personal Safe pattern instead.
          The username comes from the users list (lauserslist.csv), so load it in step 1.</p>
        ${personalTops.length ? `<div class="msg warn">Your folders include ${personalTops.map(t => `<code>${esc(t)}</code>`).join(", ")}. ${personalTops.map(t => `<button class="btn small ps-mark" data-folder="${esc(t)}" title="Adds this folder below: each folder directly under it becomes one person's Safe. Nothing is saved until you click Save &amp; apply.">Mark ${esc(t)} as personal</button>`).join(" ")}</div>` : ""}
        <div class="row"><label class="inline">Personal Safe pattern <input type="text" id="ps-template" size="24" value="${esc(ps.template || "P-{user}")}" data-check="safe"
          title="How personal Safes are named. Placeholders:\n{user} the username (the UPN before the @, from the users list)\n{upn} the whole UPN\n{first} {last} the first and last name\n{name} the name as the folder gives it\nExamples: P-{user} gives P-jane.smith · P-{last}{first} gives P-SmithJane"></label>
          <span class="muted small">{user} {upn} {first} {last} {name}</span>
          <label class="inline">Add the person to their Safe as <select id="ps-owner" title="The person a personal Safe belongs to becomes its member with at least this role (empty: not added).\nThe folder permission reports should show them on their folder too: the member's notes say what the report gives, or CHECK when it doesn't list them.">${roleOptions(ps.owner_role === undefined ? "Full" : ps.owner_role, true)}</select></label></div>
        ${editorTable("t-ps", PS, ps.folders || [], "+ Add a personal folder")}</div>
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
      if (!rows.length) { if (STATE.has_db) $("#conv-folders").innerHTML = '<p class="muted small">Your loaded accounts have no folders, so there is nothing to abbreviate here.</p>'; return; }
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
        personal_safes: { template: $("#ps-template").value.trim() || "P-{user}", owner_role: $("#ps-owner").value,
          folders: readTable("t-ps").filter(r => r.folder).map(r => r.person ? { folder: r.folder, person: r.person } : { folder: r.folder, person: "" }) },
        group_rules: readTable("t-gr").map(r => { const o = { safe: r.safe }; if (r.group) o.group = r.group; else if (r.group_pattern) o.group_pattern = r.group_pattern; if (r.min_role) o.min_role = r.min_role; return o; }),
        group_rules_first: $("#gr-first").checked,
        safe_max_accounts: num($("#max-acc").value.trim(), "The account limit"),
        safe_split_over_max: $("#split").value === "1",
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
          <th title="The Safe the accounts go to, with every rule, exception and your own changes applied">SafeName</th>
          <th title="Characters in the Safe name (at most ${cfg.safe_name.max_length})">Length</th>
          <th title="The CPM that manages this Safe's accounts: the Safe settings, then the 'Different settings' exceptions, then your own Safe changes. Empty = no CPM">ManagingCPM</th>
          <th title="numberOfVersionsRetention or numberOfDaysRetention">Keeps</th><th>Description</th>
          <th title="Things to check about this Safe">Notes</th></tr>`,
        row: (x) => `<tr><td>${esc(x.folder || "(no folder)")}</td><td>${x.accounts}</td>
          <td${chg(x, "safe", "nowrap")}><b>${esc(x.safe)}</b>${x.valid ? "" : ' <span class="pill REVIEW" title="Forbidden characters replaced or the name shortened">name changed</span>'}</td>
          <td>${x.length}</td><td${chg(x, "cpm", "nowrap")}>${x.cpm ? esc(x.cpm) : '<span class="muted">(no CPM)</span>'}</td>
          <td${chg(x, "keeps", "nowrap")}>${esc(x.keeps)}</td><td${chg(x, "description")}>${esc(x.description)}</td><td class="notes">${esc(x.issues)}</td></tr>`,
      },
      after() {
        document.querySelectorAll(".ps-mark").forEach(b => b.onclick = () => {
          $('[data-add="t-ps"]').click();
          const rows = document.querySelectorAll("#t-ps tr"), last = rows[rows.length - 1];
          $('[data-k="folder"]', last).value = b.dataset.folder;
          const block = $("#t-ps").closest("details"); if (block) block.open = true;
          b.disabled = true; DIRTY.main = true; syncSave();
          $("#t-ps").dispatchEvent(new Event("change", { bubbles: true }));   // the preview updates
        });
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
        this.previewed = (r) => {
          if (!$("#conv-folders").contains(document.activeElement)) renderFolderCodes(r.folder_codes || []);
          // How big the Safes come out: the account limit decides whether to add a part or split.
          const per = {}; (r.rows || []).forEach(x => { per[x.safe] = (per[x.safe] || 0) + x.accounts; });
          const sizes = Object.values(per).sort((a, b) => b - a), limit = Number($("#max-acc").value) || 0;
          const over = limit ? sizes.filter(n => n > limit).length : 0;
          $("#flat-size").innerHTML = sizes.length ? `With these settings: ${r.safes} Safes; the biggest holds ${sizes[0]} accounts${limit ? `, ${over ? `<b>${over} ${over === 1 ? "is" : "are"} over the ${limit} limit</b>: add a part, or pick "split them" above` : `none over the ${limit} limit`}` : ""}.` : "";
        };
        // The placeholder name follows the column picked (Site → site), unless you typed your own.
        const nameFor = (f) => f.startsWith("column:") ? f.slice(7).toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "").replace(/^(\d)/, "c$1") || "col"
          : f === "address_domain" ? "dom" : "rtype";
        let autoName = true;
        const syncName = () => { if (autoName && $("#flat-field").value) $("#flat-name").value = nameFor($("#flat-field").value); };
        $("#flat-field").addEventListener("change", syncName);
        $("#flat-name").addEventListener("input", () => { autoName = !$("#flat-name").value.trim(); });
        syncName();
        $("#flat-add").onclick = async () => {
          const field = $("#flat-field").value, name = $("#flat-name").value.trim().replace(/^\{|\}$/g, "");
          if (!field) return msg($("#flat-msg"), "err", "Load an accounts file first.");
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return msg($("#flat-msg"), "err", "Give the placeholder a name: letters, digits and _ only, for example site.");
          if (["folder", "folder_leaf", "type", "convention", "folder_abbrev"].includes(name)) return msg($("#flat-msg"), "err", `{${name}} is built in; pick another name.`);
          let r; try { r = await api("/api/rules/values", { field, config: { ...cfg, ...collect() } }); } catch (e) { return msg($("#flat-msg"), "err", e.message); }
          if (!r.values.length) return msg($("#flat-msg"), "warn", "No loaded account has a value there.");
          readLayers();
          const rows = r.values.map(v => ({ field: field === "address_domain" ? "address_domain" : field, pattern: "^" + reEsc(v.value) + "$", code: v.code }));
          const had = layers[name];
          // An existing placeholder ({env}) keeps its rows below the new ones: folders still count.
          layers[name] = { label: had ? had.label : field.startsWith("column:") ? field.slice(7) : name, default: had ? had.default : "",
            rules: rows.concat(had ? (had.rules || []).filter(x => x.field !== rows[0].field) : []) };
          renderLayers();
          const flatT = $("#conv-flat"), tag = `{${name}}`;
          if (!flatT.value.includes(tag)) {
            const t = flatT.value.trim() || "{env}-{tech}-{flavor}-{acct}";
            flatT.value = t.includes("{env}") ? t.replace("{env}", "{env}-" + tag) : tag + "-" + t;
          }
          $('[data-block="codes"]').open = true; $('[data-block="layers-all"]').open = true; const blk = $(`[data-block="layer-${name}"]`); if (blk) blk.open = true;
          const clashes = r.values.filter(v => v.clash).map(v => `${v.value} and ${v.clash} (${v.code})`);
          msg($("#flat-msg"), clashes.length || r.too_many ? "warn" : "ok",
            `{${name}} ${had ? "now also takes" : "takes"} its code from ${r.distinct} ${r.distinct === 1 ? "value" : "values"}${r.empty ? `; ${r.empty} accounts have none, so the part is left out of their Safe name` : ""}. ` +
            `The pattern for accounts with no folders is now ${flatT.value}. Check or change the codes under Codes used in names → {${name}}.` +
            (clashes.length ? ` Same code for different values: ${clashes.slice(0, 5).join(", ")}; give one of each its own code.` : "") +
            (r.too_many ? ` Only the first ${r.values.length} values were added: a column with this many values makes too many Safes.` : ""));
          flatT.dispatchEvent(new Event("input", { bubbles: true }));
          DIRTY.main = true; syncSave();
        };
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
  ({ config: cfg, presets, hints, standard_member_set: suggested }) => {
    const LEGACY = { owner: "Full", editor: "Accounts manager", user: "Read only", viewer: "List only" };
    let customRoles = Object.entries({ ...(cfg.role_permissions || {}), ...(cfg.custom_roles || {}) }).filter(([n]) => !presets[n])
      .map(([name, perms]) => ({ name, perms: new Set(perms) }));
    ROLE_NAMES = () => Object.keys(presets).concat(customRoles.map(r => r.name.trim()).filter(Boolean));
    const fixRole = (r) => r ? (LEGACY[String(r).toLowerCase()] && !customRoles.some(c => c.name === r) ? LEGACY[String(r).toLowerCase()] : r) : "";
    const PR = [{ key: "role", label: "Source permission word" }, { key: "to", label: "Privilege Cloud role", roles: true }];
    const std = cfg.standard_members || {}, stdRows = std.members || [];
    const noGrants = (hints.records || 0) > 0 && !(hints.with_grants || 0);
    const SM = [{ key: "name", label: "Member name", ph: "{safe}-Users", tip: SM_TIP.name },
                { key: "member_type", label: "Member type", options: MEMBER_TYPES, def: "Group", tip: SM_TIP.member_type },
                { key: "role", label: "Role", roles: true, tip: SM_TIP.role },
                { key: "search_in", label: "searchIn (optional)", ph: "empty = every directory", tip: SM_TIP.search_in }];
    const html = `<div class="card"><h3>Source permission → role <span class="muted small">(a member with several permissions on one Safe gets the strongest role)</span></h3>
        ${noGrants ? '<div class="msg warn">None of your loaded accounts has permissions (access groups), so this table has nothing to convert. Give the Safes members with <b>Standard member groups</b> below.</div>' : ""}
        ${editorTable("t-pr", PR, Object.entries(cfg.permission_map).map(([role, to]) => ({ role, to: fixRole(to) })), "+ Add row", !noGrants)}</div>
      <div class="card" id="std-card"><h3>Standard member groups for each Safe <span class="muted small">(for a plain accounts list with no permissions; empty unless you add rows)</span></h3>
        <p class="small">The same set of members on every Safe, each named after its Safe: <code>{safe}-Owners</code> on the Safe <code>P-BOS-SVR-WIN-LA</code> is the group
          <code>P-BOS-SVR-WIN-LA-Owners</code>. A row without <code>{safe}</code> (for example <code>PAM-Vault-Admins</code>) adds that one member to every Safe.
          Names then go through <b>C. Safe members</b> (domain conversion and directory sources) like any other member. The groups must exist in your directory
          before the upload: <b>Create upload files</b> (step 4) writes the list as <code>review/MemberGroups_To_Create.csv</code>.</p>
        <div class="row"><label class="inline">Add them to <select id="std-apply">${[["no_source_members", "Safes that get no members from the source (recommended)"],
            ["all", "every Safe, next to the source's members"], ["off", "no Safe (keep the rows, add nothing)"]].map(([v, l]) =>
            `<option value="${v}" ${(std.apply_to || "no_source_members") === v ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>
          <button class="btn small" id="std-suggest" title="Adds three rows you can change: {safe}-Owners (Full), {safe}-Users (Connect only) and {safe}-Approvers (Approver). Rows you already have stay.">Use the suggested set (${esc(suggested.map(r => r.name.replace("{safe}-", "")).join(", "))})</button></div>
        ${editorTable("t-std", SM, stdRows, "+ Add member", stdRows.length > 0 || noGrants)}
        <p class="muted small" id="std-example"></p></div>
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
          <th>SafeName</th><th>MemberName</th><th>MemberType</th><th title="The Privilege Cloud role: a preset or your custom role, from the table on this page. SafeMembers.csv gets it as True/False permission columns">role</th><th>Notes</th></tr>`,
        row: (x) => `<tr${(x.changed || []).includes("new") ? ` class="chg-row" title="New compared with what is saved"` : ""}><td>${x.standard ? `<span class="muted" title="Not in the export: added by your standard member groups">${esc(x.source)}</span>` : esc(x.source)}</td><td>${esc(x.permission)}</td>
          <td class="nowrap">${esc(x.safe)}</td><td${chg(x, "member_name")}>${esc(x.member_name)}</td><td${chg(x, "member_type")}>${esc(x.member_type)}</td>
          <td${chg(x, "role", "nowrap")}>${x.role === "UNMAPPED" ? '<span class="pill ERROR">no role</span>' : esc(x.role)}</td><td class="notes">${esc(x.notes)}</td></tr>`,
      },
      collect: () => ({
        standard_members: { apply_to: $("#std-apply").value, members: readTable("t-std").map(r => {
          if (!r.name) throw new Error("Every standard member group row needs a member name, for example {safe}-Users.");
          return { name: r.name, member_type: r.member_type || "Group", role: r.role || "", search_in: r.search_in || "" }; }) },
        permission_map: Object.fromEntries(readTable("t-pr").filter(r => r.role && r.to).map(r => [r.role, r.to])),
        custom_roles: Object.fromEntries(customRoles.map(r => [r.name.trim(), PERM_GROUPS.flatMap(g => g[1].map(p => p[0])).filter(p => r.perms.has(p))])),
        role_permissions: {},
      }),
      after() {
        renderRoles();
        // One Safe as the example: what each row's name pattern gives, and names to check.
        const example = () => {
          const safe = this.exampleSafe || "P-BOS-SVR-WIN-LA";
          const rows = readTable("t-std").filter(r => r.name);
          $("#std-example").innerHTML = !rows.length ? "" : `On the Safe <b>${esc(safe)}</b>: ` + rows.map(r => {
            const name = r.name.split("{safe}").join(safe), short = name.split("\\").pop().split("@")[0];
            const warn = (r.member_type || "Group") === "Group" && (short.length > 64 || /["/\[\]:;|=,+*?<>]/.test(short))
              ? ` <span class="pill REVIEW" title="Active Directory group names are at most 64 characters, without &quot; / [ ] : ; | = , + * ? &lt; &gt;">check the name</span>` : "";
            return `<code>${esc(name)}</code> (${esc(r.role || "no role yet")})${warn}`; }).join(", ") +
            ($("#std-apply").value === "off" ? ' · <span class="pill REVIEW">off: added to no Safe</span>' : "");
        };
        ["input", "change"].forEach(ev => $("#std-card").addEventListener(ev, example));
        $("#std-card").addEventListener("click", () => setTimeout(example, 0));
        this.previewed = (r) => { const x = (r.rows || []).find(y => y.standard) || (r.rows || [])[0]; if (x && x.safe !== this.exampleSafe) { this.exampleSafe = x.safe; example(); } };
        example();
        $("#std-suggest").onclick = () => {
          const have = new Set(readTable("t-std").map(r => (r.name || "").toLowerCase()));
          const t = $("#t-std");
          suggested.filter(r => !have.has(r.name.toLowerCase())).forEach(r => t.insertAdjacentHTML("beforeend", editorRow(SM, r)));
          updateBlockCount("t-std"); $('[data-block="t-std"]').open = true;
          if ($("#std-apply").value === "off") $("#std-apply").value = "no_source_members";
          DIRTY.main = true; syncSave(); example();
          t.dispatchEvent(new Event("change", { bubbles: true }));
        };
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

/* D. Platforms */
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
          <tr><th>Record type</th><th>Folders</th><th>Accounts</th><th title="The platform ID the accounts get">PlatformId</th>
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

/* E. Accounts */
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
          <p class="muted small" style="margin-left:24px">The <code>Name</code> column in Accounts.csv stays empty. Two accounts with the same platform, address and username in one Safe would get the same generated name, so the second is rejected. Accounts sharing a username and address are flagged as possible duplicates anyway, in any Safe.
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
          <tr><th>Name</th><th>Address</th><th>Username</th><th>SafeName</th><th>PlatformId</th>
          <th title="The account's name in its Safe; empty = Privilege Cloud names it">Name</th><th>Address</th>
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
      head: `<tr>${SRC_HEAD(2)}${CSV_HEAD(3, "Safes.csv")}</tr><tr><th>Folder</th><th>Accounts</th><th>SafeName</th><th>ManagingCPM</th><th>Keeps</th></tr>`,
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
  if (!STATE.has_db) return msg($("#main"), "warn", "Load your exports first (step 1).");
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
    <div class="floatbar"><button class="btn" data-go="review-safes">‹ Safes &amp; members</button><button class="btn primary" data-go="output">Next: Create upload files ›</button></div>`;
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
       ${sortTh(["target_safe", "SafeName"])}${sortTh(["platform_id", "PlatformId"])}${sortTh(["account_name", "Name"])}${sortTh(["address", "Address"])}${sortTh(["username", "UserName"])}<th>SecretType</th>
       ${showStatus ? sortTh(["status", "Status"]) : ""}<th>${whyLabel}</th></tr>`
    : `<tr><th><input type="checkbox" id="selall" title="Tick every account on this page"></th>
      ${cols.concat(showStatus ? [["status", "Status"]] : []).map(c => sortTh(c)).join("")}
      <th title="What is wrong with this account itself. Notes about its Safe (for example no access groups or a shortened Safe name) are on Safes &amp; members.">${whyLabel}</th></tr>`;
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
  if (!STATE.has_db) return msg($("#main"), "warn", "Load your exports first (step 1).");
  const d = await api("/api/safes");
  const und = STATE.undecided_all ? (await api("/api/undecided")).rows : [];
  DECIDE.rows = und;
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
  const tab = SAFES.tab === "decide" && !und.length ? "safes" : SAFES.tab || "safes";
  SAFES.tab = tab;
  const undOpen = und.filter(r => !r.decision).length;
  const csvMode = SAFES.mode === "csv";
  const safeLink = (s) => `<a href="#" data-members-of="${esc(s.safe_name)}" title="Rename this Safe, change its settings or its members">${esc(s.safe_name)}</a>${s.override_json ? ' <span class="pill REVIEW" title="You changed this Safe\'s name or settings directly">changed by you</span>' : ""}${nameNote(s)}`;
  const nameNote = (s) => s.valid_safe_name !== "TRUE"
    ? ` <span class="pill REVIEW" title="${esc(`The rules proposed ${s.proposed_names}: ${s.issues}`)}">name changed</span>`
    : s.issues ? ` <span class="pill REVIEW" title="${esc(s.issues)}">⚠</span>` : "";
  $("#main").innerHTML = `<h2>3. Review &amp; change · A. Safes &amp; members</h2>
    <p class="lead">The Safes the upload will create and who gets access. Click a Safe or a member to see and change it. To change how Safes are named or who gets access everywhere, use
      2. Mapping rules (<a href="#" data-go="rules-safes">Safes</a>, <a href="#" data-go="rules-members">permissions</a>, <a href="#" data-go="rules-dir">members</a>).${und.length ? ` Users who may get their access through a group wait under <a href="#" data-go="members-decide">Confirm user access</a>.` : ""}</p>
    ${safeEditsHtml(d)}${editsHtml}
    <div class="tabs" role="tablist"><button data-tab="safes" class="${tab === "safes" ? "on" : ""}" role="tab">Safes (${d.safes.length})</button>
      <button data-tab="members" class="${tab === "members" ? "on" : ""}" role="tab">Members (${d.people.length})</button>
      ${und.length ? `<button data-tab="decide" class="${tab === "decide" ? "on" : ""}" role="tab" title="Users from the folder report who may get their access through a group: add them as members or rely on the group">Confirm user access (${undOpen ? `${undOpen} to decide` : "all decided"})</button>` : ""}<label class="inline small${tab === "decide" ? " hidden" : ""}" id="s-cols" style="margin-left:auto;align-self:center" title="Review: the usual columns. Source → upload CSV: what the export had on the left, and the Safes.csv / SafeMembers.csv columns it becomes on the right.">Columns
      <select id="s-cols-mode"><option value="review">Review</option><option value="csv" ${csvMode ? "selected" : ""}>Source → upload CSV</option></select></label></div>
    <div id="tab-safes" class="${tab === "safes" ? "" : "hidden"}">
      ${noFullCount ? `<div class="msg warn">${noFullCount} ${noFullCount === 1 ? "Safe has" : "Safes have"} no member with full permissions, so nobody from your source could manage ${noFullCount === 1 ? "it" : "them"} or ${noFullCount === 1 ? "its" : "their"} members after the upload.
        Give one user, group or role the <b>Full</b> role: tick the Safes, then <b>Add to ticked Safes</b> with role Full; or map a source permission to Full in <a href="#" data-go="rules-members">2. Mapping rules · B. Safe permissions</a>.
        <label class="inline" style="margin-left:8px"><input type="checkbox" id="s-nofull" ${SAFES.nofull ? "checked" : ""}> show only these Safes</label></div>` : ""}
      <div class="row" style="margin-bottom:8px"><input type="search" id="s-filter" placeholder="Show Safes containing…" size="28" value="${esc(SAFES.filter)}">
        <button class="btn small" id="s-tick-shown">Tick the Safes shown</button>
        <span class="muted small" id="s-count"></span></div>
      <div class="tablewrap"><table id="safes-table">${csvMode ? `<thead><tr><th></th>${SRC_HEAD(2)}${CSV_HEAD(7, "Safes.csv")}<th class="grp" colspan="2"></th></tr>
        <tr><th></th><th title="The source folders whose accounts go to this Safe">Folders</th><th title="The name the rules gave, before cleanup or your rename">Rules proposed</th>
        <th>SafeName</th><th>ManagingCPM</th><th title="numberOfVersionsRetention or numberOfDaysRetention">Keeps</th><th>Description</th><th>Location</th><th>OlacEnabled</th><th>AutoPurgeEnabled</th>
        <th>Accounts</th><th>Members</th></tr></thead><tbody>` : `<tr><th></th><th>Safe</th><th>Accounts</th><th>To upload</th><th>Members</th><th>CPM</th><th>Keeps</th><th>Description</th></tr>`}
      ${d.safes.map(s => csvMode ? `<tr data-name="${esc((s.safe_name + " " + (s.source_folders || "")).toLowerCase())}"${noFull(s) ? ' data-nofull="1"' : ""}><td><input type="checkbox" class="s-sel" value="${esc(s.safe_name)}" ${SAFES.selected.has(s.safe_name) ? "checked" : ""}></td>
        <td class="small">${esc(s.source_folders || "").split(" | ").join("<br>")}</td><td class="small">${esc(s.proposed_names || "")}</td>
        <td class="nowrap">${safeLink(s)}</td><td class="small">${esc(s.managing_cpm || "")}</td><td class="small nowrap">${esc(s.retention || "")}</td><td class="small">${esc(s.description || "")}</td>
        <td class="small">${esc(s.location || "")}</td><td class="small">${esc(s.olac_enabled || "")}</td><td class="small">${esc(s.auto_purge || "")}</td>
        <td><a href="#" data-safe="${esc(s.safe_name)}" title="Show this Safe's accounts">${s.accounts}</a></td>
        <td class="nowrap">${membersCell(s)}</td></tr>`
        : `<tr data-name="${esc(s.safe_name.toLowerCase())}"${noFull(s) ? ' data-nofull="1"' : ""}><td><input type="checkbox" class="s-sel" value="${esc(s.safe_name)}" ${SAFES.selected.has(s.safe_name) ? "checked" : ""}></td>
        <td class="nowrap">${safeLink(s)}</td>
        <td><a href="#" data-safe="${esc(s.safe_name)}" title="Show this Safe's accounts">${s.accounts}</a></td><td>${s.accounts_to_upload}</td>
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
        <tr><th>Member in the export</th><th title="The permission the source gives (the strongest, when it has several)">Permission</th><th>SafeName</th><th>MemberName</th><th>MemberType</th><th>SearchIn</th><th>role</th><th>Accounts</th><th>Notes</th></tr></thead>
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
    ${und.length ? `<div id="tab-decide" class="${tab === "decide" ? "" : "hidden"}"></div>` : ""}
    <div class="floatbar"><button class="btn primary${tab === "decide" ? "" : " hidden"}" id="d-save" disabled>Decisions saved</button>
      <button class="btn${tab === "decide" ? "" : " primary"}" id="s-next" data-go="review">Next: Accounts ›</button></div>`;
  const showTab = () => {
    document.querySelectorAll("[data-tab]").forEach(x => x.classList.toggle("on", x.dataset.tab === SAFES.tab));
    ["safes", "members", "decide"].forEach(t => { const el = $("#tab-" + t); if (el) el.classList.toggle("hidden", SAFES.tab !== t); });
    $("#d-save").classList.toggle("hidden", SAFES.tab !== "decide"); $("#s-cols").classList.toggle("hidden", SAFES.tab === "decide"); $("#s-next").classList.toggle("primary", SAFES.tab !== "decide");
  };
  document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => { SAFES.tab = b.dataset.tab; showTab(); });
  if (und.length) drawDecide();
  $("#d-save").onclick = saveDecisions;
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
      <p class="muted small">Change this one Safe directly. What you set here wins over the rules in steps 3 and 4 and is kept when the rules or exports change.
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
  if (!STATE.has_db) return msg($("#main"), "warn", "Load your exports first (step 1).");
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
      <p class="small">The files go into <a class="pathlink" id="open-output" title="Open the output folder in Explorer"><code id="o-path">${esc(STATE.output)}</code></a>
        <button class="btn small" id="open-output2">Open folder</button>
        <button class="btn small" id="copy-output" title="Copy the folder path, to paste into File Explorer's address bar or a file dialog">Copy path</button></p>
      <p class="small" title="Each Safe name is split on the separator: column var1 lists every value used as the first part, var2 the second and so on ({var1}-{var2}-{var3}-{var4}). Personal Safes have their own pattern and are left out.">Also written: <code>review/SafeNamingConvention.csv</code>, the parts of every Safe name these files create, to keep naming new Safes the same way after the migration.</p>
      <button class="btn primary" id="extract">Create files</button><div id="out-msg"></div>
    </div>
    <div class="card"><h3>Earlier outputs in <a class="pathlink" id="open-output3" title="Open this folder in Explorer"><code>${esc(STATE.output)}</code></a>
      <button class="btn small" id="open-output4">Open folder</button>
      <button class="btn small" data-copy="${esc(STATE.output)}" title="Copy the folder path, to paste into File Explorer's address bar or a file dialog">Copy path</button></h3>
      ${STATE.outputs.length ? `<table><tr><th>Name</th><th>Created</th><th>Accounts</th><th>Secrets</th><th></th></tr>
        ${STATE.outputs.map(o => `<tr><td><a class="pathlink" data-open-out="${esc(o.name)}" title="Open this folder in Explorer">${esc(o.name)}</a></td><td>${esc(o.created)}</td><td>${o.counts.accounts ?? ""}</td>
          <td>${o.secrets && o.has_upload ? '<span class="pill ERROR">plaintext</span>' : o.secrets ? "deleted" : "none"}</td>
          <td>${o.has_upload ? `<button class="btn danger" data-del="${esc(o.name)}">Securely delete upload files</button>` : ""}</td></tr>`).join("")}</table>` : '<p class="muted">None yet.</p>'}</div>`;
  if (LAST_OUT) { $("#out-msg").innerHTML = LAST_OUT; LAST_OUT = ""; }
  wireTiles();
  // Clickable paths, as on the Load page: the output folder, or one output inside it.
  const openOutput = async (name) => {
    try {
      const r = await api("/api/open", name ? { which: "output", name } : { which: "output" });
      if (!r.opened) alert("Open this folder yourself: " + r.path);
    } catch (e) { msg($("#out-msg"), "err", e.message); }
  };
  ["#open-output", "#open-output2", "#open-output3", "#open-output4"].forEach(id => $(id).onclick = () => openOutput());
  document.querySelectorAll("[data-open-out]").forEach(a => a.onclick = () => openOutput(a.dataset.openOut));
  const sep = STATE.output.includes("\\") ? "\\" : "/";
  const showPath = () => { const n = $("#o-name").value.trim(); $("#o-path").textContent = n ? STATE.output + sep + n : STATE.output; };
  $("#copy-output").onclick = () => copyText($("#copy-output"), $("#o-path").textContent);
  wireCopy($("#main"));
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
    showPath();
  };
  $("#o-name").addEventListener("input", () => { typed = !!$("#o-name").value.trim(); showPath(); });
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
        Folder: <a class="pathlink" data-open-out="${esc(r.name)}" title="Open this folder in Explorer"><code>${esc(r.path)}</code></a>
        <button class="btn small" data-copy="${esc(r.path)}" title="Copy the folder path">Copy path</button><br>${r.files.map(esc).join(" · ")}
        ${r.files.some(f => /SafeNamingConvention\.csv$/.test(f)) ? `<br>The Safe naming convention is in <code>review/SafeNamingConvention.csv</code>.` : ""}</div>`;
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
};

// CSV downloads (activity log, account changes, Safe naming convention): fetched by the page
// itself, then saved, which works the same with a self-signed certificate.
document.addEventListener("click", async (e) => {
  const a = e.target.closest && e.target.closest("[data-export]");
  if (!a) return;
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
