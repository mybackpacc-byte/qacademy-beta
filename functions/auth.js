// functions/auth.js
// Auth, join, profile, and school-switching routes

import { createHelpers } from "./shared.js";

export async function handleAuthRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    if (!env.DB) {
      const { page } = createHelpers(request, env);
      return page(`
        <div class="card err">
          <h1>DB not connected</h1>
          <p class="muted">Your Pages project does not have the D1 binding set.</p>
          <p class="muted">Fix: Pages → Settings → Functions → D1 bindings → add <b>DB</b> → select <b>beta_db</b> (for Production + Preview).</p>
        </div>
      `, 500);
    }

    const {
      PEPPER, nowISO, uuid,
      page, redirect, escapeHtml, escapeAttr, roleLabel, fmtISO, form,
      randomSaltHex, pbkdf2Hex, sha256Hex,
      cookieGet, cookieSet, cookieClear,
      first, all, run,
      loadAuth, requireLogin, pickActiveMembership,
      setActiveTenantForCurrentSession, createSessionForUser,
    } = createHelpers(request, env);

    // =============================
    // Constants
    // =============================
    const JOIN_CODE_DEFAULT_EXP_DAYS = 14;
    const JOIN_CODE_DEFAULT_MAX_USES = 300;
    const ALLOW_SCHOOL_ADMIN_JOIN_CODES = false;
    const JOIN_PREVENT_TEACHER_DEMOTION_ON_STUDENT_CODES = true;

    // =============================
    // Join code helpers
    // =============================
    const CODE_ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    function makeJoinCodePlain() {
      const rnd = (n) => {
        let s = "";
        const a = new Uint8Array(n);
        crypto.getRandomValues(a);
        for (let i = 0; i < n; i++) s += CODE_ALPH[a[i] % CODE_ALPH.length];
        return s;
      };
      return `${rnd(4)}-${rnd(4)}`;
    }

    async function joinCodeHash(codePlain) {
      return await sha256Hex(`${codePlain}|${PEPPER}|JOINCODE`);
    }

    function isIsoInPast(iso) {
      if (!iso) return false;
      const t = Date.parse(iso);
      if (Number.isNaN(t)) return false;
      return t < Date.now();
    }

    function scopeLabel(scope) {
      if (scope === "TENANT_ROLE") return "School access";
      if (scope === "COURSE_ENROLL") return "Course enrol";
      if (scope === "COURSE_TEACHER") return "Course teacher";
      return scope || "";
    }

    function requestTypeFromScope(scope) {
      if (scope === "TENANT_ROLE") return "MEMBERSHIP";
      if (scope === "COURSE_ENROLL") return "COURSE_ENROLL";
      if (scope === "COURSE_TEACHER") return "COURSE_TEACHER";
      return "MEMBERSHIP";
    }

    async function loadJoinCodeByPlain(codePlain) {
      const h = await joinCodeHash(codePlain);
      const jc = await first(
        `SELECT jc.*, t.name AS tenant_name, c.title AS course_title
         FROM join_codes jc
         JOIN tenants t ON t.id = jc.tenant_id
         LEFT JOIN courses c ON c.id = jc.course_id
         WHERE jc.code_hash=?`,
        [h]
      );
      return jc || null;
    }

    function joinCodeIsValid(jc) {
      if (!jc) return { ok: false, why: "Invalid code." };
      if (Number(jc.revoked) === 1) return { ok: false, why: "This code was revoked." };
      if (isIsoInPast(jc.expires_at)) return { ok: false, why: "This code has expired." };
      if (Number(jc.uses_approved) >= Number(jc.max_uses)) return { ok: false, why: "This code has reached its maximum uses." };
      return { ok: true, why: "" };
    }

    async function reserveJoinCodeUse(joinCodeId) {
      const ts = nowISO();
      const res = await run(
        `UPDATE join_codes
         SET uses_approved = uses_approved + 1, updated_at=?
         WHERE id=? AND revoked=0 AND uses_approved < max_uses AND expires_at > ?`,
        [ts, joinCodeId, ts]
      );
      return Number(res?.meta?.changes || 0) > 0;
    }

    async function unreserveJoinCodeUse(joinCodeId) {
      await run(
        `UPDATE join_codes
         SET uses_approved = CASE WHEN uses_approved>0 THEN uses_approved-1 ELSE 0 END, updated_at=?
         WHERE id=?`,
        [nowISO(), joinCodeId]
      );
    }

    async function ensureMembership(tenantId, userId, roleWanted) {
      const m = await first(
        "SELECT id, role, status FROM memberships WHERE tenant_id=? AND user_id=? ORDER BY created_at ASC LIMIT 1",
        [tenantId, userId]
      );
      const ts = nowISO();
      if (!m) {
        const mid = uuid();
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [mid, userId, tenantId, roleWanted, ts, ts]
        );
        return { created: true, updated: false, role: roleWanted };
      }
      if (m.status !== "ACTIVE") {
        await run("UPDATE memberships SET status='ACTIVE', role=?, updated_at=? WHERE id=?", [roleWanted, ts, m.id]);
        return { created: false, updated: true, role: roleWanted };
      }
      if (m.role !== roleWanted) {
        await run("UPDATE memberships SET role=?, updated_at=? WHERE id=?", [roleWanted, ts, m.id]);
        return { created: false, updated: true, role: roleWanted };
      }
      return { created: false, updated: false, role: m.role };
    }

    async function applyJoinActionForUser(userId, jc) {
      if (jc.scope === "COURSE_ENROLL" || jc.scope === "COURSE_TEACHER") {
        if (!jc.course_id) return { ok: false, msg: "Code is missing course binding." };
        const c = await first("SELECT id, tenant_id, status FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [
          jc.course_id, jc.tenant_id,
        ]);
        if (!c) return { ok: false, msg: "Course not found or inactive." };
      }

      const m = await first(
        "SELECT id, role, status FROM memberships WHERE tenant_id=? AND user_id=? ORDER BY created_at ASC LIMIT 1",
        [jc.tenant_id, userId]
      );
      const curRole = m && m.status === "ACTIVE" ? m.role : null;

      if (
        JOIN_PREVENT_TEACHER_DEMOTION_ON_STUDENT_CODES &&
        curRole === "TEACHER" &&
        jc.role === "STUDENT" &&
        (jc.scope === "TENANT_ROLE" || jc.scope === "COURSE_ENROLL")
      ) {
        return { ok: false, msg: "This code is for students. Ask the School Admin for the correct code." };
      }

      if (jc.scope === "TENANT_ROLE") {
        if (!ALLOW_SCHOOL_ADMIN_JOIN_CODES && jc.role === "SCHOOL_ADMIN") {
          return { ok: false, msg: "School Admin join codes are disabled." };
        }
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : jc.role;
        await ensureMembership(jc.tenant_id, userId, roleToSet);
        return { ok: true, msg: `School access updated: ${roleLabel(roleToSet)}.` };
      }

      if (jc.scope === "COURSE_ENROLL") {
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : "STUDENT";
        if (!curRole) {
          await ensureMembership(jc.tenant_id, userId, roleToSet);
        } else if (curRole !== "SCHOOL_ADMIN" && curRole !== "STUDENT") {
          await ensureMembership(jc.tenant_id, userId, "STUDENT");
        }
        const ex = await first("SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=? LIMIT 1", [jc.course_id, userId]);
        if (!ex) {
          await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [jc.course_id, userId, nowISO()]);
        }
        return { ok: true, msg: `Enrolled into course: ${jc.course_title || "Course"}.` };
      }

      if (jc.scope === "COURSE_TEACHER") {
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : "TEACHER";
        if (!curRole) {
          await ensureMembership(jc.tenant_id, userId, roleToSet);
        } else if (curRole !== "SCHOOL_ADMIN" && curRole !== "TEACHER") {
          await ensureMembership(jc.tenant_id, userId, "TEACHER");
        }
        const ex = await first("SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1", [jc.course_id, userId]);
        if (!ex) {
          await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [jc.course_id, userId, nowISO()]);
        }
        return { ok: true, msg: `Assigned as teacher for: ${jc.course_title || "Course"}.` };
      }

      return { ok: false, msg: "Unknown join code scope." };
    }

    // =============================
    // Routes
    // =============================

    if (path === "/health") {
      const row = await first("SELECT COUNT(*) AS n FROM users", []);
      return page(`<div class="card"><h1>OK</h1><p class="muted">Users count: ${escapeHtml(row?.n ?? 0)}</p></div>`);
    }

    if (path === "/") {
      const a = await loadAuth();
      if (!a.user) return redirect("/login");
      if (Number(a.user.is_system_admin) === 1) return redirect("/sys");
      if (!a.memberships.length) return redirect("/no-access");

      const active = pickActiveMembership(a);
      if (!active) {
        if (a.memberships.length === 1)
          return redirect(`/switch-school?tenant_id=${encodeURIComponent(a.memberships[0].tenant_id)}`);
        return redirect("/choose-school");
      }

      if (active.role === "SCHOOL_ADMIN") return redirect("/school");
      if (active.role === "TEACHER") return redirect("/teacher");
      if (active.role === "STUDENT") return redirect("/student");
      return redirect("/no-access");
    }

    if (path === "/no-access") {
      return page(`
        <div class="card">
          <h1>No access</h1>
          <p class="muted">Your account has no active school access yet.</p>
          <p class="muted">If you have a join code, go to <a href="/join">/join</a>.</p>
          <p><a href="/logout">Logout</a></p>
        </div>
      `);
    }

    // Setup (only if zero users exist)
    if (path === "/setup") {
      const countRow = await first("SELECT COUNT(*) AS n FROM users", []);
      const n = Number(countRow?.n || 0);

      if (request.method === "GET") {
        if (n > 0) {
          return page(`<div class="card"><h1>Setup already done</h1><p><a href="/login">Go to login</a></p></div>`);
        }
        return page(`
          <div class="card">
            <h1>First-time Setup</h1>
            <p class="muted">Create the System Admin account (only once).</p>
            <form method="post" action="/setup">
              <label>Full name</label><input name="name" required />
              <label>Email</label><input name="email" type="email" required />
              <label>Password (6+ characters)</label><input name="password" type="password" required />
              <button type="submit">Create System Admin</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        if (n > 0) return redirect("/login");
        const f = await form();
        const name = (f.name || "");
        const email = (f.email || "").toLowerCase();
        const password = (f.password || "");

        if (!name || !email || password.length < 6) {
          return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/setup">Back</a></p>`, 400);
        }

        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(password + "|" + PEPPER, saltHex, iter);
        const id = uuid();
        const ts = nowISO();

        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,1,'ACTIVE',?,?)",
          [id, email, name, saltHex, hashHex, iter, ts, ts]
        );

        return page(`<div class="card ok"><h1>System Admin created</h1><p><a href="/login">Go to login</a></p></div>`);
      }
    }

    // Login
    if (path === "/login") {
      if (request.method === "GET") {
        return page(`
          <div class="card">
            <h1>Login</h1>
            <form method="post" action="/login">
              <label>Email</label><input name="email" type="email" required />
              <label>Password</label><input name="password" type="password" required />
              <button type="submit">Login</button>
            </form>
            <p class="muted">Have a join code? Go to <a href="/join">/join</a>.</p>
            <p class="muted">First time? Go to <a href="/setup">/setup</a>.</p>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const email = (f.email || "").toLowerCase();
        const password = (f.password || "");

        const u = await first(
          "SELECT id,email,name,password_salt,password_hash,password_iter,is_system_admin FROM users WHERE email=? AND status='ACTIVE'",
          [email]
        );
        if (!u) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);

        const check = await pbkdf2Hex(password + "|" + PEPPER, u.password_salt, Number(u.password_iter));
        if (check !== u.password_hash) {
          return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);
        }

        const token = uuid() + "-" + uuid();
        const tokenHash = await sha256Hex(token);
        const ts = nowISO();
        const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString();

        await run(
          "INSERT INTO sessions (token_hash,user_id,active_tenant_id,expires_at,created_at) VALUES (?,?,?,?,?)",
          [tokenHash, u.id, null, expires, ts]
        );

        const headers = { "Set-Cookie": cookieSet("qa_sess", token, 60 * 60 * 24 * 7) };

        if (Number(u.is_system_admin) === 1) return redirect("/sys", headers);

        const mems = await all(
          `SELECT m.tenant_id, m.role, t.name AS tenant_name
           FROM memberships m
           JOIN tenants t ON t.id = m.tenant_id
           WHERE m.user_id=? AND m.status='ACTIVE' AND t.status='ACTIVE'
           ORDER BY t.name ASC`,
          [u.id]
        );

        if (!mems.length) return redirect("/no-access", headers);

        if (mems.length === 1) {
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [mems[0].tenant_id, tokenHash]);
          if (mems[0].role === "SCHOOL_ADMIN") return redirect("/school", headers);
          if (mems[0].role === "TEACHER") return redirect("/teacher", headers);
          if (mems[0].role === "STUDENT") return redirect("/student", headers);
          return redirect("/no-access", headers);
        }

        return redirect("/choose-school", headers);
      }
    }

    // Logout
    if (path === "/logout") {
      const token = cookieGet("qa_sess");
      if (token) {
        const tokenHash = await sha256Hex(token);
        await run("DELETE FROM sessions WHERE token_hash=?", [tokenHash]);
      }
      return redirect("/login", { "Set-Cookie": cookieClear("qa_sess") });
    }

    // Choose school
    if (path === "/choose-school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");
      if (!r.memberships.length) return redirect("/no-access");
      if (r.memberships.length === 1) {
        return redirect(`/switch-school?tenant_id=${encodeURIComponent(r.memberships[0].tenant_id)}`);
      }

      const activeNow = pickActiveMembership(r);
      const activeId = activeNow ? activeNow.tenant_id : null;

      const cards = r.memberships.map((m) => {
        const isCurrent = activeId && m.tenant_id === activeId;
        return `
          <div class="card">
            <div class="topbar">
              <div>
                <div><b>${escapeHtml(m.tenant_name)}</b></div>
                <div class="muted">
                  Role: <span class="pill">${escapeHtml(roleLabel(m.role))}</span>
                  ${isCurrent ? `<span class="pill">Current</span>` : ``}
                </div>
              </div>
              <form method="post" action="/switch-school">
                <input type="hidden" name="tenant_id" value="${escapeAttr(m.tenant_id)}"/>
                <button type="submit">${isCurrent ? "Open" : "Switch"}</button>
              </form>
            </div>
          </div>
        `;
      }).join("");

      return page(`
        <div class="card">
          <h1>Choose School</h1>
          <p class="muted">Select which school you want to use right now.</p>
        </div>
        ${cards}
        <p class="actions"><a href="/profile">Profile</a> <a href="/logout">Logout</a></p>
      `);
    }

    // Switch school
    if (path === "/switch-school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      let tenantId = url.searchParams.get("tenant_id") || "";
      if (request.method === "POST") {
        const f = await form();
        tenantId = (f.tenant_id || tenantId).trim();
      }

      const membership = r.memberships.find((m) => m.tenant_id === tenantId);
      if (!membership) return redirect("/choose-school");

      await setActiveTenantForCurrentSession(tenantId);
      return redirect("/");
    }

    // =============================
    // Public Join
    // =============================
    if (path === "/join") {
      const a = await loadAuth();
      const isLoggedIn = !!a.user;

      if (request.method === "GET") {
        return page(`
          <div class="card">
            <div class="topbar">
              <h1>Join a school or course</h1>
              <div class="actions">
                ${isLoggedIn ? `<a href="/">Dashboard</a>` : `<a href="/login">Login</a>`}
              </div>
            </div>
            <p class="muted">Enter your join code. You can join a school role or a specific course.</p>
            <form method="post" action="/join">
              <label>Join code</label>
              <input name="code" placeholder="ABCD-EFGH" required />
              <button type="submit">Continue</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
        if (!codePlain) return redirect("/join");

        const jc = await loadJoinCodeByPlain(codePlain);
        const v = joinCodeIsValid(jc);
        if (!v.ok) {
          return page(`<div class="card err"><b>${escapeHtml(v.why)}</b></div><p><a href="/join">Back</a></p>`, 400);
        }

        if (isLoggedIn) {
          if (Number(jc.auto_approve) === 1) {
            const reserved = await reserveJoinCodeUse(jc.id);
            if (!reserved) {
              return page(`<div class="card err"><b>Code is no longer available (expired/used up/revoked).</b></div><p><a href="/join">Back</a></p>`, 400);
            }
            const applied = await applyJoinActionForUser(a.user.id, jc);
            if (!applied.ok) {
              await unreserveJoinCodeUse(jc.id);
              return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
            }
            await setActiveTenantForCurrentSession(jc.tenant_id);
            return page(`
              <div class="card ok">
                <h1>Joined</h1>
                <p class="muted">${escapeHtml(applied.msg)}</p>
                <p class="actions"><a href="/">Go to dashboard</a> <a href="/join">Join another</a></p>
              </div>
            `);
          }

          const exists = await first(
            `SELECT id FROM join_requests WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
            [jc.id, a.user.id]
          );
          if (!exists) {
            await run(
              `INSERT INTO join_requests (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
               VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
              [uuid(), jc.id, jc.tenant_id, jc.course_id || null, a.user.id, requestTypeFromScope(jc.scope), jc.role, nowISO()]
            );
          }
          return page(`
            <div class="card ok">
              <h1>Request sent</h1>
              <p class="muted">School: <b>${escapeHtml(jc.tenant_name)}</b></p>
              <p class="muted">A School Admin must approve this request.</p>
              <p class="actions"><a href="/">Back</a> <a href="/join">Join another</a></p>
            </div>
          `);
        }

        return page(`
          <div class="card">
            <h1>Join preview</h1>
            <p class="muted">School: <b>${escapeHtml(jc.tenant_name)}</b></p>
            <p class="muted">Action: <b>${escapeHtml(scopeLabel(jc.scope))}</b> • Role: <b>${escapeHtml(roleLabel(jc.role))}</b>${jc.course_title ? ` • Course: <b>${escapeHtml(jc.course_title)}</b>` : ""}</p>
            <p class="muted">Expires: ${escapeHtml(fmtISO(jc.expires_at))} • Uses: ${escapeHtml(jc.uses_approved)}/${escapeHtml(jc.max_uses)} • Auto-approve: ${Number(jc.auto_approve) === 1 ? "Yes" : "No"}</p>
          </div>

          <div class="row">
            <div class="card">
              <h2>Login</h2>
              <form method="post" action="/join-login">
                <input type="hidden" name="code" value="${escapeAttr(codePlain)}"/>
                <label>Email</label><input name="email" type="email" required />
                <label>Password</label><input name="password" type="password" required />
                <button type="submit">Login & join</button>
              </form>
            </div>
            <div class="card">
              <h2>Create account</h2>
              <form method="post" action="/join-create-account">
                <input type="hidden" name="code" value="${escapeAttr(codePlain)}"/>
                <label>Full name</label><input name="name" required />
                <label>Email</label><input name="email" type="email" required />
                <label>Password (6+ characters)</label><input name="password" type="password" required />
                <button type="submit">Create & join</button>
              </form>
            </div>
          </div>
          <p><a href="/join">Back</a></p>
        `);
      }
    }

    if (path === "/join-login" && request.method === "POST") {
      const f = await form();
      const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
      const email = (f.email || "").toLowerCase();
      const password = (f.password || "");

      const jc = await loadJoinCodeByPlain(codePlain);
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>${escapeHtml(v.why)}</b></div><p><a href="/join">Back</a></p>`, 400);

      const u = await first(
        "SELECT id,email,name,password_salt,password_hash,password_iter,is_system_admin FROM users WHERE email=? AND status='ACTIVE'",
        [email]
      );
      if (!u) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/join">Back</a></p>`, 401);

      const check = await pbkdf2Hex(password + "|" + PEPPER, u.password_salt, Number(u.password_iter));
      if (check !== u.password_hash) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/join">Back</a></p>`, 401);

      const s = await createSessionForUser(u.id);

      if (Number(jc.auto_approve) === 1) {
        const reserved = await reserveJoinCodeUse(jc.id);
        if (!reserved) return page(`<div class="card err"><b>Code is no longer available.</b></div><p><a href="/join">Back</a></p>`, 400);
        const applied = await applyJoinActionForUser(u.id, jc);
        if (!applied.ok) {
          await unreserveJoinCodeUse(jc.id);
          return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
        }
        await (async () => {
          const tokenHash = await sha256Hex(s.token);
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [jc.tenant_id, tokenHash]);
        })();
        return redirect("/", s.headers);
      }

      const exists = await first(
        `SELECT id FROM join_requests WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
        [jc.id, u.id]
      );
      if (!exists) {
        await run(
          `INSERT INTO join_requests (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
           VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
          [uuid(), jc.id, jc.tenant_id, jc.course_id || null, u.id, requestTypeFromScope(jc.scope), jc.role, nowISO()]
        );
      }
      return page(
        `<div class="card ok"><h1>Request sent</h1><p class="muted">A School Admin must approve this request.</p><p class="actions"><a href="/">Continue</a></p></div>`,
        200, s.headers
      );
    }

    if (path === "/join-create-account" && request.method === "POST") {
      const f = await form();
      const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
      const name = (f.name || "");
      const email = (f.email || "").toLowerCase();
      const password = (f.password || "");

      const jc = await loadJoinCodeByPlain(codePlain);
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>${escapeHtml(v.why)}</b></div><p><a href="/join">Back</a></p>`, 400);

      if (!name || !email || password.length < 6) {
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/join">Back</a></p>`, 400);
      }

      const ts = nowISO();
      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(password + "|" + PEPPER, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, email, name, saltHex, hashHex, iter, ts, ts]
        );
      }

      const s = await createSessionForUser(userId);

      if (Number(jc.auto_approve) === 1) {
        const reserved = await reserveJoinCodeUse(jc.id);
        if (!reserved) return page(`<div class="card err"><b>Code is no longer available.</b></div><p><a href="/join">Back</a></p>`, 400);
        const applied = await applyJoinActionForUser(userId, jc);
        if (!applied.ok) {
          await unreserveJoinCodeUse(jc.id);
          return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
        }
        await (async () => {
          const tokenHash = await sha256Hex(s.token);
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [jc.tenant_id, tokenHash]);
        })();
        return redirect("/", s.headers);
      }

      const exists = await first(
        `SELECT id FROM join_requests WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
        [jc.id, userId]
      );
      if (!exists) {
        await run(
          `INSERT INTO join_requests (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
           VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
          [uuid(), jc.id, jc.tenant_id, jc.course_id || null, userId, requestTypeFromScope(jc.scope), jc.role, nowISO()]
        );
      }
      return page(
        `<div class="card ok"><h1>Request sent</h1><p class="muted">A School Admin must approve this request.</p><p class="actions"><a href="/">Continue</a></p></div>`,
        200, s.headers
      );
    }

    // =============================
    // Profile
    // =============================
    if (path === "/profile") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      if (request.method === "GET") {
        const mems = r.memberships || [];
        const rows = mems.map((m) =>
          `<li><b>${escapeHtml(m.tenant_name)}</b> — <span class="pill">${escapeHtml(roleLabel(m.role))}</span></li>`
        ).join("");

        return page(`
          <div class="card">
            <div class="topbar">
              <h1>Profile</h1>
              <div class="actions"><a href="/">Dashboard</a><a href="/logout">Logout</a></div>
            </div>
            <p class="muted"><b>${escapeHtml(r.user.name)}</b> — ${escapeHtml(r.user.email)}</p>
            ${Number(r.user.is_system_admin) === 1 ? `<p><span class="pill">System Admin</span></p>` : ""}
          </div>
          <div class="card">
            <h2>My schools</h2>
            <ul>${rows || "<li class='muted'>None</li>"}</ul>
          </div>
          <div class="card">
            <h2>Change password</h2>
            <form method="post" action="/profile">
              <label>Current password</label><input name="old_password" type="password" required />
              <label>New password (6+ characters)</label><input name="new_password" type="password" required />
              <label>Confirm new password</label><input name="new_password2" type="password" required />
              <button type="submit">Update password</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const oldPw = f.old_password || "";
        const newPw = f.new_password || "";
        const newPw2 = f.new_password2 || "";

        if (newPw.length < 6) return page(`<div class="card err"><b>New password must be 6+ characters.</b></div><p><a href="/profile">Back</a></p>`, 400);
        if (newPw !== newPw2) return page(`<div class="card err"><b>Passwords do not match.</b></div><p><a href="/profile">Back</a></p>`, 400);

        const u = await first("SELECT id,password_salt,password_hash,password_iter FROM users WHERE id=? AND status='ACTIVE'", [r.user.id]);
        if (!u) return redirect("/logout");

        const check = await pbkdf2Hex(oldPw + "|" + PEPPER, u.password_salt, Number(u.password_iter));
        if (check !== u.password_hash) {
          return page(`<div class="card err"><b>Current password is incorrect.</b></div><p><a href="/profile">Back</a></p>`, 401);
        }

        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(newPw + "|" + PEPPER, saltHex, iter);
        await run("UPDATE users SET password_salt=?, password_hash=?, password_iter=?, updated_at=? WHERE id=?", [
          saltHex, hashHex, iter, nowISO(), r.user.id,
        ]);
        return page(`<div class="card ok"><h1>Password updated</h1><p class="actions"><a href="/">Back to dashboard</a></p></div>`);
      }
    }

    return page(`
      <div class="card">
        <h1>Not found</h1>
        <p class="muted">Try <a href="/setup">/setup</a> or <a href="/login">/login</a>.</p>
        <p class="muted">Have a join code? Try <a href="/join">/join</a>.</p>
      </div>
    `, 404);

  } catch (err) {
    console.error("FATAL", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR:\n\n" + msg, { status: 500 });
  }
}
