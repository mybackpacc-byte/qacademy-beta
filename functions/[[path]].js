export async function onRequest(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;

  // Small helpers
  const nowISO = () => new Date().toISOString();
  const uuid = () => crypto.randomUUID();

  const html = (body, status = 200, extraHeaders = {}) =>
    new Response(`<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Beta</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f8f7;color:#1f2a28}
  .wrap{max-width:920px;margin:0 auto;padding:18px}
  .card{background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:14px;padding:16px;margin:12px 0}
  h1{font-size:20px;margin:0 0 8px}
  h2{font-size:16px;margin:14px 0 8px}
  label{display:block;font-size:13px;margin:10px 0 6px}
  input,select{width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px}
  button{padding:10px 14px;border:0;border-radius:10px;background:#0b7a75;color:#fff;font-weight:700;cursor:pointer}
  .muted{color:rgba(0,0,0,.6);font-size:13px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:720px){.row{grid-template-columns:1fr}}
  .topbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin:6px 0 10px}
  a{color:#0b7a75;text-decoration:none}
  .pill{display:inline-block;padding:5px 10px;border-radius:999px;background:rgba(11,122,117,.10);color:#0b7a75;font-weight:700;font-size:12px}
  .err{background:#fff3f3;border:1px solid rgba(255,0,0,.18);padding:10px;border-radius:10px}
  .ok{background:#f0fff8;border:1px solid rgba(0,200,120,.18);padding:10px;border-radius:10px}
  .btn2{background:#1f2a28}
</style>
</head><body><div class="wrap">${body}</div></body></html>`, {
      status,
      headers: { "content-type": "text/html; charset=utf-8", ...extraHeaders },
    });

  const redirect = (to, headers = {}) =>
    new Response(null, { status: 302, headers: { Location: to, ...headers } });

  const parseForm = async () => {
    const ct = request.headers.get("content-type") || "";
    if (!ct.includes("application/x-www-form-urlencoded")) return {};
    const text = await request.text();
    const params = new URLSearchParams(text);
    const obj = {};
    for (const [k, v] of params.entries()) obj[k] = v.trim();
    return obj;
  };

  // Base64 helpers (URL-safe not needed here)
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;

  const sha256Hex = async (text) => {
    const data = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  };

  const pbkdf2Hash = async (password, saltB64, iterations) => {
    const salt = unb64(saltB64);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      256
    );
    return b64(bits);
  };

  const newSaltB64 = () => {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return b64(arr.buffer);
  };

  const cookieGet = (name) => {
    const raw = request.headers.get("Cookie") || "";
    const parts = raw.split(";").map(s => s.trim());
    for (const p of parts) {
      const i = p.indexOf("=");
      if (i < 0) continue;
      const k = p.slice(0, i);
      const v = p.slice(i + 1);
      if (k === name) return decodeURIComponent(v);
    }
    return null;
  };

  const cookieSet = (name, value, opts = {}) => {
    const base = `${name}=${encodeURIComponent(value)}`;
    const bits = [base, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
    if (opts.maxAge) bits.push(`Max-Age=${opts.maxAge}`);
    return bits.join("; ");
  };

  const cookieClear = (name) => `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

  // DB helpers
  const q1 = async (sql, params = []) => {
    const res = await env.DB.prepare(sql).bind(...params).all();
    return res.results[0] || null;
  };
  const qAll = async (sql, params = []) => {
    const res = await env.DB.prepare(sql).bind(...params).all();
    return res.results || [];
  };
  const exec = async (sql, params = []) => {
    await env.DB.prepare(sql).bind(...params).run();
  };

  // Load session + user (if logged in)
  const loadAuth = async () => {
    const sid = cookieGet("qa_sess");
    if (!sid) return { user: null, session: null, memberships: [] };

    const sh = await sha256Hex(sid);
    const session = await q1(
      "SELECT session_hash, user_id, active_tenant_id, expires_at FROM sessions WHERE session_hash=?",
      [sh]
    );
    if (!session) return { user: null, session: null, memberships: [] };

    if (new Date(session.expires_at).getTime() < Date.now()) {
      await exec("DELETE FROM sessions WHERE session_hash=?", [sh]);
      return { user: null, session: null, memberships: [] };
    }

    const user = await q1(
      "SELECT id, email, name, is_system_admin FROM users WHERE id=? AND status='ACTIVE'",
      [session.user_id]
    );
    if (!user) return { user: null, session: null, memberships: [] };

    const memberships = await qAll(
      `SELECT m.tenant_id, m.role, t.name AS tenant_name
       FROM memberships m
       JOIN tenants t ON t.id = m.tenant_id
       WHERE m.user_id=? AND m.status='ACTIVE' AND t.status='ACTIVE'
       ORDER BY t.name ASC`,
      [user.id]
    );

    return { user, session, memberships };
  };

  const requireLogin = async () => {
    const auth = await loadAuth();
    if (!auth.user) return { ok: false, res: redirect("/login") };
    return { ok: true, ...auth };
  };

  const pickActiveTenant = (auth) => {
    const activeId = auth.session?.active_tenant_id || null;
    if (!activeId) return null;
    return auth.memberships.find(m => m.tenant_id === activeId) || null;
  };

  const dashboardRedirectFor = (auth) => {
    if (auth.user.is_system_admin) return "/sys";
    if (!auth.memberships.length) return "/no-access";

    const active = pickActiveTenant(auth);
    if (!active) {
      if (auth.memberships.length === 1) return `/switch-school?tenant_id=${encodeURIComponent(auth.memberships[0].tenant_id)}`;
      return "/choose-school";
    }

    if (active.role === "SCHOOL_ADMIN") return "/school";
    if (active.role === "TEACHER") return "/teacher";
    if (active.role === "STUDENT") return "/student";
    return "/no-access";
  };

  // ===== Routes =====

  // Home: send user to the right place
  if (path === "/") {
    const auth = await loadAuth();
    if (!auth.user) return redirect("/login");
    return redirect(dashboardRedirectFor(auth));
  }

  // No-access page
  if (path === "/no-access") {
    return html(`
      <div class="card">
        <h1>No access</h1>
        <p class="muted">Your account has no active school access yet.</p>
        <p><a href="/logout">Logout</a></p>
      </div>
    `);
  }

  // Setup: only works if no users exist yet
  if (path === "/setup") {
    const countRow = await q1("SELECT COUNT(*) AS n FROM users", []);
    const n = Number(countRow?.n || 0);

    if (request.method === "GET") {
      if (n > 0) {
        return html(`
          <div class="card">
            <h1>Setup already done</h1>
            <p><a href="/login">Go to login</a></p>
          </div>
        `);
      }
      return html(`
        <div class="card">
          <h1>First-time Setup</h1>
          <p class="muted">Create the System Admin account (only once).</p>
          <form method="post" action="/setup">
            <label>Full name</label><input name="name" required />
            <label>Email</label><input name="email" type="email" required />
            <label>Password</label><input name="password" type="password" required />
            <button type="submit">Create System Admin</button>
          </form>
        </div>
      `);
    }

    if (request.method === "POST") {
      if (n > 0) return redirect("/login");
      const f = await parseForm();
      const name = (f.name || "").trim();
      const email = (f.email || "").trim().toLowerCase();
      const password = (f.password || "").trim();

      if (!name || !email || password.length < 6) {
        return html(`<div class="card err"><b>Check your inputs.</b> Password must be at least 6 characters.</div>
          <p><a href="/setup">Back</a></p>`, 400);
      }

      const salt = newSaltB64();
      const iter = 150000;
      const ph = await pbkdf2Hash(password, salt, iter);
      const id = uuid();
      const ts = nowISO();

      try {
        await exec(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,1,'ACTIVE',?,?)",
          [id, email, name, salt, ph, iter, ts, ts]
        );
      } catch (e) {
        return html(`<div class="card err"><b>Could not create user.</b> That email might already exist.</div>
          <p><a href="/setup">Back</a></p>`, 400);
      }

      return html(`
        <div class="card ok">
          <h1>System Admin created</h1>
          <p><a href="/login">Go to login</a></p>
        </div>
      `);
    }
  }

  // Login
  if (path === "/login") {
    if (request.method === "GET") {
      return html(`
        <div class="card">
          <h1>Login</h1>
          <form method="post" action="/login">
            <label>Email</label><input name="email" type="email" required />
            <label>Password</label><input name="password" type="password" required />
            <button type="submit">Login</button>
          </form>
          <p class="muted">If this is a new project, go to <a href="/setup">/setup</a> first.</p>
        </div>
      `);
    }

    if (request.method === "POST") {
      const f = await parseForm();
      const email = (f.email || "").trim().toLowerCase();
      const password = (f.password || "").trim();

      const u = await q1(
        "SELECT id,email,name,password_salt,password_hash,password_iter,is_system_admin FROM users WHERE email=? AND status='ACTIVE'",
        [email]
      );
      if (!u) return html(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);

      const ph = await pbkdf2Hash(password, u.password_salt, Number(u.password_iter));
      if (ph !== u.password_hash) {
        return html(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);
      }

      // Create session
      const sessionId = uuid() + "-" + uuid();
      const sh = await sha256Hex(sessionId);
      const ts = nowISO();
      const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString(); // 7 days

      await exec(
        "INSERT INTO sessions (session_hash,user_id,active_tenant_id,expires_at,created_at) VALUES (?,?,?,?,?)",
        [sh, u.id, null, expires, ts]
      );

      const headers = {
        "Set-Cookie": cookieSet("qa_sess", sessionId, { maxAge: 60 * 60 * 24 * 7 }),
      };

      // redirect to correct place
      const auth = await loadAuth(); // will not see cookie yet, so do manual redirect logic:
      // Instead: check system admin first, else go to choose-school
      if (Number(u.is_system_admin) === 1) return redirect("/sys", headers);
      return redirect("/choose-school", headers);
    }
  }

  // Logout
  if (path === "/logout") {
    const sid = cookieGet("qa_sess");
    if (sid) {
      const sh = await sha256Hex(sid);
      await exec("DELETE FROM sessions WHERE session_hash=?", [sh]);
    }
    return redirect("/login", { "Set-Cookie": cookieClear("qa_sess") });
  }

  // Choose school (if user has multiple)
  if (path === "/choose-school") {
    const r = await requireLogin();
    if (!r.ok) return r.res;

    if (r.user.is_system_admin) return redirect("/sys");

    if (!r.memberships.length) return redirect("/no-access");
    if (r.memberships.length === 1) {
      return redirect(`/switch-school?tenant_id=${encodeURIComponent(r.memberships[0].tenant_id)}`);
    }

    const items = r.memberships.map(m => `
      <div class="card">
        <div class="topbar">
          <div>
            <div><b>${escapeHtml(m.tenant_name)}</b></div>
            <div class="muted">Role: <span class="pill">${escapeHtml(m.role)}</span></div>
          </div>
          <form method="post" action="/switch-school">
            <input type="hidden" name="tenant_id" value="${escapeAttr(m.tenant_id)}"/>
            <button type="submit">Open</button>
          </form>
        </div>
      </div>
    `).join("");

    return html(`
      <div class="card">
        <h1>Choose School</h1>
        <p class="muted">Select which school you want to use right now.</p>
      </div>
      ${items}
      <p><a href="/logout">Logout</a></p>
    `);
  }

  // Switch active school
  if (path === "/switch-school") {
    const r = await requireLogin();
    if (!r.ok) return r.res;

    let tenantId = null;
    if (request.method === "GET") tenantId = url.searchParams.get("tenant_id");
    if (request.method === "POST") {
      const f = await parseForm();
      tenantId = f.tenant_id;
    }
    tenantId = (tenantId || "").trim();
    if (!tenantId) return redirect("/choose-school");

    const membership = r.memberships.find(m => m.tenant_id === tenantId);
    if (!membership) return redirect("/choose-school");

    // update session
    const sid = cookieGet("qa_sess");
    const sh = await sha256Hex(sid);
    await exec("UPDATE sessions SET active_tenant_id=? WHERE session_hash=?", [tenantId, sh]);

    // redirect to correct dashboard
    const role = membership.role;
    if (role === "SCHOOL_ADMIN") return redirect("/school");
    if (role === "TEACHER") return redirect("/teacher");
    if (role === "STUDENT") return redirect("/student");
    return redirect("/no-access");
  }

  // ===== System Admin dashboard =====
  if (path === "/sys") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    if (!r.user.is_system_admin) return redirect("/");

    const tenants = await qAll("SELECT id,name,status FROM tenants ORDER BY name ASC", []);

    const list = tenants.map(t => `<li>${escapeHtml(t.name)} <span class="muted">(${escapeHtml(t.status)})</span></li>`).join("");

    return html(`
      <div class="card">
        <div class="topbar">
          <h1>System Admin</h1>
          <div><a href="/logout">Logout</a></div>
        </div>
        <p class="muted">Create a school + its first School Admin in one step.</p>
      </div>

      <div class="card">
        <h2>Create School</h2>
        <form method="post" action="/sys-create-school">
          <label>School name</label><input name="tenant_name" required />
          <div class="row">
            <div>
              <label>School Admin full name</label><input name="admin_name" required />
            </div>
            <div>
              <label>School Admin email</label><input name="admin_email" type="email" required />
            </div>
          </div>
          <label>Temporary password (you will give this to the School Admin)</label>
          <input name="admin_password" type="text" required />
          <button type="submit">Create school + admin</button>
        </form>
      </div>

      <div class="card">
        <h2>Schools</h2>
        <ul>${list || "<li class='muted'>No schools yet</li>"}</ul>
      </div>
    `);
  }

  // System Admin action: create school + first school admin
  if (path === "/sys-create-school" && request.method === "POST") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    if (!r.user.is_system_admin) return redirect("/");

    const f = await parseForm();
    const tenantName = (f.tenant_name || "").trim();
    const adminName = (f.admin_name || "").trim();
    const adminEmail = (f.admin_email || "").trim().toLowerCase();
    const adminPassword = (f.admin_password || "").trim();

    if (!tenantName || !adminName || !adminEmail || adminPassword.length < 6) {
      return html(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/sys">Back</a></p>`, 400);
    }

    const tenantId = uuid();
    const ts = nowISO();

    // Create tenant
    await exec(
      "INSERT INTO tenants (id,name,status,created_at,updated_at) VALUES (?,?, 'ACTIVE', ?, ?)",
      [tenantId, tenantName, ts, ts]
    );

    // Create user (school admin) if not exists; if exists, reuse
    let u = await q1("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [adminEmail]);
    let userId = u?.id;

    if (!userId) {
      const salt = newSaltB64();
      const iter = 150000;
      const ph = await pbkdf2Hash(adminPassword, salt, iter);
      userId = uuid();
      await exec(
        "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
        [userId, adminEmail, adminName, salt, ph, iter, ts, ts]
      );
    }

    // Create membership
    await exec(
      "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?, 'SCHOOL_ADMIN','ACTIVE',?,?)",
      [uuid(), userId, tenantId, ts, ts]
    );

    return redirect("/sys");
  }

  // ===== School Admin dashboard =====
  if (path === "/school") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    if (r.user.is_system_admin) return redirect("/sys");

    const active = pickActiveTenant(r);
    if (!active) return redirect("/choose-school");
    if (active.role !== "SCHOOL_ADMIN") return redirect("/");

    const tenantId = active.tenant_id;

    const members = await qAll(
      `SELECT u.id,u.name,u.email,m.role
       FROM memberships m JOIN users u ON u.id=m.user_id
       WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'
       ORDER BY m.role ASC, u.name ASC`,
      [tenantId]
    );

    const courses = await qAll(
      "SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC",
      [tenantId]
    );

    const teachers = members.filter(x => x.role === "TEACHER");
    const students = members.filter(x => x.role === "STUDENT");

    const memberList = members.map(x => `<li><b>${escapeHtml(x.name)}</b> — ${escapeHtml(x.email)} <span class="pill">${escapeHtml(x.role)}</span></li>`).join("");
    const courseList = courses.map(c => `<li><b>${escapeHtml(c.title)}</b> <span class="muted">(${escapeHtml(c.status)})</span></li>`).join("");

    const teacherOptions = teachers.map(t => `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)} (${escapeHtml(t.email)})</option>`).join("");
    const studentOptions = students.map(s => `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`).join("");
    const courseOptions = courses.map(c => `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`).join("");

    return html(`
      <div class="card">
        <div class="topbar">
          <div>
            <h1>School Admin</h1>
            <div class="muted">${escapeHtml(active.tenant_name)}</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            <a href="/choose-school">Switch school</a>
            <a href="/logout">Logout</a>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Add User (Teacher or Student)</h2>
        <form method="post" action="/school-add-user">
          <label>Full name</label><input name="name" required />
          <label>Email</label><input name="email" type="email" required />
          <label>Role</label>
          <select name="role" required>
            <option value="TEACHER">Teacher</option>
            <option value="STUDENT">Student</option>
          </select>
          <label>Temporary password</label><input name="password" type="text" required />
          <button type="submit">Create user + add to this school</button>
        </form>
      </div>

      <div class="card">
        <h2>Create Course</h2>
        <form method="post" action="/school-create-course">
          <label>Course title</label><input name="title" required />
          <button type="submit">Create course</button>
        </form>
      </div>

      <div class="card">
        <h2>Assign Teacher to Course</h2>
        <form method="post" action="/school-assign-teacher">
          <label>Course</label>
          <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
          <label>Teacher</label>
          <select name="teacher_id" required>${teacherOptions || "<option value=''>Add a teacher first</option>"}</select>
          <button type="submit">Assign teacher</button>
        </form>
      </div>

      <div class="card">
        <h2>Enrol Student to Course</h2>
        <form method="post" action="/school-enrol-student">
          <label>Course</label>
          <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
          <label>Student</label>
          <select name="student_id" required>${studentOptions || "<option value=''>Add a student first</option>"}</select>
          <button type="submit">Enrol student</button>
        </form>
      </div>

      <div class="card">
        <h2>Users in this school</h2>
        <ul>${memberList || "<li class='muted'>No users yet</li>"}</ul>
      </div>

      <div class="card">
        <h2>Courses</h2>
        <ul>${courseList || "<li class='muted'>No courses yet</li>"}</ul>
      </div>
    `);
  }

  // School Admin actions
  if (path === "/school-add-user" && request.method === "POST") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

    const tenantId = active.tenant_id;
    const f = await parseForm();
    const name = (f.name || "").trim();
    const email = (f.email || "").trim().toLowerCase();
    const role = (f.role || "").trim();
    const password = (f.password || "").trim();

    if (!name || !email || !["TEACHER","STUDENT"].includes(role) || password.length < 6) {
      return html(`<div class="card err"><b>Check inputs.</b></div><p><a href="/school">Back</a></p>`, 400);
    }

    const ts = nowISO();

    // Create or reuse global user
    let u = await q1("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
    let userId = u?.id;

    if (!userId) {
      const salt = newSaltB64();
      const iter = 150000;
      const ph = await pbkdf2Hash(password, salt, iter);
      userId = uuid();
      await exec(
        "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
        [userId, email, name, salt, ph, iter, ts, ts]
      );
    }

    // Add membership (if exists, ignore)
    try {
      await exec(
        "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
        [uuid(), userId, tenantId, role, ts, ts]
      );
    } catch (e) {
      // membership already exists; update role if you want (for now keep as-is)
    }

    return redirect("/school");
  }

  if (path === "/school-create-course" && request.method === "POST") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

    const tenantId = active.tenant_id;
    const f = await parseForm();
    const title = (f.title || "").trim();
    if (!title) return redirect("/school");

    const ts = nowISO();
    await exec(
      "INSERT INTO courses (id,tenant_id,title,status,created_at,updated_at) VALUES (?,?,?,'ACTIVE',?,?)",
      [uuid(), tenantId, title, ts, ts]
    );

    return redirect("/school");
  }

  if (path === "/school-assign-teacher" && request.method === "POST") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

    const tenantId = active.tenant_id;
    const f = await parseForm();
    const courseId = (f.course_id || "").trim();
    const teacherId = (f.teacher_id || "").trim();
    if (!courseId || !teacherId) return redirect("/school");

    // Ensure course belongs to tenant
    const c = await q1("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, tenantId]);
    if (!c) return redirect("/school");

    // Ensure teacher has TEACHER membership in tenant
    const m = await q1("SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='TEACHER' AND status='ACTIVE'", [teacherId, tenantId]);
    if (!m) return redirect("/school");

    try {
      await exec("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, teacherId, nowISO()]);
    } catch (e) {}
    return redirect("/school");
  }

  if (path === "/school-enrol-student" && request.method === "POST") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

    const tenantId = active.tenant_id;
    const f = await parseForm();
    const courseId = (f.course_id || "").trim();
    const studentId = (f.student_id || "").trim();
    if (!courseId || !studentId) return redirect("/school");

    const c = await q1("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, tenantId]);
    if (!c) return redirect("/school");

    const m = await q1("SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='STUDENT' AND status='ACTIVE'", [studentId, tenantId]);
    if (!m) return redirect("/school");

    try {
      await exec("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, studentId, nowISO()]);
    } catch (e) {}
    return redirect("/school");
  }

  // ===== Teacher dashboard (read-only for now) =====
  if (path === "/teacher") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active) return redirect("/choose-school");
    if (active.role !== "TEACHER") return redirect("/");

    const rows = await qAll(
      `SELECT c.title
       FROM course_teachers ct
       JOIN courses c ON c.id = ct.course_id
       WHERE ct.user_id=? AND c.tenant_id=? AND c.status='ACTIVE'
       ORDER BY c.title ASC`,
      [r.user.id, active.tenant_id]
    );

    return html(`
      <div class="card">
        <div class="topbar">
          <div>
            <h1>Teacher</h1>
            <div class="muted">${escapeHtml(active.tenant_name)}</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            <a href="/choose-school">Switch school</a>
            <a href="/logout">Logout</a>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>My assigned courses</h2>
        <ul>${rows.map(x => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
      </div>
    `);
  }

  // ===== Student dashboard (read-only for now) =====
  if (path === "/student") {
    const r = await requireLogin();
    if (!r.ok) return r.res;
    const active = pickActiveTenant(r);
    if (!active) return redirect("/choose-school");
    if (active.role !== "STUDENT") return redirect("/");

    const rows = await qAll(
      `SELECT c.title
       FROM enrollments e
       JOIN courses c ON c.id = e.course_id
       WHERE e.user_id=? AND c.tenant_id=? AND c.status='ACTIVE'
       ORDER BY c.title ASC`,
      [r.user.id, active.tenant_id]
    );

    return html(`
      <div class="card">
        <div class="topbar">
          <div>
            <h1>Student</h1>
            <div class="muted">${escapeHtml(active.tenant_name)}</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            <a href="/choose-school">Switch school</a>
            <a href="/logout">Logout</a>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>My enrolled courses</h2>
        <ul>${rows.map(x => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
      </div>
    `);
  }

  // Fallback
  return html(`
    <div class="card">
      <h1>Not found</h1>
      <p class="muted">Try <a href="/login">/login</a> or <a href="/">home</a>.</p>
    </div>
  `, 404);

  // -------- safe HTML helpers --------
  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replaceAll("`", "&#096;");
  }
}
