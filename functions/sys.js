// functions/sys.js
// System Admin routes

import { createHelpers } from "./shared.js";

export async function handleSysRequest(ctx) {
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
    // System Admin dashboard
    // =============================
    if (path === "/sys") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const tenants = await all("SELECT id,name,status FROM tenants ORDER BY name ASC", []);
      const list = tenants.map((t) =>
        `<li>${escapeHtml(t.name)} <span class="muted">(${escapeHtml(t.status)})</span></li>`
      ).join("");

      const q = (url.searchParams.get("q") || "").trim().toLowerCase();
      let userSearchBlock = "";
      if (q) {
        const users = await all(
          "SELECT id,email,name,is_system_admin,status,created_at FROM users WHERE lower(email) LIKE ? ORDER BY email ASC LIMIT 25",
          [`%${q}%`]
        );

        const tenantOptions = tenants.filter((t) => t.status === "ACTIVE")
          .map((t) => `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)}</option>`).join("");

        const rows = [];
        for (const u of users) {
          const mems = await all(
            `SELECT m.tenant_id, t.name AS tenant_name, m.role, m.status
             FROM memberships m JOIN tenants t ON t.id=m.tenant_id
             WHERE m.user_id=? ORDER BY t.name ASC`,
            [u.id]
          );
          const memList = mems.map((m) =>
            `${escapeHtml(m.tenant_name)}: ${escapeHtml(m.role)} (${escapeHtml(m.status)})`
          ).join("<br/>");

          rows.push(`
            <tr>
              <td>
                <b>${escapeHtml(u.email)}</b><br/>
                <span class="muted">${escapeHtml(u.name)}</span>
                ${Number(u.is_system_admin) === 1 ? `<div class="pill">System Admin</div>` : ``}
              </td>
              <td class="small">${memList || `<span class="muted">No memberships</span>`}</td>
              <td>
                <form method="post" action="/sys-add-member">
                  <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
                  <label class="small">School</label>
                  <select name="tenant_id" required>${tenantOptions || "<option value=''>No schools</option>"}</select>
                  <label class="small">Role</label>
                  <select name="role" required>
                    <option value="STUDENT">Student</option>
                    <option value="TEACHER">Teacher</option>
                    <option value="SCHOOL_ADMIN">School Admin</option>
                  </select>
                  <button type="submit" style="margin-top:8px">Add / Update</button>
                </form>
              </td>
            </tr>
          `);
        }

        userSearchBlock = `
          <div class="card">
            <h2>User directory</h2>
            <p class="muted">Search: <b>${escapeHtml(q)}</b></p>
            <table class="table">
              <thead><tr><th>User</th><th>Schools / Roles</th><th>Add to school</th></tr></thead>
              <tbody>${rows.join("") || `<tr><td colspan="3" class="muted">No users found</td></tr>`}</tbody>
            </table>
          </div>
        `;
      }

      return page(`
        <div class="card">
          <div class="topbar">
            <h1>System Admin</h1>
            <div class="actions"><a href="/profile">Profile</a><a href="/logout">Logout</a></div>
          </div>
        </div>
        <div class="card">
          <h2>Create School</h2>
          <form method="post" action="/sys-create-school">
            <label>School name</label><input name="tenant_name" required />
            <div class="row">
              <div><label>School Admin full name</label><input name="admin_name" required /></div>
              <div><label>School Admin email</label><input name="admin_email" type="email" required /></div>
            </div>
            <label>Temporary password (used only if this email is NEW)</label>
            <input name="admin_password" type="text" required />
            <button type="submit">Create school + admin</button>
          </form>
        </div>
        <div class="card">
          <h2>Find user by email</h2>
          <form method="get" action="/sys">
            <label>Email contains</label>
            <input name="q" value="${escapeAttr(q)}" placeholder="e.g. ama@" required />
            <button type="submit">Search</button>
          </form>
        </div>
        ${userSearchBlock}
        <div class="card">
          <h2>Schools</h2>
          <ul>${list || "<li class='muted'>No schools yet</li>"}</ul>
        </div>
      `);
    }

    if (path === "/sys-add-member" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const f = await form();
      const userId = (f.user_id || "").trim();
      const tenantId = (f.tenant_id || "").trim();
      const role = (f.role || "").trim();
      if (!userId || !tenantId || !["STUDENT", "TEACHER", "SCHOOL_ADMIN"].includes(role)) return redirect("/sys");

      const u = await first("SELECT id FROM users WHERE id=? AND status='ACTIVE'", [userId]);
      const t = await first("SELECT id FROM tenants WHERE id=? AND status='ACTIVE'", [tenantId]);
      if (!u || !t) return redirect("/sys");

      const m = await first(
        "SELECT id,status FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1",
        [userId, tenantId]
      );
      const ts = nowISO();
      if (!m) {
        await run("INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), userId, tenantId, role, ts, ts]);
      } else {
        await run("UPDATE memberships SET role=?, status='ACTIVE', updated_at=? WHERE id=?", [role, ts, m.id]);
      }
      return redirect(`/sys?q=${encodeURIComponent((url.searchParams.get("q") || "").trim())}`);
    }

    if (path === "/sys-create-school" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const f = await form();
      const tenantName = (f.tenant_name || "");
      const adminName = (f.admin_name || "");
      const adminEmail = (f.admin_email || "").toLowerCase();
      const adminPassword = (f.admin_password || "");

      if (!tenantName || !adminName || !adminEmail || adminPassword.length < 6) {
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/sys">Back</a></p>`, 400);
      }

      const tenantId = uuid();
      const ts = nowISO();
      await run("INSERT INTO tenants (id,name,status,created_at,updated_at) VALUES (?,?,'ACTIVE',?,?)", [tenantId, tenantName, ts, ts]);

      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [adminEmail]);
      let userId = u?.id;
      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(adminPassword + "|" + PEPPER, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, adminEmail, adminName, saltHex, hashHex, iter, ts, ts]
        );
      }

      const m = await first("SELECT id FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1", [userId, tenantId]);
      if (!m) {
        await run("INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,'SCHOOL_ADMIN','ACTIVE',?,?)",
          [uuid(), userId, tenantId, ts, ts]);
      } else {
        await run("UPDATE memberships SET role='SCHOOL_ADMIN', status='ACTIVE', updated_at=? WHERE id=?", [ts, m.id]);
      }
      return redirect("/sys");
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
