// functions/admin.js
// School Admin routes (/school and /school-*)

import { createHelpers } from "./shared.js";

export async function handleAdminRequest(ctx) {
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
    // School Admin dashboard
    // =============================
    if (path === "/school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const members = await all(
        `SELECT u.id,u.name,u.email,m.id AS membership_id,m.role
         FROM memberships m JOIN users u ON u.id=m.user_id
         WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'
         ORDER BY m.role ASC, u.name ASC`,
        [tenantId]
      );

      const courses = await all("SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC", [tenantId]);
      const classes = await all(
        `SELECT c.id, c.name, c.year_group, c.academic_year, c.status,
                COUNT(cs.id) AS student_count
         FROM classes c
         LEFT JOIN class_students cs ON cs.class_id = c.id
         WHERE c.tenant_id=? GROUP BY c.id ORDER BY c.name ASC`,
        [tenantId]
      );
      const teachers = members.filter((x) => x.role === "TEACHER");
      const students = members.filter((x) => x.role === "STUDENT");

      const teacherOptions = teachers.map((t) =>
        `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)} (${escapeHtml(t.email)})</option>`
      ).join("");

      const studentOptions = students.map((s) =>
        `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`
      ).join("");

      const courseOptions = courses.filter((c) => c.status === "ACTIVE").map((c) =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const codes = await all(
        `SELECT jc.*, c.title AS course_title FROM join_codes jc
         LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.tenant_id=? ORDER BY jc.created_at DESC`,
        [tenantId]
      );

      const codesRows = codes.map((c) => {
        const expired = isIsoInPast(c.expires_at);
        const status = Number(c.revoked) === 1 ? "Revoked" : expired ? "Expired" : "Active";
        return `
          <tr>
            <td>
              <b>${escapeHtml(scopeLabel(c.scope))}</b><br/>
              <span class="muted small">${escapeHtml(roleLabel(c.role))}${c.course_title ? ` • ${escapeHtml(c.course_title)}` : ""}</span>
            </td>
            <td class="small">
              ${escapeHtml(fmtISO(c.expires_at))}<br/>
              Uses: ${escapeHtml(c.uses_approved)}/${escapeHtml(c.max_uses)}<br/>
              Auto: ${Number(c.auto_approve) === 1 ? "Yes" : "No"}
            </td>
            <td><span class="pill">${escapeHtml(status)}</span></td>
            <td>
              ${Number(c.revoked) === 1
                ? `<span class="muted small">—</span>`
                : `<form method="post" action="/school-revoke-code" onsubmit="return confirm('Revoke this code?')">
                    <input type="hidden" name="code_id" value="${escapeAttr(c.id)}"/>
                    <button type="submit" class="btn3">Revoke</button>
                  </form>`}
            </td>
          </tr>
        `;
      }).join("");

      const pending = await all(
        `SELECT jr.id, jr.type, jr.requested_role, jr.created_at,
                u.name AS user_name, u.email AS user_email, c.title AS course_title
         FROM join_requests jr
         JOIN users u ON u.id = jr.user_id
         LEFT JOIN courses c ON c.id = jr.course_id
         WHERE jr.tenant_id=? AND jr.status='PENDING' ORDER BY jr.created_at DESC`,
        [tenantId]
      );

      const history = await all(
        `SELECT jr.id, jr.type, jr.requested_role, jr.status, jr.created_at, jr.reviewed_at,
                u.name AS user_name, u.email AS user_email, c.title AS course_title
         FROM join_requests jr
         JOIN users u ON u.id = jr.user_id
         LEFT JOIN courses c ON c.id = jr.course_id
         WHERE jr.tenant_id=? AND jr.status IN ('APPROVED','REJECTED')
         ORDER BY jr.reviewed_at DESC, jr.created_at DESC LIMIT 50`,
        [tenantId]
      );

      const pendingRows = pending.map((x) => `
        <tr>
          <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
          <td class="small">
            ${escapeHtml(x.type)} • ${escapeHtml(roleLabel(x.requested_role))}
            ${x.course_title ? `<br/>Course: ${escapeHtml(x.course_title)}` : ``}
            <br/><span class="muted">Requested: ${escapeHtml(fmtISO(x.created_at))}</span>
          </td>
          <td>
            <div class="actions">
              <form method="post" action="/school-approve-request" onsubmit="return confirm('Approve this request?')">
                <input type="hidden" name="request_id" value="${escapeAttr(x.id)}"/>
                <button class="btn2" type="submit">Approve</button>
              </form>
              <form method="post" action="/school-reject-request" onsubmit="return confirm('Reject this request?')">
                <input type="hidden" name="request_id" value="${escapeAttr(x.id)}"/>
                <button class="btn3" type="submit">Reject</button>
              </form>
            </div>
          </td>
        </tr>
      `).join("");

      const historyRows = history.map((x) => `
        <tr>
          <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
          <td class="small">
            ${escapeHtml(x.type)} • ${escapeHtml(roleLabel(x.requested_role))}
            ${x.course_title ? `<br/>Course: ${escapeHtml(x.course_title)}` : ``}
          </td>
          <td class="small">
            <span class="pill">${escapeHtml(x.status)}</span><br/>
            <span class="muted">Reviewed: ${escapeHtml(fmtISO(x.reviewed_at || ""))}</span>
          </td>
        </tr>
      `).join("");

      const memberRows = members.map((m) => {
        const self = m.id === r.user.id;
        return `
          <tr>
            <td><b>${escapeHtml(m.name)}</b><br/><span class="muted small">${escapeHtml(m.email)}</span>${self ? `<div class="pill">You</div>` : ``}</td>
            <td>
              <form method="post" action="/school-update-member-role" class="actions">
                <input type="hidden" name="user_id" value="${escapeAttr(m.id)}"/>
                <select name="role" required>
                  <option value="STUDENT" ${m.role === "STUDENT" ? "selected" : ""}>Student</option>
                  <option value="TEACHER" ${m.role === "TEACHER" ? "selected" : ""}>Teacher</option>
                  <option value="SCHOOL_ADMIN" ${m.role === "SCHOOL_ADMIN" ? "selected" : ""}>School Admin</option>
                </select>
                <button type="submit" class="btn2">Update</button>
              </form>
            </td>
            <td>
              <form method="post" action="/school-remove-member" onsubmit="return confirm('Remove this member from the school?')">
                <input type="hidden" name="user_id" value="${escapeAttr(m.id)}"/>
                <button type="submit" class="btn3" ${self ? "disabled title='Cannot remove yourself'" : ""}>Remove</button>
              </form>
            </td>
          </tr>
        `;
      }).join("");

      // Sittings for School Admin dashboard
      const sittingsForAdmin = await all(
        `SELECT es.id, es.title, es.academic_year, es.status,
                (SELECT COUNT(*) FROM exam_sitting_papers esp WHERE esp.sitting_id = es.id) AS paper_count
         FROM exam_sittings es
         WHERE es.tenant_id=? ORDER BY es.created_at DESC`,
        [tenantId]
      );

      const rosterBlocks = [];
      for (const c of courses.filter((x) => x.status === "ACTIVE")) {
        const tRows = await all(
          `SELECT u.id,u.name,u.email FROM course_teachers ct JOIN users u ON u.id=ct.user_id
           WHERE ct.course_id=? ORDER BY u.name ASC`, [c.id]
        );
        const sRows = await all(
          `SELECT u.id,u.name,u.email FROM enrollments e JOIN users u ON u.id=e.user_id
           WHERE e.course_id=? ORDER BY u.name ASC`, [c.id]
        );

        const tList = tRows.map((u) => `
          <li>${escapeHtml(u.name)} <span class="muted small">(${escapeHtml(u.email)})</span>
            <form style="display:inline" method="post" action="/school-unassign-teacher" onsubmit="return confirm('Unassign teacher?')">
              <input type="hidden" name="course_id" value="${escapeAttr(c.id)}"/>
              <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
              <button class="btn3" type="submit" style="margin-left:8px;padding:6px 10px">Remove</button>
            </form>
          </li>`).join("");

        const sList = sRows.map((u) => `
          <li>${escapeHtml(u.name)} <span class="muted small">(${escapeHtml(u.email)})</span>
            <form style="display:inline" method="post" action="/school-unenrol-student" onsubmit="return confirm('Remove student?')">
              <input type="hidden" name="course_id" value="${escapeAttr(c.id)}"/>
              <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
              <button class="btn3" type="submit" style="margin-left:8px;padding:6px 10px">Remove</button>
            </form>
          </li>`).join("");

        rosterBlocks.push(`
          <div class="card">
            <h2>${escapeHtml(c.title)}</h2>
            <div class="row">
              <div><h3 style="margin:0 0 6px;font-size:14px">Teachers (${tRows.length})</h3><ul>${tList || `<li class="muted">None</li>`}</ul></div>
              <div><h3 style="margin:0 0 6px;font-size:14px">Students (${sRows.length})</h3><ul>${sList || `<li class="muted">None</li>`}</ul></div>
            </div>
          </div>
        `);
      }

      const _schoolPaCnt = await first(
        `SELECT COUNT(*) AS cnt FROM sitting_approval_gates sag
         JOIN sitting_approval_responses sar
           ON sar.exam_id=sag.exam_id AND sar.gate_type=sag.gate_type
          AND sar.approver_id=sag.user_id AND sar.tenant_id=sag.tenant_id
         WHERE sag.user_id=? AND sag.tenant_id=? AND sar.status='PENDING'`,
        [r.user.id, tenantId]
      );
      const _schoolPaNum = Number((_schoolPaCnt || {}).cnt);
      const schoolApprovalBanner = _schoolPaNum > 0
        ? `<div class="card" style="background:#fffbea;border:1px solid #f0c040;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;flex-wrap:wrap"><span style="font-weight:600;font-size:14px">&#128236; You have ${_schoolPaNum} pending approval${_schoolPaNum !== 1 ? "s" : ""}</span><a href="/approvals" class="btn2" style="display:inline-block;text-decoration:none;padding:7px 14px;font-size:13px;white-space:nowrap">View Inbox &#8594;</a></div>`
        : "";

      const classRows = classes.map((cl) => `
        <tr>
          <td><b>${escapeHtml(cl.name)}</b>${cl.year_group ? ` <span class="muted small">${escapeHtml(cl.year_group)}</span>` : ""}</td>
          <td class="small">${escapeHtml(cl.academic_year || "—")}</td>
          <td><span class="pill">${escapeHtml(cl.status)}</span></td>
          <td class="small">${Number(cl.student_count)}</td>
          <td><a href="/school-class?class_id=${escapeAttr(cl.id)}" class="btn3" style="display:inline-block;padding:4px 10px;border-radius:8px;text-decoration:none">Manage</a></td>
        </tr>
      `).join("");

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>School Admin</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ``}
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        ${schoolApprovalBanner}
        <div class="card">
          <h2>Join Codes</h2>
          <p class="muted small">Codes are stored hashed; you'll see the plaintext code only at creation time.</p>
          <form method="post" action="/school-create-code">
            <label>Code type</label>
            <select name="kind" required>
              <option value="TENANT_STUDENT">Student (school-wide access)</option>
              <option value="TENANT_TEACHER">Teacher (school-wide access)</option>
              <option value="COURSE_ENROLL">Student (course enrol)</option>
              <option value="COURSE_TEACHER">Teacher (course assignment)</option>
            </select>
            <label>Course (required for course codes)</label>
            <select name="course_id">${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <div class="row">
              <div>
                <label>Auto-approve</label>
                <select name="auto_approve">
                  <option value="0">No (admin approval required)</option>
                  <option value="1">Yes (instant)</option>
                </select>
              </div>
              <div>
                <label>Expiry (days)</label>
                <input name="exp_days" type="number" min="1" value="${JOIN_CODE_DEFAULT_EXP_DAYS}" required />
              </div>
            </div>
            <label>Max uses</label>
            <input name="max_uses" type="number" min="1" value="${JOIN_CODE_DEFAULT_MAX_USES}" required />
            <button type="submit">Create code</button>
          </form>
          <h3 style="margin:14px 0 6px;font-size:14px">Existing codes</h3>
          <table class="table">
            <thead><tr><th>Type</th><th>Limits</th><th>Status</th><th></th></tr></thead>
            <tbody>${codesRows || `<tr><td colspan="4" class="muted">No codes yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Join Requests</h2>
          <h3 style="margin:10px 0 6px;font-size:14px">Pending</h3>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Actions</th></tr></thead>
            <tbody>${pendingRows || `<tr><td colspan="3" class="muted">No pending requests</td></tr>`}</tbody>
          </table>
          <h3 style="margin:14px 0 6px;font-size:14px">History</h3>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Status</th></tr></thead>
            <tbody>${historyRows || `<tr><td colspan="3" class="muted">No history yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Add User (manual)</h2>
          <form method="post" action="/school-add-user">
            <label>Full name</label><input name="name" required />
            <label>Email</label><input name="email" type="email" required />
            <label>Role</label>
            <select name="role" required>
              <option value="TEACHER">Teacher</option>
              <option value="STUDENT">Student</option>
              <option value="SCHOOL_ADMIN">School Admin</option>
            </select>
            <label>Temporary password (used only if this email is NEW)</label>
            <input name="password" type="text" required />
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
          <h2>Assign Teacher to Course (manual)</h2>
          <form method="post" action="/school-assign-teacher">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Teacher</label>
            <select name="teacher_id" required>${teacherOptions || "<option value=''>Add a teacher first</option>"}</select>
            <button type="submit">Assign teacher</button>
          </form>
        </div>

        <div class="card">
          <h2>Enrol Student to Course (manual)</h2>
          <form method="post" action="/school-enrol-student">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Student</label>
            <select name="student_id" required>${studentOptions || "<option value=''>Add a student first</option>"}</select>
            <button type="submit">Enrol student</button>
          </form>
        </div>

        <div class="card">
          <h2>Members (manage roles / remove)</h2>
          <table class="table">
            <thead><tr><th>Member</th><th>Role</th><th>Remove</th></tr></thead>
            <tbody>${memberRows || `<tr><td colspan="3" class="muted">No users yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Courses</h2>
          <ul>${courses.map((c) => `<li><b>${escapeHtml(c.title)}</b> <span class="muted">(${escapeHtml(c.status)})</span></li>`).join("") || "<li class='muted'>No courses yet</li>"}</ul>
        </div>

        <div class="card">
          <h2>Classes</h2>
          <table class="table">
            <thead><tr><th>Name</th><th>Academic Year</th><th>Status</th><th>Students</th><th></th></tr></thead>
            <tbody>${classRows || `<tr><td colspan="5" class="muted">No classes yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Create Class</h2>
          <form method="post" action="/school-create-class">
            <label>Class name <span class="muted">*</span></label>
            <input name="name" required placeholder="e.g. Year 10 Alpha" />
            <label>Year group <span class="muted">(optional)</span></label>
            <input name="year_group" placeholder="e.g. Year 10" />
            <label>Academic year <span class="muted">(optional)</span></label>
            <input name="academic_year" placeholder="e.g. 2024/25" />
            <label>Description <span class="muted">(optional)</span></label>
            <textarea name="description" rows="2" placeholder="e.g. Top-set Maths group"></textarea>
            <button type="submit">Create class</button>
          </form>
        </div>

        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <h2 style="margin:0">&#128203; Exam Sittings</h2>
            <div class="actions">
              <a href="/sittings" class="btn3" style="display:inline-block;padding:6px 12px;text-decoration:none;font-size:13px">Manage Sittings</a>
              <form method="post" action="/sitting-create" style="display:inline">
                <button type="submit" class="btn2" style="padding:6px 12px;font-size:13px">+ New Sitting</button>
              </form>
            </div>
          </div>
          ${sittingsForAdmin.length === 0 ? `<p class="muted small">No sittings yet — create one to group exam papers into a formal sitting event.</p>` : `
          <table class="table">
            <thead><tr><th>Title</th><th>Academic Year</th><th>Status</th><th>Papers</th><th></th></tr></thead>
            <tbody>${sittingsForAdmin.map(s => {
              const badge = s.status === "ACTIVE"
                ? `<span class="pill" style="background:#d4f5e9;color:#0b5e4e;font-size:11px">Active</span>`
                : s.status === "CLOSED"
                  ? `<span class="pill" style="background:#ffe8e8;color:#c00;font-size:11px">Closed</span>`
                  : `<span class="pill" style="background:rgba(0,0,0,.07);color:rgba(0,0,0,.5);font-size:11px">Draft</span>`;
              return `<tr>
                <td><b>${escapeHtml(s.title)}</b></td>
                <td class="small muted">${escapeHtml(s.academic_year || "—")}</td>
                <td>${badge}</td>
                <td class="small">${Number(s.paper_count)}</td>
                <td><a href="/sitting-builder?sitting_id=${escapeAttr(s.id)}" class="btn3" style="display:inline-block;padding:4px 10px;text-decoration:none;font-size:12px">Open</a></td>
              </tr>`;
            }).join("")}</tbody>
          </table>`}
        </div>

        <div class="card">
          <h2>Course rosters</h2>
          <p class="muted small">Teachers assigned + students enrolled, per course.</p>
        </div>
        ${rosterBlocks.join("")}
      `);
    }

    if (path === "/school-create-code" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const kind = (f.kind || "").trim();
      const courseId = (f.course_id || "").trim();
      const autoApprove = Number(f.auto_approve || "0") === 1 ? 1 : 0;
      const expDays = Math.max(1, parseInt(f.exp_days || `${JOIN_CODE_DEFAULT_EXP_DAYS}`, 10) || JOIN_CODE_DEFAULT_EXP_DAYS);
      const maxUses = Math.max(1, parseInt(f.max_uses || `${JOIN_CODE_DEFAULT_MAX_USES}`, 10) || JOIN_CODE_DEFAULT_MAX_USES);

      let scope = "", role = "", course_id = null;
      if (kind === "TENANT_STUDENT") { scope = "TENANT_ROLE"; role = "STUDENT"; }
      else if (kind === "TENANT_TEACHER") { scope = "TENANT_ROLE"; role = "TEACHER"; }
      else if (kind === "COURSE_ENROLL") { scope = "COURSE_ENROLL"; role = "STUDENT"; course_id = courseId || null; }
      else if (kind === "COURSE_TEACHER") { scope = "COURSE_TEACHER"; role = "TEACHER"; course_id = courseId || null; }
      else return redirect("/school");

      if ((scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") && !course_id) {
        return page(`<div class="card err"><b>Please select a course for course codes.</b></div><p><a href="/school">Back</a></p>`, 400);
      }
      if (scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") {
        const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [course_id, active.tenant_id]);
        if (!c) return page(`<div class="card err"><b>Course not found or inactive.</b></div><p><a href="/school">Back</a></p>`, 400);
      }

      const expiresAt = new Date(Date.now() + expDays * 24 * 60 * 60 * 1000).toISOString();
      const ts = nowISO();

      let codePlain = "", codeHash = "", attempts = 0;
      while (attempts < 6) {
        attempts++;
        codePlain = makeJoinCodePlain();
        codeHash = await joinCodeHash(codePlain);
        const exists = await first("SELECT id FROM join_codes WHERE code_hash=? LIMIT 1", [codeHash]);
        if (!exists) break;
      }
      if (!codePlain) throw new Error("Failed to generate join code.");

      const id = uuid();
      await run(
        `INSERT INTO join_codes (id,tenant_id,scope,role,course_id,code_hash,auto_approve,expires_at,max_uses,uses_approved,revoked,created_by_user_id,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,0,0,?,?,?)`,
        [id, active.tenant_id, scope, role, course_id, codeHash, autoApprove, expiresAt, maxUses, r.user.id, ts, ts]
      );

      return page(`
        <div class="card ok">
          <h1>Join code created</h1>
          <p class="muted">Copy and share this code (shown only once):</p>
          <div class="card" style="border:1px dashed rgba(0,0,0,.2);background:#fff;margin:10px 0">
            <div style="font-size:28px;font-weight:900;letter-spacing:.08em">${escapeHtml(codePlain)}</div>
          </div>
          <p class="muted">Users go to <b>/join</b>, enter the code, then login/create account.</p>
          <p class="actions"><a href="/school">Back to School Admin</a></p>
        </div>
      `);
    }

    if (path === "/school-revoke-code" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const codeId = (f.code_id || "").trim();
      if (!codeId) return redirect("/school");
      await run("UPDATE join_codes SET revoked=1, updated_at=? WHERE id=? AND tenant_id=?", [nowISO(), codeId, active.tenant_id]);
      return redirect("/school");
    }

    if (path === "/school-approve-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school");

      const jr = await first(`SELECT * FROM join_requests WHERE id=? AND tenant_id=? AND status='PENDING'`, [reqId, active.tenant_id]);
      if (!jr) return redirect("/school");

      const jc = await first(
        `SELECT jc.*, t.name AS tenant_name, c.title AS course_title
         FROM join_codes jc JOIN tenants t ON t.id=jc.tenant_id LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.id=? AND jc.tenant_id=?`,
        [jr.join_code_id, active.tenant_id]
      );
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(v.why)}</div><p><a href="/school">Back</a></p>`, 400);

      const reserved = await reserveJoinCodeUse(jc.id);
      if (!reserved) return page(`<div class="card err"><b>Cannot approve:</b> Code is no longer available.</div><p><a href="/school">Back</a></p>`, 400);

      const applied = await applyJoinActionForUser(jr.user_id, jc);
      if (!applied.ok) {
        await unreserveJoinCodeUse(jc.id);
        return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(applied.msg)}</div><p><a href="/school">Back</a></p>`, 400);
      }

      await run("UPDATE join_requests SET status='APPROVED', reviewed_by_user_id=?, reviewed_at=? WHERE id=?", [r.user.id, nowISO(), reqId]);
      return redirect("/school");
    }

    if (path === "/school-reject-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school");
      await run(
        "UPDATE join_requests SET status='REJECTED', reviewed_by_user_id=?, reviewed_at=? WHERE id=? AND tenant_id=? AND status='PENDING'",
        [r.user.id, nowISO(), reqId, active.tenant_id]
      );
      return redirect("/school");
    }

    if (path === "/school-update-member-role" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const userId = (f.user_id || "").trim();
      const role = (f.role || "").trim();
      if (!userId || !["STUDENT", "TEACHER", "SCHOOL_ADMIN"].includes(role)) return redirect("/school");
      if (userId === r.user.id && role !== "SCHOOL_ADMIN") {
        return page(`<div class="card err"><b>You cannot remove your own School Admin role.</b></div><p><a href="/school">Back</a></p>`, 400);
      }
      const m = await first(
        "SELECT id FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [active.tenant_id, userId]
      );
      if (!m) return redirect("/school");
      await run("UPDATE memberships SET role=?, updated_at=? WHERE id=?", [role, nowISO(), m.id]);
      return redirect("/school");
    }

    if (path === "/school-remove-member" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const userId = (f.user_id || "").trim();
      if (!userId) return redirect("/school");
      if (userId === r.user.id) return page(`<div class="card err"><b>You cannot remove yourself.</b></div><p><a href="/school">Back</a></p>`, 400);

      await run("UPDATE memberships SET status='REMOVED', updated_at=? WHERE tenant_id=? AND user_id=? AND status='ACTIVE'",
        [nowISO(), active.tenant_id, userId]);

      const courseIds = await all("SELECT id FROM courses WHERE tenant_id=?", [active.tenant_id]);
      for (const c of courseIds) {
        await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [c.id, userId]);
        await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [c.id, userId]);
      }
      return redirect("/school");
    }

    if (path === "/school-unassign-teacher" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");
      await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect("/school");
    }

    if (path === "/school-unenrol-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");
      await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect("/school");
    }

    if (path === "/school-add-user" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;
      const f = await form();
      const name = (f.name || "");
      const email = (f.email || "").toLowerCase();
      const role = (f.role || "");
      const password = (f.password || "");

      if (!name || !email || !["TEACHER", "STUDENT", "SCHOOL_ADMIN"].includes(role) || password.length < 6) {
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/school">Back</a></p>`, 400);
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

      const m = await first("SELECT id,status FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1", [userId, tenantId]);
      if (!m) {
        await run("INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), userId, tenantId, role, ts, ts]);
      } else {
        await run("UPDATE memberships SET role=?, status='ACTIVE', updated_at=? WHERE id=?", [role, ts, m.id]);
      }
      return redirect("/school");
    }

    if (path === "/school-create-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const title = (f.title || "");
      if (!title) return redirect("/school");
      const ts = nowISO();
      await run("INSERT INTO courses (id,tenant_id,title,status,created_at,updated_at) VALUES (?,?,?,'ACTIVE',?,?)",
        [uuid(), active.tenant_id, title, ts, ts]);
      return redirect("/school");
    }

    if (path === "/school-assign-teacher" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "");
      const teacherId = (f.teacher_id || "");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");
      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('TEACHER','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [teacherId, active.tenant_id]
      );
      if (!m) return redirect("/school");
      const ex = await first("SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1", [courseId, teacherId]);
      if (!ex) {
        await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, teacherId, nowISO()]);
      }
      return redirect("/school");
    }

    if (path === "/school-enrol-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "");
      const studentId = (f.student_id || "");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");
      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('STUDENT','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [studentId, active.tenant_id]
      );
      if (!m) return redirect("/school");
      const ex = await first("SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=? LIMIT 1", [courseId, studentId]);
      if (!ex) {
        await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, studentId, nowISO()]);
      }
      return redirect("/school");
    }

    // =============================
    // Classes: create (POST)
    // =============================
    if (path === "/school-create-class" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const name = (f.name || "").trim();
      if (!name) return redirect("/school");

      const ts = nowISO();
      await run(
        `INSERT INTO classes (id, tenant_id, name, year_group, academic_year, description, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
        [uuid(), active.tenant_id, name,
         (f.year_group || "").trim() || null,
         (f.academic_year || "").trim() || null,
         (f.description || "").trim() || null,
         ts, ts]
      );
      return redirect("/school");
    }

    // =============================
    // Class detail page (GET)
    // =============================
    if (path === "/school-class") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const classId = url.searchParams.get("class_id") || "";
      if (!classId) return redirect("/school");

      const cls = await first(`SELECT * FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school");

      const classStudents = await all(
        `SELECT u.id, u.name, u.email
         FROM class_students cs JOIN users u ON u.id = cs.user_id
         WHERE cs.class_id=? ORDER BY u.name ASC`,
        [classId]
      );

      const classStudentIds = new Set(classStudents.map((s) => s.id));
      const allStudents = await all(
        `SELECT u.id, u.name, u.email
         FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.tenant_id=? AND m.role='STUDENT' AND m.status='ACTIVE' AND u.status='ACTIVE'
         ORDER BY u.name ASC`,
        [active.tenant_id]
      );
      const availableStudents = allStudents.filter((s) => !classStudentIds.has(s.id));

      const allCourses = await all(
        `SELECT id, title FROM courses WHERE tenant_id=? AND status='ACTIVE' ORDER BY title ASC`,
        [active.tenant_id]
      );

      const studentRows = classStudents.map((s) => `
        <tr>
          <td><b>${escapeHtml(s.name)}</b><br/><span class="muted small">${escapeHtml(s.email)}</span></td>
          <td>
            <form method="post" action="/school-class-remove-student" onsubmit="return confirm('Remove this student from the class?')">
              <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
              <input type="hidden" name="user_id" value="${escapeAttr(s.id)}"/>
              <button type="submit" class="btn3">Remove</button>
            </form>
          </td>
        </tr>
      `).join("");

      const addStudentOptions = availableStudents.map((s) =>
        `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`
      ).join("");

      const courseOptions = allCourses.map((c) =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const archiveLabel = cls.status === "ACTIVE" ? "Archive class" : "Unarchive class";

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>${escapeHtml(cls.name)}</h1>
              <div class="muted">
                ${cls.year_group ? `<span class="pill">${escapeHtml(cls.year_group)}</span>` : ""}
                ${cls.academic_year ? `<span class="pill">${escapeHtml(cls.academic_year)}</span>` : ""}
                <span class="pill">${escapeHtml(cls.status)}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/school">← Back to school</a>
            </div>
          </div>
          ${cls.description ? `<p class="muted" style="margin-top:8px">${escapeHtml(cls.description)}</p>` : ""}
        </div>

        <div class="card">
          <h2>Students (${classStudents.length})</h2>
          <table class="table">
            <thead><tr><th>Student</th><th></th></tr></thead>
            <tbody>${studentRows || `<tr><td colspan="2" class="muted">No students in this class yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Add Student</h2>
          ${availableStudents.length > 0 ? `
          <form method="post" action="/school-class-add-student">
            <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
            <label>Student</label>
            <select name="user_id" required>${addStudentOptions}</select>
            <button type="submit">Add to class</button>
          </form>
          ` : `<p class="muted">All students in the school are already in this class.</p>`}
        </div>

        <div class="card">
          <h2>Enrol Class in Course</h2>
          ${allCourses.length > 0 ? `
          <form method="post" action="/school-class-enrol-course">
            <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
            <label>Course</label>
            <select name="course_id" required>${courseOptions}</select>
            <button type="submit">Enrol all students in course</button>
          </form>
          ` : `<p class="muted">No active courses found.</p>`}
        </div>

        <div class="card">
          <h2>Archive</h2>
          <form method="post" action="/school-class-archive" onsubmit="return confirm('${cls.status === "ACTIVE" ? "Archive" : "Unarchive"} this class?')">
            <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
            <button type="submit" class="btn3">${escapeHtml(archiveLabel)}</button>
          </form>
        </div>
      `);
    }

    // =============================
    // Class: add student (POST)
    // =============================
    if (path === "/school-class-add-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!classId || !userId) return redirect("/school");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school");

      const member = await first(
        `SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='STUDENT' AND status='ACTIVE'`,
        [userId, active.tenant_id]
      );
      if (!member) return redirect(`/school-class?class_id=${classId}`);

      const existing = await first(`SELECT id FROM class_students WHERE class_id=? AND user_id=?`, [classId, userId]);
      if (!existing) {
        const ts = nowISO();
        await run(
          `INSERT INTO class_students (id, class_id, user_id, created_at) VALUES (?, ?, ?, ?)`,
          [uuid(), classId, userId, ts]
        );
      }
      return redirect(`/school-class?class_id=${classId}`);
    }

    // =============================
    // Class: remove student (POST)
    // =============================
    if (path === "/school-class-remove-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!classId || !userId) return redirect("/school");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school");

      await run(`DELETE FROM class_students WHERE class_id=? AND user_id=?`, [classId, userId]);
      return redirect(`/school-class?class_id=${classId}`);
    }

    // =============================
    // Class: enrol in course (POST)
    // =============================
    if (path === "/school-class-enrol-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const courseId = (f.course_id || "").trim();
      if (!classId || !courseId) return redirect("/school");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school");

      const course = await first(
        `SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'`,
        [courseId, active.tenant_id]
      );
      if (!course) return redirect(`/school-class?class_id=${classId}`);

      const classStudents = await all(`SELECT user_id FROM class_students WHERE class_id=?`, [classId]);
      const ts = nowISO();
      for (const s of classStudents) {
        const enrolled = await first(
          `SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=?`,
          [courseId, s.user_id]
        );
        if (!enrolled) {
          await run(
            `INSERT INTO enrollments (course_id, user_id, created_at) VALUES (?, ?, ?)`,
            [courseId, s.user_id, ts]
          );
        }
      }
      return redirect(`/school-class?class_id=${classId}`);
    }

    // =============================
    // Class: toggle archive (POST)
    // =============================
    if (path === "/school-class-archive" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      if (!classId) return redirect("/school");

      const cls = await first(`SELECT id, status FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school");

      const newStatus = cls.status === "ACTIVE" ? "ARCHIVED" : "ACTIVE";
      const ts = nowISO();
      await run(`UPDATE classes SET status=?, updated_at=? WHERE id=?`, [newStatus, ts, classId]);
      return redirect(`/school-class?class_id=${classId}`);
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
