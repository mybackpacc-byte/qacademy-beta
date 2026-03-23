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

    function describeCode(scope, role, courseTitle) {
      if (scope === "TENANT_ROLE" && role === "STUDENT") return "Students \u2192 join school";
      if (scope === "TENANT_ROLE" && role === "TEACHER") return "Teachers \u2192 join school";
      if (scope === "COURSE_ENROLL" && courseTitle) return `Students \u2192 enrol in ${courseTitle}`;
      if (scope === "COURSE_TEACHER" && courseTitle) return `Teachers \u2192 assign to ${courseTitle}`;
      return scopeLabel(scope) + " (" + roleLabel(role) + ")";
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
    // Shared UI helpers
    // =============================
    function schoolNav(activePath) {
      const links = [
        { label: "Overview", href: "/school" },
        { label: "Sittings", href: "/school-sittings" },
        { label: "Courses", href: "/school-courses" },
        { label: "Classes", href: "/school-classes" },
        { label: "People", href: "/school-people" },
        { label: "Join Codes", href: "/school-join-codes" },
      ];
      const items = links.map(({ label, href }) => {
        const active = href === activePath;
        return `<a href="${href}" style="padding:6px 12px;border-radius:8px;text-decoration:none;white-space:nowrap${active ? ";background:rgba(0,0,0,.07);font-weight:700" : ""}">${label}</a>`;
      }).join("");
      return `<div class="card" style="display:flex;flex-wrap:wrap;gap:4px;padding:10px 14px">${items}</div>`;
    }

    function schoolHeader(r, active) {
      return `
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
      `;
    }

    // =============================
    // School Admin — Overview
    // =============================
    if (path === "/school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const totalStudents = await first(
        `SELECT COUNT(*) AS cnt FROM memberships WHERE tenant_id=? AND status='ACTIVE' AND role='STUDENT'`, [tenantId]
      );
      const totalTeachers = await first(
        `SELECT COUNT(*) AS cnt FROM memberships WHERE tenant_id=? AND status='ACTIVE' AND role='TEACHER'`, [tenantId]
      );
      const totalCourses = await first(`SELECT COUNT(*) AS cnt FROM courses WHERE tenant_id=?`, [tenantId]);
      const totalClasses = await first(`SELECT COUNT(*) AS cnt FROM classes WHERE tenant_id=?`, [tenantId]);
      const totalSittings = await first(`SELECT COUNT(*) AS cnt FROM exam_sittings WHERE tenant_id=?`, [tenantId]);
      const pendingJR = await first(
        `SELECT COUNT(*) AS cnt FROM join_requests WHERE tenant_id=? AND status='PENDING'`, [tenantId]
      );

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

      const pendingJRCount = Number((pendingJR || {}).cnt);
      const pendingJRNote = pendingJRCount > 0
        ? `<div class="card" style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;flex-wrap:wrap"><span style="font-size:14px">${pendingJRCount} pending join request${pendingJRCount !== 1 ? "s" : ""}</span><a href="/school-join-codes" class="btn2" style="display:inline-block;text-decoration:none;padding:7px 14px;font-size:13px;white-space:nowrap">View Requests &#8594;</a></div>`
        : "";

      const stat = (label, value) =>
        `<div class="card" style="text-align:center;flex:1;min-width:120px"><div style="font-size:28px;font-weight:700">${value}</div><div class="muted small">${label}</div></div>`;

      return page(`
        ${schoolHeader(r, active)}
        ${schoolApprovalBanner}
        ${schoolNav("/school")}
        <div style="display:flex;flex-wrap:wrap;gap:12px">
          ${stat("Students", Number((totalStudents || {}).cnt))}
          ${stat("Teachers", Number((totalTeachers || {}).cnt))}
          ${stat("Courses", Number((totalCourses || {}).cnt))}
          ${stat("Classes", Number((totalClasses || {}).cnt))}
          ${stat("Sittings", Number((totalSittings || {}).cnt))}
        </div>
        ${pendingJRNote}
      `);
    }

    // =============================
    // School Admin — Sittings
    // =============================
    if (path === "/school-sittings") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const sittingsForAdmin = await all(
        `SELECT es.id, es.title, es.academic_year, es.status,
                (SELECT COUNT(*) FROM exam_sitting_papers esp WHERE esp.sitting_id = es.id) AS paper_count
         FROM exam_sittings es
         WHERE es.tenant_id=? ORDER BY es.created_at DESC`,
        [tenantId]
      );

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-sittings")}
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
      `);
    }

    // =============================
    // School Admin — Courses
    // =============================
    if (path === "/school-courses") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;
      const courses = await all("SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC", [tenantId]);

      const courseRows = courses.map((c) => `
        <tr>
          <td><a href="/school-course?course_id=${escapeAttr(c.id)}"><b>${escapeHtml(c.title)}</b></a></td>
          <td><span class="pill">${escapeHtml(c.status)}</span></td>
        </tr>
      `).join("");

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-courses")}

        <div class="card">
          <h2>Courses</h2>
          <table class="table">
            <thead><tr><th>Title</th><th>Status</th></tr></thead>
            <tbody>${courseRows || `<tr><td colspan="2" class="muted">No courses yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Create Course</h2>
          <form method="post" action="/school-create-course">
            <label>Course title</label><input name="title" required />
            <button type="submit">Create course</button>
          </form>
        </div>
      `);
    }

    // =============================
    // School Admin — Course Detail
    // =============================
    if (path === "/school-course") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const courseId = url.searchParams.get("course_id") || "";
      if (!courseId) return redirect("/school-courses");

      const course = await first("SELECT * FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!course) return redirect("/school-courses");

      const tab = url.searchParams.get("tab") || "details";
      const tabs = ["details", "teachers", "students", "classes", "join-codes"];
      const tabLabels = { "details": "Details", "teachers": "Teachers", "students": "Students", "classes": "Classes", "join-codes": "Join Codes" };
      const tabNav = tabs.map((t) => {
        const active_ = t === tab;
        const label = tabLabels[t] || t;
        return `<a href="/school-course?course_id=${escapeAttr(courseId)}&tab=${t}" style="padding:6px 12px;border-radius:8px;text-decoration:none;white-space:nowrap${active_ ? ";background:rgba(0,0,0,.07);font-weight:700" : ""}">${label}</a>`;
      }).join("");

      let tabContent = "";

      // --- Details tab ---
      if (tab === "details") {
        tabContent = `
          <div class="card">
            <h2>Course Details</h2>
            <form method="post" action="/school-update-course">
              <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
              <label>Title</label>
              <input name="title" value="${escapeAttr(course.title)}" required />
              <label>Status</label>
              <select name="status">
                <option value="ACTIVE"${course.status === "ACTIVE" ? " selected" : ""}>Active</option>
                <option value="ARCHIVED"${course.status === "ARCHIVED" ? " selected" : ""}>Archived</option>
              </select>
              <button type="submit">Save changes</button>
            </form>
          </div>
        `;
      }

      // --- Teachers tab ---
      if (tab === "teachers") {
        const assignedTeachers = await all(
          `SELECT u.id, u.name, u.email FROM course_teachers ct JOIN users u ON u.id=ct.user_id
           WHERE ct.course_id=? ORDER BY u.name ASC`, [courseId]
        );
        const assignedIds = new Set(assignedTeachers.map((t) => t.id));

        const allTeachers = await all(
          `SELECT u.id, u.name, u.email FROM memberships m JOIN users u ON u.id=m.user_id
           WHERE m.tenant_id=? AND m.role IN ('TEACHER','SCHOOL_ADMIN') AND m.status='ACTIVE' AND u.status='ACTIVE'
           ORDER BY u.name ASC`, [active.tenant_id]
        );
        const availableTeachers = allTeachers.filter((t) => !assignedIds.has(t.id));

        const teacherRows = assignedTeachers.map((t) => `
          <tr>
            <td><b>${escapeHtml(t.name)}</b></td>
            <td><span class="muted small">${escapeHtml(t.email)}</span></td>
            <td>
              <form method="post" action="/school-unassign-teacher" onsubmit="return confirm('Unassign this teacher?')">
                <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
                <input type="hidden" name="user_id" value="${escapeAttr(t.id)}"/>
                <button type="submit" class="btn3">Remove</button>
              </form>
            </td>
          </tr>
        `).join("");

        const teacherOptions = availableTeachers.map((t) =>
          `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)} (${escapeHtml(t.email)})</option>`
        ).join("");

        tabContent = `
          <div class="card">
            <h2>Teachers (${assignedTeachers.length})</h2>
            <table class="table">
              <thead><tr><th>Name</th><th>Email</th><th></th></tr></thead>
              <tbody>${teacherRows || `<tr><td colspan="3" class="muted">No teachers assigned yet</td></tr>`}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Assign Teacher</h2>
            ${availableTeachers.length > 0 ? `
            <form method="post" action="/school-assign-teacher">
              <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
              <label>Teacher</label>
              <select name="teacher_id" required>${teacherOptions}</select>
              <button type="submit">Assign teacher</button>
            </form>
            ` : `<p class="muted">All teachers are already assigned to this course.</p>`}
          </div>
        `;
      }

      // --- Students tab ---
      if (tab === "students") {
        const enrolledStudents = await all(
          `SELECT u.id, u.name, u.email FROM enrollments e JOIN users u ON u.id=e.user_id
           WHERE e.course_id=? ORDER BY u.name ASC`, [courseId]
        );
        const enrolledIds = new Set(enrolledStudents.map((s) => s.id));

        const allStudents = await all(
          `SELECT u.id, u.name, u.email FROM memberships m JOIN users u ON u.id=m.user_id
           WHERE m.tenant_id=? AND m.role='STUDENT' AND m.status='ACTIVE' AND u.status='ACTIVE'
           ORDER BY u.name ASC`, [active.tenant_id]
        );
        const availableStudents = allStudents.filter((s) => !enrolledIds.has(s.id));

        const studentRows = enrolledStudents.map((s) => `
          <tr>
            <td><b>${escapeHtml(s.name)}</b></td>
            <td><span class="muted small">${escapeHtml(s.email)}</span></td>
            <td>
              <form method="post" action="/school-unenrol-student" onsubmit="return confirm('Remove this student?')">
                <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
                <input type="hidden" name="user_id" value="${escapeAttr(s.id)}"/>
                <button type="submit" class="btn3">Remove</button>
              </form>
            </td>
          </tr>
        `).join("");

        const studentOptions = availableStudents.map((s) =>
          `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`
        ).join("");

        tabContent = `
          <div class="card">
            <h2>Students (${enrolledStudents.length})</h2>
            <table class="table">
              <thead><tr><th>Name</th><th>Email</th><th></th></tr></thead>
              <tbody>${studentRows || `<tr><td colspan="3" class="muted">No students enrolled yet</td></tr>`}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Enrol Student</h2>
            ${availableStudents.length > 0 ? `
            <form method="post" action="/school-enrol-student">
              <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
              <label>Student</label>
              <select name="student_id" required>${studentOptions}</select>
              <button type="submit">Enrol student</button>
            </form>
            ` : `<p class="muted">All students are already enrolled in this course.</p>`}
          </div>
        `;
      }

      // --- Classes tab ---
      if (tab === "classes") {
        const allClasses = await all(
          `SELECT id, name, year_group FROM classes WHERE tenant_id=? AND status='ACTIVE' ORDER BY name ASC`,
          [active.tenant_id]
        );

        // For each class, check how many of its students are enrolled in this course
        const classRows = [];
        for (const cls of allClasses) {
          const totalInClass = await first(
            `SELECT COUNT(*) AS cnt FROM class_students WHERE class_id=?`, [cls.id]
          );
          const enrolledFromClass = await first(
            `SELECT COUNT(*) AS cnt FROM class_students cs
             JOIN enrollments e ON e.user_id=cs.user_id AND e.course_id=?
             WHERE cs.class_id=?`, [courseId, cls.id]
          );
          if (enrolledFromClass.cnt > 0) {
            classRows.push(`
              <tr>
                <td><b>${escapeHtml(cls.name)}</b>${cls.year_group ? ` <span class="muted small">(${escapeHtml(cls.year_group)})</span>` : ""}</td>
                <td>${enrolledFromClass.cnt} / ${totalInClass.cnt} students enrolled</td>
                <td>
                  <form method="post" action="/school-course-unenrol-class" onsubmit="return confirm('Remove this class from the course? This will unenrol ${enrolledFromClass.cnt} student(s).')">
                    <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
                    <input type="hidden" name="class_id" value="${escapeAttr(cls.id)}"/>
                    <button type="submit" class="btn3">Remove</button>
                  </form>
                </td>
              </tr>
            `);
          }
        }

        const classOptions = allClasses.map((c) =>
          `<option value="${escapeAttr(c.id)}">${escapeHtml(c.name)}${c.year_group ? ` (${escapeHtml(c.year_group)})` : ""}</option>`
        ).join("");

        tabContent = `
          <div class="card">
            <h2>Classes enrolled in this course</h2>
            <table class="table">
              <thead><tr><th>Class</th><th>Enrolment</th><th></th></tr></thead>
              <tbody>${classRows.join("") || `<tr><td colspan="3" class="muted">No classes enrolled yet</td></tr>`}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Enrol a Class</h2>
            <p class="muted small">This will enrol all students currently in the class into this course. Students already enrolled will be skipped.</p>
            ${allClasses.length > 0 ? `
            <form method="post" action="/school-course-enrol-class">
              <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
              <label>Class</label>
              <select name="class_id" required>${classOptions}</select>
              <button type="submit">Enrol class</button>
            </form>
            ` : `<p class="muted">No active classes found.</p>`}
          </div>
        `;
      }

      // --- Join Codes tab ---
      if (tab === "join-codes") {
        const courseCodes = await all(
          `SELECT jc.*, c.title AS course_title FROM join_codes jc
           LEFT JOIN courses c ON c.id=jc.course_id
           WHERE jc.tenant_id=? AND jc.course_id=? AND jc.revoked=0
           ORDER BY jc.created_at DESC`,
          [active.tenant_id, courseId]
        );
        const activeCourseCodes = courseCodes.filter((c) => !isIsoInPast(c.expires_at));
        const returnTo = `/school-course?course_id=${courseId}&tab=join-codes`;

        const codeRows = activeCourseCodes.map((c) => `
          <tr>
            <td><b>${escapeHtml(describeCode(c.scope, c.role, c.course_title))}</b></td>
            <td class="small">
              Expires: ${escapeHtml(fmtISO(c.expires_at))}<br/>
              Uses: ${escapeHtml(c.uses_approved)}/${escapeHtml(c.max_uses)}
            </td>
            <td><span class="pill">${Number(c.auto_approve) === 1 ? "Auto-approve" : "Needs approval"}</span></td>
            <td>
              <form method="post" action="/school-revoke-code" onsubmit="return confirm('Revoke this code?')">
                <input type="hidden" name="code_id" value="${escapeAttr(c.id)}"/>
                <input type="hidden" name="return_to" value="${escapeAttr(returnTo)}"/>
                <button type="submit" class="btn3">Revoke</button>
              </form>
            </td>
          </tr>
        `).join("");

        tabContent = `
          <div class="card">
            <h2>Join Codes for this Course</h2>
            <table class="table">
              <thead><tr><th>Description</th><th>Limits</th><th>Approval</th><th></th></tr></thead>
              <tbody>${codeRows || `<tr><td colspan="4" class="muted">No active codes for this course</td></tr>`}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Create Code for this Course</h2>
            <form method="post" action="/school-create-code">
              <input type="hidden" name="action" value="course"/>
              <input type="hidden" name="course_id" value="${escapeAttr(courseId)}"/>
              <input type="hidden" name="return_to" value="${escapeAttr(returnTo)}"/>
              <label>Who is this code for?</label>
              <select name="who" required>
                <option value="student">Student</option>
                <option value="teacher">Teacher</option>
              </select>
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
          </div>
        `;
      }

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-courses")}

        <div class="card">
          <div class="topbar">
            <div>
              <h1>${escapeHtml(course.title)}</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(course.status)}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/school-courses">← Back to courses</a>
            </div>
          </div>
        </div>

        <div class="card" style="display:flex;flex-wrap:wrap;gap:4px;padding:10px 14px">
          ${tabNav}
        </div>

        ${tabContent}
      `);
    }

    // =============================
    // School Admin — Classes
    // =============================
    if (path === "/school-classes") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const classes = await all(
        `SELECT c.id, c.name, c.year_group, c.academic_year, c.status,
                COUNT(cs.id) AS student_count
         FROM classes c
         LEFT JOIN class_students cs ON cs.class_id = c.id
         WHERE c.tenant_id=? GROUP BY c.id ORDER BY c.name ASC`,
        [tenantId]
      );

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
        ${schoolHeader(r, active)}
        ${schoolNav("/school-classes")}

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
      `);
    }

    // =============================
    // School Admin — People
    // =============================
    if (path === "/school-people") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;
      const tab = url.searchParams.get("tab") || "members";
      const tabItems = ["members", "add"];
      const tabLabels = { "members": "Members", "add": "Add Person" };
      const tabNav = tabItems.map((t) => {
        const active_ = t === tab;
        const label = tabLabels[t] || t;
        return `<a href="/school-people?tab=${t}" style="padding:6px 12px;border-radius:8px;text-decoration:none;white-space:nowrap${active_ ? ";background:rgba(0,0,0,.07);font-weight:700" : ""}">${label}</a>`;
      }).join("");

      let tabContent = "";

      // --- Members tab ---
      if (tab === "members") {
        const filterRole = url.searchParams.get("role") || "";
        const filterCourseId = url.searchParams.get("course_id") || "";
        const filterClassId = url.searchParams.get("class_id") || "";

        // Build filtered member query
        let sql = `SELECT DISTINCT u.id, u.name, u.email, m.role
                   FROM memberships m JOIN users u ON u.id=m.user_id
                   WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'`;
        const params = [tenantId];

        if (filterRole) {
          sql += ` AND m.role=?`;
          params.push(filterRole);
        }
        if (filterCourseId) {
          sql += ` AND (EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id=m.user_id AND e.course_id=?)
                    OR EXISTS (SELECT 1 FROM course_teachers ct WHERE ct.user_id=m.user_id AND ct.course_id=?))`;
          params.push(filterCourseId, filterCourseId);
        }
        if (filterClassId) {
          sql += ` AND EXISTS (SELECT 1 FROM class_students cs WHERE cs.user_id=m.user_id AND cs.class_id=?)`;
          params.push(filterClassId);
        }
        sql += ` ORDER BY m.role ASC, u.name ASC`;

        const members = await all(sql, params);
        const memberIds = members.map((m) => m.id);

        // Batch context queries — courses and classes per member
        const coursesByUser = {};
        const classesByUser = {};

        if (memberIds.length > 0) {
          const placeholders = memberIds.map(() => "?").join(",");

          const enrolledCourses = await all(
            `SELECT e.user_id, c.title FROM enrollments e JOIN courses c ON c.id=e.course_id
             WHERE e.user_id IN (${placeholders}) AND c.status='ACTIVE' ORDER BY c.title ASC`,
            memberIds
          );
          const taughtCourses = await all(
            `SELECT ct.user_id, c.title FROM course_teachers ct JOIN courses c ON c.id=ct.course_id
             WHERE ct.user_id IN (${placeholders}) AND c.status='ACTIVE' ORDER BY c.title ASC`,
            memberIds
          );
          const memberClasses = await all(
            `SELECT cs.user_id, cl.name FROM class_students cs JOIN classes cl ON cl.id=cs.class_id
             WHERE cs.user_id IN (${placeholders}) AND cl.status='ACTIVE' ORDER BY cl.name ASC`,
            memberIds
          );

          for (const row of enrolledCourses) {
            if (!coursesByUser[row.user_id]) coursesByUser[row.user_id] = [];
            coursesByUser[row.user_id].push(row.title);
          }
          for (const row of taughtCourses) {
            if (!coursesByUser[row.user_id]) coursesByUser[row.user_id] = [];
            if (!coursesByUser[row.user_id].includes(row.title)) coursesByUser[row.user_id].push(row.title);
          }
          for (const row of memberClasses) {
            if (!classesByUser[row.user_id]) classesByUser[row.user_id] = [];
            classesByUser[row.user_id].push(row.name);
          }
        }

        // Filter options
        const allCourses = await all("SELECT id, title FROM courses WHERE tenant_id=? AND status='ACTIVE' ORDER BY title ASC", [tenantId]);
        const allClasses = await all("SELECT id, name FROM classes WHERE tenant_id=? AND status='ACTIVE' ORDER BY name ASC", [tenantId]);

        const roleFilterOptions = [
          `<option value="">All roles</option>`,
          `<option value="STUDENT"${filterRole === "STUDENT" ? " selected" : ""}>Student</option>`,
          `<option value="TEACHER"${filterRole === "TEACHER" ? " selected" : ""}>Teacher</option>`,
          `<option value="SCHOOL_ADMIN"${filterRole === "SCHOOL_ADMIN" ? " selected" : ""}>School Admin</option>`,
        ].join("");

        const courseFilterOptions = [`<option value="">All courses</option>`].concat(
          allCourses.map((c) => `<option value="${escapeAttr(c.id)}"${filterCourseId === c.id ? " selected" : ""}>${escapeHtml(c.title)}</option>`)
        ).join("");

        const classFilterOptions = [`<option value="">All classes</option>`].concat(
          allClasses.map((c) => `<option value="${escapeAttr(c.id)}"${filterClassId === c.id ? " selected" : ""}>${escapeHtml(c.name)}</option>`)
        ).join("");

        const memberRows = members.map((m) => {
          const self = m.id === r.user.id;
          const userCourses = coursesByUser[m.id] || [];
          const userClasses = classesByUser[m.id] || [];
          const contextPills = [
            ...userCourses.map((t) => `<span class="pill" style="font-size:11px">${escapeHtml(t)}</span>`),
            ...userClasses.map((n) => `<span class="pill" style="font-size:11px;background:rgba(0,0,0,.05)">${escapeHtml(n)}</span>`),
          ].join(" ");

          return `
            <tr>
              <td>
                <b>${escapeHtml(m.name)}</b>${self ? ` <span class="pill">You</span>` : ``}<br/>
                <span class="muted small">${escapeHtml(m.email)}</span>
                ${contextPills ? `<div style="margin-top:4px">${contextPills}</div>` : ""}
              </td>
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

        tabContent = `
          <div class="card">
            <h2>Filter</h2>
            <form method="get" action="/school-people">
              <input type="hidden" name="tab" value="members"/>
              <div class="row">
                <div>
                  <label>Role</label>
                  <select name="role">${roleFilterOptions}</select>
                </div>
                <div>
                  <label>Course</label>
                  <select name="course_id">${courseFilterOptions}</select>
                </div>
                <div>
                  <label>Class</label>
                  <select name="class_id">${classFilterOptions}</select>
                </div>
              </div>
              <button type="submit">Apply filters</button>
            </form>
          </div>
          <div class="card">
            <h2>Members (${members.length})</h2>
            <table class="table">
              <thead><tr><th>Member</th><th>Role</th><th></th></tr></thead>
              <tbody>${memberRows || `<tr><td colspan="3" class="muted">No members match the filters</td></tr>`}</tbody>
            </table>
          </div>
        `;
      }

      // --- Add Person tab ---
      if (tab === "add") {
        const checkEmail = url.searchParams.get("email") || "";
        const exists = url.searchParams.get("exists") || "";
        const userName = url.searchParams.get("user_name") || "";

        let addContent = "";

        if (!checkEmail) {
          // Step 1: email check form
          addContent = `
            <div class="card">
              <h2>Add Person</h2>
              <p class="muted small">Enter their email to check if they already have an account.</p>
              <form method="post" action="/school-check-email">
                <label>Email</label>
                <input name="email" type="email" required placeholder="user@example.com" />
                <button type="submit">Check email</button>
              </form>
            </div>
          `;
        } else if (exists === "1") {
          // Step 2a: existing user — just assign role
          addContent = `
            <div class="card">
              <h2>Add Existing User</h2>
              <p>Found: <b>${escapeHtml(userName)}</b> (${escapeHtml(checkEmail)})</p>
              <p class="muted small">This person already has an account. Just choose their role at this school.</p>
              <form method="post" action="/school-add-existing-user">
                <input type="hidden" name="email" value="${escapeAttr(checkEmail)}"/>
                <label>Role</label>
                <select name="role" required>
                  <option value="STUDENT">Student</option>
                  <option value="TEACHER">Teacher</option>
                  <option value="SCHOOL_ADMIN">School Admin</option>
                </select>
                <button type="submit">Add to school</button>
              </form>
              <p style="margin-top:10px"><a href="/school-people?tab=add">Check a different email</a></p>
            </div>
          `;
        } else {
          // Step 2b: new user — full form
          addContent = `
            <div class="card">
              <h2>Create New User</h2>
              <p class="muted small">No account found for <b>${escapeHtml(checkEmail)}</b>. Fill in the details to create one.</p>
              <form method="post" action="/school-add-user">
                <input type="hidden" name="email" value="${escapeAttr(checkEmail)}"/>
                <label>Full name</label>
                <input name="name" required />
                <label>Role</label>
                <select name="role" required>
                  <option value="STUDENT">Student</option>
                  <option value="TEACHER">Teacher</option>
                  <option value="SCHOOL_ADMIN">School Admin</option>
                </select>
                <label>Temporary password</label>
                <input name="password" type="text" required minlength="6" />
                <button type="submit">Create user + add to school</button>
              </form>
              <p style="margin-top:10px"><a href="/school-people?tab=add">Check a different email</a></p>
            </div>
          `;
        }

        tabContent = addContent;
      }

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-people")}

        <div class="card" style="display:flex;flex-wrap:wrap;gap:4px;padding:10px 14px">
          ${tabNav}
        </div>

        ${tabContent}
      `);
    }

    // =============================
    // School Admin — Join Codes
    // =============================
    if (path === "/school-join-codes") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const courses = await all("SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC", [tenantId]);
      const courseOptions = courses.filter((c) => c.status === "ACTIVE").map((c) =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const codes = await all(
        `SELECT jc.*, c.title AS course_title FROM join_codes jc
         LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.tenant_id=? ORDER BY jc.created_at DESC`,
        [tenantId]
      );

      const activeCodes = codes.filter((c) => Number(c.revoked) !== 1 && !isIsoInPast(c.expires_at));
      const activeCodesRows = activeCodes.map((c) => `
        <tr>
          <td><b>${escapeHtml(describeCode(c.scope, c.role, c.course_title))}</b></td>
          <td class="small">
            Expires: ${escapeHtml(fmtISO(c.expires_at))}<br/>
            Uses: ${escapeHtml(c.uses_approved)}/${escapeHtml(c.max_uses)}
          </td>
          <td><span class="pill">${Number(c.auto_approve) === 1 ? "Auto-approve" : "Needs approval"}</span></td>
          <td>
            <form method="post" action="/school-revoke-code" onsubmit="return confirm('Revoke this code?')">
              <input type="hidden" name="code_id" value="${escapeAttr(c.id)}"/>
              <button type="submit" class="btn3">Revoke</button>
            </form>
          </td>
        </tr>
      `).join("");

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

      const pendingRows = pending.map((x) => {
        const reqDesc = x.course_title
          ? `${escapeHtml(roleLabel(x.requested_role))} access to ${escapeHtml(x.course_title)}`
          : `${escapeHtml(roleLabel(x.requested_role))} access to school`;
        return `
        <tr>
          <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
          <td class="small">
            ${reqDesc}
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
      `;
      }).join("");

      const historyRows = history.map((x) => {
        const hDesc = x.course_title
          ? `${escapeHtml(roleLabel(x.requested_role))} access to ${escapeHtml(x.course_title)}`
          : `${escapeHtml(roleLabel(x.requested_role))} access to school`;
        return `
        <tr>
          <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
          <td class="small">${hDesc}</td>
          <td class="small">
            <span class="pill">${escapeHtml(x.status)}</span><br/>
            <span class="muted">Reviewed: ${escapeHtml(fmtISO(x.reviewed_at || ""))}</span>
          </td>
        </tr>
      `;
      }).join("");

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-join-codes")}

        <div class="card">
          <h2>Active Codes</h2>
          <p class="muted small">Codes are stored hashed — the plaintext is only shown at creation time.</p>
          <table class="table">
            <thead><tr><th>Description</th><th>Limits</th><th>Approval</th><th></th></tr></thead>
            <tbody>${activeCodesRows || `<tr><td colspan="4" class="muted">No active codes</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Create Code</h2>
          <form method="post" action="/school-create-code">
            <label>Who is this code for?</label>
            <select name="who" required>
              <option value="student">Student</option>
              <option value="teacher">Teacher</option>
            </select>
            <label>What should happen when they join?</label>
            <select name="action" required>
              <option value="school">Join the school only</option>
              <option value="course">Join the school AND enrol in a specific course</option>
            </select>
            <label>Course (only needed if enrolling in a course)</label>
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
        </div>

        <div class="card">
          <h2>Pending Requests</h2>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Actions</th></tr></thead>
            <tbody>${pendingRows || `<tr><td colspan="3" class="muted">No pending requests</td></tr>`}</tbody>
          </table>
          ${history.length > 0 ? `
          <h3 style="margin:14px 0 6px;font-size:14px">History</h3>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Status</th></tr></thead>
            <tbody>${historyRows}</tbody>
          </table>
          ` : ""}
        </div>
      `);
    }

    if (path === "/school-create-code" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const who = (f.who || "").trim();
      const action = (f.action || "").trim();
      const courseId = (f.course_id || "").trim();
      const returnTo = (f.return_to || "").trim();
      const autoApprove = Number(f.auto_approve || "0") === 1 ? 1 : 0;
      const expDays = Math.max(1, parseInt(f.exp_days || `${JOIN_CODE_DEFAULT_EXP_DAYS}`, 10) || JOIN_CODE_DEFAULT_EXP_DAYS);
      const maxUses = Math.max(1, parseInt(f.max_uses || `${JOIN_CODE_DEFAULT_MAX_USES}`, 10) || JOIN_CODE_DEFAULT_MAX_USES);
      const backLink = returnTo || "/school-join-codes";

      let scope = "", role = "", course_id = null;
      if (who === "student" && action === "school") { scope = "TENANT_ROLE"; role = "STUDENT"; }
      else if (who === "student" && action === "course") { scope = "COURSE_ENROLL"; role = "STUDENT"; course_id = courseId || null; }
      else if (who === "teacher" && action === "school") { scope = "TENANT_ROLE"; role = "TEACHER"; }
      else if (who === "teacher" && action === "course") { scope = "COURSE_TEACHER"; role = "TEACHER"; course_id = courseId || null; }
      else return redirect(backLink);

      if ((scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") && !course_id) {
        return page(`<div class="card err"><b>Please select a course.</b></div><p><a href="${escapeAttr(backLink)}">Back</a></p>`, 400);
      }
      if (scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") {
        const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [course_id, active.tenant_id]);
        if (!c) return page(`<div class="card err"><b>Course not found or inactive.</b></div><p><a href="${escapeAttr(backLink)}">Back</a></p>`, 400);
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
          <p class="actions"><a href="${escapeAttr(backLink)}">Back</a></p>
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
      const returnTo = (f.return_to || "").trim();
      if (!codeId) return redirect("/school-join-codes");
      await run("UPDATE join_codes SET revoked=1, updated_at=? WHERE id=? AND tenant_id=?", [nowISO(), codeId, active.tenant_id]);
      return redirect(returnTo || "/school-join-codes");
    }

    if (path === "/school-approve-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school-join-codes");

      const jr = await first(`SELECT * FROM join_requests WHERE id=? AND tenant_id=? AND status='PENDING'`, [reqId, active.tenant_id]);
      if (!jr) return redirect("/school-join-codes");

      const jc = await first(
        `SELECT jc.*, t.name AS tenant_name, c.title AS course_title
         FROM join_codes jc JOIN tenants t ON t.id=jc.tenant_id LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.id=? AND jc.tenant_id=?`,
        [jr.join_code_id, active.tenant_id]
      );
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(v.why)}</div><p><a href="/school-join-codes">Back</a></p>`, 400);

      const reserved = await reserveJoinCodeUse(jc.id);
      if (!reserved) return page(`<div class="card err"><b>Cannot approve:</b> Code is no longer available.</div><p><a href="/school-join-codes">Back</a></p>`, 400);

      const applied = await applyJoinActionForUser(jr.user_id, jc);
      if (!applied.ok) {
        await unreserveJoinCodeUse(jc.id);
        return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(applied.msg)}</div><p><a href="/school-join-codes">Back</a></p>`, 400);
      }

      await run("UPDATE join_requests SET status='APPROVED', reviewed_by_user_id=?, reviewed_at=? WHERE id=?", [r.user.id, nowISO(), reqId]);
      return redirect("/school-join-codes");
    }

    if (path === "/school-reject-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school-join-codes");
      await run(
        "UPDATE join_requests SET status='REJECTED', reviewed_by_user_id=?, reviewed_at=? WHERE id=? AND tenant_id=? AND status='PENDING'",
        [r.user.id, nowISO(), reqId, active.tenant_id]
      );
      return redirect("/school-join-codes");
    }

    if (path === "/school-update-member-role" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const userId = (f.user_id || "").trim();
      const role = (f.role || "").trim();
      if (!userId || !["STUDENT", "TEACHER", "SCHOOL_ADMIN"].includes(role)) return redirect("/school-people");
      if (userId === r.user.id && role !== "SCHOOL_ADMIN") {
        return page(`<div class="card err"><b>You cannot remove your own School Admin role.</b></div><p><a href="/school-people">Back</a></p>`, 400);
      }
      const m = await first(
        "SELECT id FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [active.tenant_id, userId]
      );
      if (!m) return redirect("/school-people");
      await run("UPDATE memberships SET role=?, updated_at=? WHERE id=?", [role, nowISO(), m.id]);
      return redirect("/school-people");
    }

    if (path === "/school-remove-member" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const userId = (f.user_id || "").trim();
      if (!userId) return redirect("/school-people");
      if (userId === r.user.id) return page(`<div class="card err"><b>You cannot remove yourself.</b></div><p><a href="/school-people">Back</a></p>`, 400);

      await run("UPDATE memberships SET status='REMOVED', updated_at=? WHERE tenant_id=? AND user_id=? AND status='ACTIVE'",
        [nowISO(), active.tenant_id, userId]);

      const courseIds = await all("SELECT id FROM courses WHERE tenant_id=?", [active.tenant_id]);
      for (const c of courseIds) {
        await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [c.id, userId]);
        await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [c.id, userId]);
      }
      return redirect("/school-people");
    }

    // =============================
    // Course: update (POST)
    // =============================
    if (path === "/school-update-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "").trim();
      const title = (f.title || "").trim();
      const status = (f.status || "").trim();
      if (!courseId || !title) return redirect("/school-courses");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school-courses");
      if (!["ACTIVE", "ARCHIVED"].includes(status)) return redirect(`/school-course?course_id=${courseId}`);
      await run("UPDATE courses SET title=?, status=?, updated_at=? WHERE id=?", [title, status, nowISO(), courseId]);
      return redirect(`/school-course?course_id=${courseId}&tab=details`);
    }

    // =============================
    // Course: enrol class (POST) — from course detail page
    // =============================
    if (path === "/school-course-enrol-class" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const courseId = (f.course_id || "").trim();
      if (!classId || !courseId) return redirect("/school-courses");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-courses");

      const course = await first(
        `SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'`,
        [courseId, active.tenant_id]
      );
      if (!course) return redirect(`/school-course?course_id=${courseId}&tab=classes`);

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
      return redirect(`/school-course?course_id=${courseId}&tab=classes`);
    }

    if (path === "/school-unassign-teacher" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school-courses");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school-courses");
      await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect(`/school-course?course_id=${courseId}&tab=teachers`);
    }

    if (path === "/school-unenrol-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school-courses");
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school-courses");
      await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect(`/school-course?course_id=${courseId}&tab=students`);
    }

    // =============================
    // People: check email (POST)
    // =============================
    if (path === "/school-check-email" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const email = (f.email || "").toLowerCase().trim();
      if (!email) return redirect("/school-people?tab=add");
      const u = await first("SELECT id, name FROM users WHERE email=? AND status='ACTIVE'", [email]);
      if (u) {
        return redirect(`/school-people?tab=add&email=${encodeURIComponent(email)}&exists=1&user_name=${encodeURIComponent(u.name)}`);
      }
      return redirect(`/school-people?tab=add&email=${encodeURIComponent(email)}&exists=0`);
    }

    // =============================
    // People: add existing user (POST)
    // =============================
    if (path === "/school-add-existing-user" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;
      const f = await form();
      const email = (f.email || "").toLowerCase().trim();
      const role = (f.role || "");
      if (!email || !["TEACHER", "STUDENT", "SCHOOL_ADMIN"].includes(role)) {
        return redirect("/school-people?tab=add");
      }

      const u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
      if (!u) return redirect("/school-people?tab=add");

      const ts = nowISO();
      const m = await first("SELECT id,status FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1", [u.id, tenantId]);
      if (!m) {
        await run("INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), u.id, tenantId, role, ts, ts]);
      } else {
        await run("UPDATE memberships SET role=?, status='ACTIVE', updated_at=? WHERE id=?", [role, ts, m.id]);
      }
      return redirect("/school-people?tab=members");
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
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/school-people">Back</a></p>`, 400);
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
      return redirect("/school-people?tab=members");
    }

    if (path === "/school-create-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");
      const f = await form();
      const title = (f.title || "");
      if (!title) return redirect("/school-courses");
      const ts = nowISO();
      await run("INSERT INTO courses (id,tenant_id,title,status,created_at,updated_at) VALUES (?,?,?,'ACTIVE',?,?)",
        [uuid(), active.tenant_id, title, ts, ts]);
      return redirect("/school-courses");
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
      if (!c) return redirect("/school-courses");
      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('TEACHER','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [teacherId, active.tenant_id]
      );
      if (!m) return redirect("/school-courses");
      const ex = await first("SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1", [courseId, teacherId]);
      if (!ex) {
        await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, teacherId, nowISO()]);
      }
      return redirect(`/school-course?course_id=${courseId}&tab=teachers`);
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
      if (!c) return redirect("/school-courses");
      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('STUDENT','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [studentId, active.tenant_id]
      );
      if (!m) return redirect("/school-courses");
      const ex = await first("SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=? LIMIT 1", [courseId, studentId]);
      if (!ex) {
        await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, studentId, nowISO()]);
      }
      return redirect(`/school-course?course_id=${courseId}&tab=students`);
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
      if (!name) return redirect("/school-classes");

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
      return redirect("/school-classes");
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
      if (!classId) return redirect("/school-classes");

      const cls = await first(`SELECT * FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

      const tab = url.searchParams.get("tab") || "details";
      const tabs = ["details", "students", "courses"];
      const tabNav = tabs.map((t) => {
        const active_ = t === tab;
        const label = t.charAt(0).toUpperCase() + t.slice(1);
        return `<a href="/school-class?class_id=${escapeAttr(classId)}&tab=${t}" style="padding:6px 12px;border-radius:8px;text-decoration:none;white-space:nowrap${active_ ? ";background:rgba(0,0,0,.07);font-weight:700" : ""}">${label}</a>`;
      }).join("");

      let tabContent = "";

      // --- Details tab ---
      if (tab === "details") {
        const archiveLabel = cls.status === "ACTIVE" ? "Archive class" : "Unarchive class";
        tabContent = `
          <div class="card">
            <h2>Class Details</h2>
            <form method="post" action="/school-update-class">
              <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
              <label>Name</label>
              <input name="name" value="${escapeAttr(cls.name)}" required />
              <label>Year Group</label>
              <input name="year_group" value="${escapeAttr(cls.year_group || "")}" />
              <label>Academic Year</label>
              <input name="academic_year" value="${escapeAttr(cls.academic_year || "")}" />
              <label>Description</label>
              <textarea name="description" rows="3">${escapeHtml(cls.description || "")}</textarea>
              <button type="submit">Save changes</button>
            </form>
          </div>
          <div class="card">
            <h2>Archive</h2>
            <form method="post" action="/school-class-archive" onsubmit="return confirm('${cls.status === "ACTIVE" ? "Archive" : "Unarchive"} this class?')">
              <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
              <button type="submit" class="btn3">${escapeHtml(archiveLabel)}</button>
            </form>
          </div>
        `;
      }

      // --- Students tab ---
      if (tab === "students") {
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

        const studentRows = classStudents.map((s) => `
          <tr>
            <td><b>${escapeHtml(s.name)}</b></td>
            <td><span class="muted small">${escapeHtml(s.email)}</span></td>
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

        tabContent = `
          <div class="card">
            <h2>Students (${classStudents.length})</h2>
            <table class="table">
              <thead><tr><th>Name</th><th>Email</th><th></th></tr></thead>
              <tbody>${studentRows || `<tr><td colspan="3" class="muted">No students in this class yet</td></tr>`}</tbody>
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
        `;
      }

      // --- Courses tab ---
      if (tab === "courses") {
        const allCourses = await all(
          `SELECT id, title FROM courses WHERE tenant_id=? AND status='ACTIVE' ORDER BY title ASC`,
          [active.tenant_id]
        );

        const classStudentIds = await all(`SELECT user_id FROM class_students WHERE class_id=?`, [classId]);
        const totalInClass = classStudentIds.length;

        const courseRows = [];
        for (const c of allCourses) {
          const enrolledFromClass = await first(
            `SELECT COUNT(*) AS cnt FROM class_students cs
             JOIN enrollments e ON e.user_id=cs.user_id AND e.course_id=?
             WHERE cs.class_id=?`, [c.id, classId]
          );
          if (enrolledFromClass.cnt > 0) {
            courseRows.push(`
              <tr>
                <td><a href="/school-course?course_id=${escapeAttr(c.id)}&tab=classes"><b>${escapeHtml(c.title)}</b></a></td>
                <td>${enrolledFromClass.cnt} / ${totalInClass} students enrolled</td>
                <td>
                  <form method="post" action="/school-class-unenrol-course" onsubmit="return confirm('Unlink this course from the class? This will unenrol ${enrolledFromClass.cnt} student(s).')">
                    <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
                    <input type="hidden" name="course_id" value="${escapeAttr(c.id)}"/>
                    <button type="submit" class="btn3">Unlink</button>
                  </form>
                </td>
              </tr>
            `);
          }
        }

        const courseOptions = allCourses.map((c) =>
          `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
        ).join("");

        tabContent = `
          <div class="card">
            <h2>Courses linked to this class</h2>
            <table class="table">
              <thead><tr><th>Course</th><th>Enrolment</th><th></th></tr></thead>
              <tbody>${courseRows.join("") || `<tr><td colspan="3" class="muted">No courses linked yet</td></tr>`}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Enrol Class in Course</h2>
            <p class="muted small">This will enrol all students currently in the class into the course. Students already enrolled will be skipped.</p>
            ${allCourses.length > 0 ? `
            <form method="post" action="/school-class-enrol-course">
              <input type="hidden" name="class_id" value="${escapeAttr(classId)}"/>
              <label>Course</label>
              <select name="course_id" required>${courseOptions}</select>
              <button type="submit">Enrol all students in course</button>
            </form>
            ` : `<p class="muted">No active courses found.</p>`}
          </div>
        `;
      }

      return page(`
        ${schoolHeader(r, active)}
        ${schoolNav("/school-classes")}

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
              <a href="/school-classes">← Back to classes</a>
            </div>
          </div>
        </div>

        <div class="card" style="display:flex;flex-wrap:wrap;gap:4px;padding:10px 14px">
          ${tabNav}
        </div>

        ${tabContent}
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
      if (!classId || !userId) return redirect("/school-classes");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

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
      return redirect(`/school-class?class_id=${classId}&tab=students`);
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
      if (!classId || !userId) return redirect("/school-classes");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

      await run(`DELETE FROM class_students WHERE class_id=? AND user_id=?`, [classId, userId]);
      return redirect(`/school-class?class_id=${classId}&tab=students`);
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
      if (!classId || !courseId) return redirect("/school-classes");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

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
      return redirect(`/school-class?class_id=${classId}&tab=courses`);
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
      if (!classId) return redirect("/school-classes");

      const cls = await first(`SELECT id, status FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

      const newStatus = cls.status === "ACTIVE" ? "ARCHIVED" : "ACTIVE";
      const ts = nowISO();
      await run(`UPDATE classes SET status=?, updated_at=? WHERE id=?`, [newStatus, ts, classId]);
      return redirect("/school-classes");
    }

    // =============================
    // Class: update details (POST)
    // =============================
    if (path === "/school-update-class" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const name = (f.name || "").trim();
      if (!classId || !name) return redirect("/school-classes");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

      const ts = nowISO();
      await run(
        `UPDATE classes SET name=?, year_group=?, academic_year=?, description=?, updated_at=? WHERE id=?`,
        [name, (f.year_group || "").trim() || null, (f.academic_year || "").trim() || null, (f.description || "").trim() || null, ts, classId]
      );
      return redirect(`/school-class?class_id=${classId}&tab=details`);
    }

    // =============================
    // Class: unenrol from course (POST) — from class page
    // =============================
    if (path === "/school-class-unenrol-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const classId = (f.class_id || "").trim();
      const courseId = (f.course_id || "").trim();
      if (!classId || !courseId) return redirect("/school-classes");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-classes");

      const classStudents = await all(`SELECT user_id FROM class_students WHERE class_id=?`, [classId]);
      for (const s of classStudents) {
        await run(`DELETE FROM enrollments WHERE course_id=? AND user_id=?`, [courseId, s.user_id]);
      }
      return redirect(`/school-class?class_id=${classId}&tab=courses`);
    }

    // =============================
    // Course: unenrol class (POST) — from course page
    // =============================
    if (path === "/school-course-unenrol-class" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "").trim();
      const classId = (f.class_id || "").trim();
      if (!courseId || !classId) return redirect("/school-courses");

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect("/school-courses");

      const classStudents = await all(`SELECT user_id FROM class_students WHERE class_id=?`, [classId]);
      for (const s of classStudents) {
        await run(`DELETE FROM enrollments WHERE course_id=? AND user_id=?`, [courseId, s.user_id]);
      }
      return redirect(`/school-course?course_id=${courseId}&tab=classes`);
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
