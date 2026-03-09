// functions/teacher.js
// Teacher dashboard route

import { createHelpers } from "./shared.js";

export async function handleTeacherRequest(ctx) {
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
    // Teacher dashboard
    // =============================
    if (path === "/teacher") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "TEACHER") return redirect("/");

      const courses = await all(
        `SELECT c.id, c.title
         FROM course_teachers ct JOIN courses c ON c.id = ct.course_id
         WHERE ct.user_id=? AND c.tenant_id=? AND c.status='ACTIVE'
         ORDER BY c.title ASC`,
        [r.user.id, active.tenant_id]
      );

      const exams = await all(
        `SELECT e.id, e.title, e.status, e.duration_mins, e.starts_at, e.ends_at,
                c.title AS course_title, es.title AS sitting_title
         FROM exams e
         JOIN courses c ON c.id = e.course_id
         JOIN course_teachers ct ON ct.course_id = e.course_id AND ct.user_id = ?
         LEFT JOIN exam_sitting_papers esp ON esp.exam_id = e.id
         LEFT JOIN exam_sittings es ON es.id = esp.sitting_id
         WHERE e.tenant_id=?
         ORDER BY e.created_at DESC`,
        [r.user.id, active.tenant_id]
      );

      const courseOptions = courses.map((c) =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const examRows = exams.map((e) => `
        <tr>
          <td>
            <b>${escapeHtml(e.title)}</b><br/>
            <span class="muted small">${escapeHtml(e.course_title)}</span>
            ${e.sitting_title ? `<div style="margin-top:2px"><span style="font-size:12px;color:rgba(0,0,0,.45)">&#128203; ${escapeHtml(e.sitting_title)}</span></div>` : ""}
          </td>
          <td class="small"><span class="pill">${escapeHtml(e.status)}</span></td>
          <td class="small">
            ${e.duration_mins} mins<br/>
            ${e.starts_at ? `Opens: ${escapeHtml(fmtISO(e.starts_at))}` : `<span class="muted">No schedule</span>`}
          </td>
          <td>
            <a href="/exam-builder?exam_id=${escapeAttr(e.id)}" class="btn2" style="display:inline-block;padding:8px 12px;border-radius:10px;background:#0b7a75;color:#fff;font-weight:700;text-decoration:none">Open</a>
          </td>
        </tr>
      `).join("");

      const _teacherPaCnt = await first(
        `SELECT COUNT(*) AS cnt FROM sitting_approval_gates sag
         JOIN sitting_approval_responses sar
           ON sar.exam_id=sag.exam_id AND sar.gate_type=sag.gate_type
          AND sar.approver_id=sag.user_id AND sar.tenant_id=sag.tenant_id
         WHERE sag.user_id=? AND sag.tenant_id=? AND sar.status='PENDING'`,
        [r.user.id, active.tenant_id]
      );
      const _teacherPaNum = Number((_teacherPaCnt || {}).cnt);
      const teacherApprovalBanner = _teacherPaNum > 0
        ? `<div class="card" style="background:#fffbea;border:1px solid #f0c040;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;flex-wrap:wrap"><span style="font-weight:600;font-size:14px">&#128236; You have ${_teacherPaNum} pending approval${_teacherPaNum !== 1 ? "s" : ""}</span><a href="/approvals" class="btn2" style="display:inline-block;text-decoration:none;padding:7px 14px;font-size:13px;white-space:nowrap">View Inbox &#8594;</a></div>`
        : "";

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>Teacher</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ``}
              <a href="/question-bank">Question Bank</a>
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        ${teacherApprovalBanner}
        <div class="card">
          <h2>Create New Exam</h2>
          <form method="post" action="/exam-create">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>No courses assigned yet</option>"}</select>
            <label>Exam title</label>
            <input name="title" placeholder="e.g. Term 1 Mathematics Exam" required />
            <button type="submit" style="margin-top:10px">Create exam</button>
          </form>
        </div>

        <div class="card">
          <h2>My Exams</h2>
          <table class="table">
            <thead><tr><th>Title</th><th>Status</th><th>Details</th><th></th></tr></thead>
            <tbody>${examRows || `<tr><td colspan="4" class="muted">No exams yet — create one above</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>My assigned courses</h2>
          <ul>${courses.map((x) => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
        </div>
      `);
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
