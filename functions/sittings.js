// functions/sittings.js
// Exam Sittings — School Admin tool + Approval Inbox
// Routes: /sittings, /sitting-builder, /sitting-create,
//         /sitting-save-settings, /sitting-add-paper, /sitting-remove-paper,
//         /sitting-gate-save, /sitting-gate-remove-approver,
//         /sitting-gate-settings,
//         /approvals, /approval-respond

import { createHelpers } from "./shared.js";

export async function handleSittingRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url  = new URL(request.url);
    const path = url.pathname;

    const {
      nowISO, uuid,
      page, redirect, escapeHtml, escapeAttr, fmtISO, form,
      first, all, run,
      requireLogin, pickActiveMembership,
    } = createHelpers(request, env);

    // ---- Auth guard: School Admin only ----
    async function requireAdmin() {
      const r = await requireLogin();
      if (!r.ok) return { ok: false, res: r.res };
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") {
        return { ok: false, res: redirect("/school") };
      }
      return { ok: true, r, active };
    }

    // ---- Badge helpers ----
    const sittingBadge = (s) => {
      if (s === "ACTIVE") return `<span class="pill" style="background:#d4f5e9;color:#0b5e4e">Active</span>`;
      if (s === "CLOSED") return `<span class="pill" style="background:#ffe8e8;color:#c00">Closed</span>`;
      return `<span class="pill" style="background:rgba(0,0,0,.07);color:rgba(0,0,0,.5)">Draft</span>`;
    };

    const examBadge = (s) => {
      if (s === "PUBLISHED") return `<span class="pill" style="background:#d4f5e9;color:#0b5e4e;font-size:11px">Published</span>`;
      if (s === "CLOSED")    return `<span class="pill" style="background:#ffe8e8;color:#c00;font-size:11px">Closed</span>`;
      return `<span class="pill" style="background:rgba(0,0,0,.07);color:rgba(0,0,0,.5);font-size:11px">Draft</span>`;
    };

    const roleLabel = (role) => {
      if (role === "SCHOOL_ADMIN") return "School Admin";
      if (role === "TEACHER")      return "Teacher";
      if (role === "STUDENT")      return "Student";
      return role || "";
    };

    // ----------------------------------------------------------------
    // GET /sittings — list all sittings
    // ----------------------------------------------------------------
    if (path === "/sittings" && request.method === "GET") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const sittings = await all(
        `SELECT es.*,
                (SELECT COUNT(*) FROM exam_sitting_papers esp WHERE esp.sitting_id = es.id) AS paper_count
         FROM exam_sittings es
         WHERE es.tenant_id=?
         ORDER BY es.created_at DESC`,
        [active.tenant_id]
      );

      const rows = sittings.map(s => `
        <tr>
          <td>
            <b>${escapeHtml(s.title)}</b>
            ${s.academic_year ? `<span class="muted small" style="margin-left:6px">${escapeHtml(s.academic_year)}</span>` : ""}
          </td>
          <td>${sittingBadge(s.status)}</td>
          <td class="small">${Number(s.paper_count)} paper${Number(s.paper_count) !== 1 ? "s" : ""}</td>
          <td class="small muted">${fmtISO(s.created_at)}</td>
          <td>
            <a href="/sitting-builder?sitting_id=${escapeAttr(s.id)}"
               class="btn2" style="display:inline-block;padding:6px 12px;text-decoration:none;font-size:13px">Open</a>
          </td>
        </tr>
      `).join("");

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>Exam Sittings</h1>
              <div class="muted"><span class="pill">${escapeHtml(active.tenant_name)}</span></div>
            </div>
            <div class="actions">
              <a href="/school">&#8592; School Admin</a>
            </div>
          </div>
        </div>
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
            <h2 style="margin:0">All Sittings</h2>
            <form method="post" action="/sitting-create">
              <button type="submit" class="btn2">+ New Sitting</button>
            </form>
          </div>
          <table class="table">
            <thead><tr><th>Title</th><th>Status</th><th>Papers</th><th>Created</th><th></th></tr></thead>
            <tbody>${rows || `<tr><td colspan="5" class="muted" style="text-align:center;padding:20px">No sittings yet — click &ldquo;New Sitting&rdquo; to get started</td></tr>`}</tbody>
          </table>
        </div>
      `);
    }

    // ----------------------------------------------------------------
    // POST /sitting-create
    // ----------------------------------------------------------------
    if (path === "/sitting-create" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const id = uuid();
      const ts = nowISO();
      await run(
        `INSERT INTO exam_sittings (id, tenant_id, title, description, academic_year, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'DRAFT', ?, ?, ?)`,
        [id, active.tenant_id, "New Sitting", null, null, r.user.id, ts, ts]
      );
      return redirect(`/sitting-builder?sitting_id=${id}&tab=settings`);
    }

    // ----------------------------------------------------------------
    // POST /sitting-save-settings
    // ----------------------------------------------------------------
    if (path === "/sitting-save-settings" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const f = await form();
      const sittingId = (f.sitting_id || "").trim();
      if (!sittingId) return redirect("/sittings");

      const sitting = await first(
        `SELECT id FROM exam_sittings WHERE id=? AND tenant_id=?`,
        [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      const title = (f.title || "").trim();
      if (!title) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=settings`);

      const description  = (f.description   || "").trim() || null;
      const academicYear = (f.academic_year  || "").trim() || null;
      const status = ["DRAFT", "ACTIVE", "CLOSED"].includes(f.status) ? f.status : "DRAFT";
      const ts = nowISO();

      await run(
        `UPDATE exam_sittings SET title=?, description=?, academic_year=?, status=?, updated_at=?
         WHERE id=? AND tenant_id=?`,
        [title, description, academicYear, status, ts, sittingId, active.tenant_id]
      );
      return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=settings`);
    }

    // ----------------------------------------------------------------
    // POST /sitting-add-paper
    // ----------------------------------------------------------------
    if (path === "/sitting-add-paper" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const f = await form();
      const sittingId = (f.sitting_id || "").trim();
      if (!sittingId) return redirect("/sittings");

      const sitting = await first(
        `SELECT id FROM exam_sittings WHERE id=? AND tenant_id=?`,
        [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      const mode = f.mode || "existing";
      const ts   = nowISO();

      if (mode === "existing") {
        const examId = (f.exam_id || "").trim();
        if (!examId) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);

        const exam = await first(`SELECT id FROM exams WHERE id=? AND tenant_id=?`, [examId, active.tenant_id]);
        if (!exam) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);

        const already = await first(
          `SELECT id FROM exam_sitting_papers WHERE sitting_id=? AND exam_id=?`,
          [sittingId, examId]
        );
        if (!already) {
          const maxRow = await first(
            `SELECT MAX(sort_order) AS mx FROM exam_sitting_papers WHERE sitting_id=?`, [sittingId]
          );
          const sortOrder = (maxRow && maxRow.mx !== null) ? Number(maxRow.mx) + 1 : 1;
          await run(
            `INSERT INTO exam_sitting_papers (id, sitting_id, exam_id, sort_order, created_at) VALUES (?, ?, ?, ?, ?)`,
            [uuid(), sittingId, examId, sortOrder, ts]
          );
        }

      } else if (mode === "create") {
        const title     = (f.title      || "").trim();
        const courseId  = (f.course_id  || "").trim();
        const teacherId = (f.teacher_id || "").trim();
        if (!title || !courseId || !teacherId) {
          return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);
        }

        const course = await first(`SELECT id FROM courses WHERE id=? AND tenant_id=?`, [courseId, active.tenant_id]);
        if (!course) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);

        const teacherMem = await first(
          `SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='TEACHER' AND status='ACTIVE'`,
          [teacherId, active.tenant_id]
        );
        if (!teacherMem) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);

        // Ensure teacher is assigned to the course (course_teachers PK is course_id, user_id)
        const alreadyCT = await first(
          `SELECT course_id FROM course_teachers WHERE course_id=? AND user_id=?`, [courseId, teacherId]
        );
        if (!alreadyCT) {
          await run(
            `INSERT INTO course_teachers (course_id, user_id, created_at) VALUES (?, ?, ?)`,
            [courseId, teacherId, ts]
          );
        }

        // Create exam — created_by = teacher (so it appears on their dashboard)
        const examId = uuid();
        await run(
          `INSERT INTO exams (id, tenant_id, course_id, created_by, title, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'DRAFT', ?, ?)`,
          [examId, active.tenant_id, courseId, teacherId, title, ts, ts]
        );

        // Link to sitting
        const maxRow = await first(
          `SELECT MAX(sort_order) AS mx FROM exam_sitting_papers WHERE sitting_id=?`, [sittingId]
        );
        const sortOrder = (maxRow && maxRow.mx !== null) ? Number(maxRow.mx) + 1 : 1;
        await run(
          `INSERT INTO exam_sitting_papers (id, sitting_id, exam_id, sort_order, created_at) VALUES (?, ?, ?, ?, ?)`,
          [uuid(), sittingId, examId, sortOrder, ts]
        );
      }

      return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);
    }

    // ----------------------------------------------------------------
    // POST /sitting-gate-save — add approver to a gate (or turn gate off)
    // ----------------------------------------------------------------
    if (path === "/sitting-gate-save" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const f = await form();
      const sittingId = (f.sitting_id || "").trim();
      const examId    = (f.exam_id    || "").trim();
      const gateType  = (f.gate_type  || "").trim();
      const userId    = (f.user_id    || "").trim();
      const enabled   = f.enabled === "1";

      if (!sittingId || !examId || !["QUESTIONS","GRADING","RESULTS"].includes(gateType)) {
        return redirect("/sittings");
      }

      // Verify sitting + exam belong to this tenant
      const sitting = await first(
        `SELECT id FROM exam_sittings WHERE id=? AND tenant_id=?`, [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      const paper = await first(
        `SELECT id FROM exam_sitting_papers WHERE sitting_id=? AND exam_id=?`, [sittingId, examId]
      );
      if (!paper) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=approvals`);

      const ts = nowISO();

      if (!enabled) {
        // Gate turned off — delete all gates and pending responses for this exam+gate_type
        await run(
          `DELETE FROM sitting_approval_gates WHERE exam_id=? AND gate_type=? AND tenant_id=?`,
          [examId, gateType, active.tenant_id]
        );
        await run(
          `DELETE FROM sitting_approval_responses WHERE exam_id=? AND gate_type=? AND status='PENDING' AND tenant_id=?`,
          [examId, gateType, active.tenant_id]
        );
      } else if (userId) {
        // Add approver — validate they are an active member of this tenant
        const member = await first(
          `SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND status='ACTIVE'`,
          [userId, active.tenant_id]
        );
        if (member) {
          // Only insert if not already assigned
          const already = await first(
            `SELECT id FROM sitting_approval_gates WHERE exam_id=? AND gate_type=? AND user_id=? AND tenant_id=?`,
            [examId, gateType, userId, active.tenant_id]
          );
          if (!already) {
            await run(
              `INSERT INTO sitting_approval_gates (id, sitting_id, exam_id, gate_type, user_id, tenant_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
              [uuid(), sittingId, examId, gateType, userId, active.tenant_id, ts]
            );
          }
        }
      }

      return redirect(`/sitting-gate-settings?sitting_id=${sittingId}&exam_id=${examId}`);
    }

    // ----------------------------------------------------------------
    // POST /sitting-gate-remove-approver — remove one approver from a gate
    // ----------------------------------------------------------------
    if (path === "/sitting-gate-remove-approver" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const f = await form();
      const sittingId = (f.sitting_id || "").trim();
      const examId    = (f.exam_id    || "").trim();
      const gateType  = (f.gate_type  || "").trim();
      const userId    = (f.user_id    || "").trim();

      if (!sittingId || !examId || !gateType || !userId) {
        return redirect("/sittings");
      }

      const sitting = await first(
        `SELECT id FROM exam_sittings WHERE id=? AND tenant_id=?`, [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      // Remove from gates
      await run(
        `DELETE FROM sitting_approval_gates WHERE exam_id=? AND gate_type=? AND user_id=? AND tenant_id=?`,
        [examId, gateType, userId, active.tenant_id]
      );
      // Delete their pending response if one exists
      await run(
        `DELETE FROM sitting_approval_responses WHERE exam_id=? AND gate_type=? AND approver_id=? AND status='PENDING' AND tenant_id=?`,
        [examId, gateType, userId, active.tenant_id]
      );

      return redirect(`/sitting-gate-settings?sitting_id=${sittingId}&exam_id=${examId}`);
    }

    // ----------------------------------------------------------------
    // POST /sitting-remove-paper
    // ----------------------------------------------------------------
    if (path === "/sitting-remove-paper" && request.method === "POST") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const f = await form();
      const sittingId = (f.sitting_id || "").trim();
      const paperId   = (f.paper_id   || "").trim();
      if (!sittingId || !paperId) return redirect("/sittings");

      const sitting = await first(
        `SELECT id FROM exam_sittings WHERE id=? AND tenant_id=?`, [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      await run(`DELETE FROM exam_sitting_papers WHERE id=? AND sitting_id=?`, [paperId, sittingId]);
      return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=papers`);
    }

    // ----------------------------------------------------------------
    // GET /sitting-builder — 3-tab pane (Settings / Papers / Results)
    // ----------------------------------------------------------------
    if (path === "/sitting-builder" && request.method === "GET") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const sittingId = url.searchParams.get("sitting_id") || "";
      if (!sittingId) return redirect("/sittings");

      const sitting = await first(
        `SELECT * FROM exam_sittings WHERE id=? AND tenant_id=?`, [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      const activeTab = url.searchParams.get("tab") || "settings";

      // ===== SETTINGS PANE =====
      const settingsPane = `
        <div id="pane-settings" class="pane ${activeTab === "settings" ? "active" : ""}">
          <div class="card">
            <h2 style="margin:0 0 16px">Settings</h2>
            <form method="post" action="/sitting-save-settings">
              <input type="hidden" name="sitting_id" value="${escapeAttr(sitting.id)}" />
              <label>Title <span class="muted">*</span></label>
              <input name="title" value="${escapeAttr(sitting.title)}" required />
              <label>Description <span class="muted">(optional)</span></label>
              <textarea name="description" rows="3">${escapeHtml(sitting.description || "")}</textarea>
              <label>Academic year <span class="muted">(optional, e.g. 2025/26)</span></label>
              <input name="academic_year" value="${escapeAttr(sitting.academic_year || "")}" placeholder="e.g. 2025/26" />
              <label>Status</label>
              <select name="status">
                <option value="DRAFT"  ${sitting.status === "DRAFT"  ? "selected" : ""}>Draft</option>
                <option value="ACTIVE" ${sitting.status === "ACTIVE" ? "selected" : ""}>Active</option>
                <option value="CLOSED" ${sitting.status === "CLOSED" ? "selected" : ""}>Closed</option>
              </select>
              <button type="submit" class="btn2" style="margin-top:14px">Save Settings</button>
            </form>
          </div>
        </div>`;

      // ===== PAPERS PANE DATA =====
      const papers = await all(
        `SELECT esp.id AS paper_id, esp.exam_id, esp.sort_order,
                e.title AS exam_title, e.status AS exam_status,
                c.title AS course_title,
                u.name AS teacher_name
         FROM exam_sitting_papers esp
         JOIN exams e ON e.id = esp.exam_id
         JOIN courses c ON c.id = e.course_id
         LEFT JOIN users u ON u.id = e.created_by
         WHERE esp.sitting_id=?
         ORDER BY esp.sort_order ASC`,
        [sittingId]
      );
      const existingPaperIds = papers.map(p => p.exam_id);

      // Exams in school NOT already in this sitting
      let availableExams = [];
      if (existingPaperIds.length > 0) {
        const notIn = existingPaperIds.map(() => "?").join(",");
        availableExams = await all(
          `SELECT e.id, e.title, e.status, c.title AS course_title
           FROM exams e JOIN courses c ON c.id = e.course_id
           WHERE e.tenant_id=? AND e.id NOT IN (${notIn})
           ORDER BY c.title ASC, e.title ASC`,
          [active.tenant_id, ...existingPaperIds]
        );
      } else {
        availableExams = await all(
          `SELECT e.id, e.title, e.status, c.title AS course_title
           FROM exams e JOIN courses c ON c.id = e.course_id
           WHERE e.tenant_id=? ORDER BY c.title ASC, e.title ASC`,
          [active.tenant_id]
        );
      }

      // Active courses + teachers for Mode 2
      const courses = await all(
        `SELECT id, title FROM courses WHERE tenant_id=? AND status='ACTIVE' ORDER BY title ASC`,
        [active.tenant_id]
      );
      const teacherRows = await all(
        `SELECT DISTINCT u.id, u.name, ct.course_id
         FROM course_teachers ct
         JOIN users u ON u.id = ct.user_id
         JOIN memberships m ON m.user_id = u.id AND m.tenant_id=? AND m.role='TEACHER' AND m.status='ACTIVE'
         JOIN courses c ON c.id = ct.course_id AND c.tenant_id=? AND c.status='ACTIVE'
         ORDER BY u.name ASC`,
        [active.tenant_id, active.tenant_id]
      );

      const paperRows = papers.map((p, i) => `
        <tr>
          <td style="font-weight:700;color:rgba(0,0,0,.35);font-size:13px;width:28px">${i + 1}</td>
          <td>
            <b>${escapeHtml(p.exam_title)}</b><br/>
            <span class="muted small">${escapeHtml(p.course_title)}${p.teacher_name ? ` &middot; ${escapeHtml(p.teacher_name)}` : ""}</span>
          </td>
          <td>${examBadge(p.exam_status)}</td>
          <td>
            <a href="/exam-builder?exam_id=${escapeAttr(p.exam_id)}" class="btn3"
               style="display:inline-block;padding:4px 10px;font-size:12px;text-decoration:none;margin-right:4px">Edit</a>
            <form method="post" action="/sitting-remove-paper" style="display:inline"
                  onsubmit="return confirm('Remove this paper from the sitting?')">
              <input type="hidden" name="sitting_id" value="${escapeAttr(sittingId)}" />
              <input type="hidden" name="paper_id" value="${escapeAttr(p.paper_id)}" />
              <button type="submit" class="btn3" style="padding:4px 10px;font-size:12px">Remove</button>
            </form>
          </td>
        </tr>`).join("");

      const examOptions = availableExams.map(e =>
        `<option value="${escapeAttr(e.id)}">${escapeHtml(e.title)} &mdash; ${escapeHtml(e.course_title)} [${escapeHtml(e.status)}]</option>`
      ).join("");

      const courseOptions = courses.map(c =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const teacherDataJson = JSON.stringify(
        teacherRows.map(t => ({ id: t.id, name: t.name, course_id: t.course_id }))
      );

      const papersPane = `
        <div id="pane-papers" class="pane ${activeTab === "papers" ? "active" : ""}">
          <div class="card">
            <h2 style="margin:0 0 14px">Papers in this Sitting</h2>
            ${papers.length > 0 ? `
              <table class="table">
                <thead><tr><th>#</th><th>Paper</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>${paperRows}</tbody>
              </table>
            ` : `<p class="muted">No papers added yet. Add a paper below.</p>`}
          </div>
          <div class="row" style="align-items:start">
            <div class="card">
              <h2 style="margin:0 0 12px;font-size:15px">&#128279; Link Existing Exam</h2>
              ${availableExams.length > 0 ? `
                <form method="post" action="/sitting-add-paper">
                  <input type="hidden" name="sitting_id" value="${escapeAttr(sittingId)}" />
                  <input type="hidden" name="mode" value="existing" />
                  <label>Exam</label>
                  <select name="exam_id" required>
                    <option value="">— select exam —</option>
                    ${examOptions}
                  </select>
                  <button type="submit" class="btn2" style="margin-top:10px">Add Paper</button>
                </form>
              ` : `<p class="muted small">All school exams are already in this sitting, or no exams exist yet.</p>`}
            </div>
            <div class="card">
              <h2 style="margin:0 0 12px;font-size:15px">&#10010; Create New Paper</h2>
              ${courses.length > 0 ? `
                <form method="post" action="/sitting-add-paper">
                  <input type="hidden" name="sitting_id" value="${escapeAttr(sittingId)}" />
                  <input type="hidden" name="mode" value="create" />
                  <label>Paper title <span class="muted">*</span></label>
                  <input name="title" placeholder="e.g. Mathematics Paper 1" required />
                  <label>Course <span class="muted">*</span></label>
                  <select name="course_id" id="new-paper-course" required>
                    <option value="">— select course —</option>
                    ${courseOptions}
                  </select>
                  <label>Assigned teacher <span class="muted">*</span></label>
                  <select name="teacher_id" id="new-paper-teacher" required>
                    <option value="">— select course first —</option>
                  </select>
                  <button type="submit" class="btn2" style="margin-top:10px">Create &amp; Add Paper</button>
                </form>
                <script>
                  (function(){
                    const TD = ${teacherDataJson};
                    function filterT(cid) {
                      const sel = document.getElementById('new-paper-teacher');
                      const fl  = TD.filter(t => t.course_id === cid);
                      sel.innerHTML = fl.length
                        ? '<option value="">— select teacher —</option>' +
                          fl.map(t => '<option value="' + t.id + '">' + t.name + '</option>').join('')
                        : '<option value="">No teachers assigned to this course</option>';
                    }
                    const cs = document.getElementById('new-paper-course');
                    cs.addEventListener('change', () => filterT(cs.value));
                    if (cs.value) filterT(cs.value);
                  })();
                </script>
              ` : `<p class="muted small">Create at least one active course before adding a new paper here.</p>`}
            </div>
          </div>
        </div>`;

      // ===== RESULTS PANE DATA =====
      const paperList = await all(
        `SELECT esp.exam_id, esp.sort_order, e.title AS exam_title, e.score_display, e.results_published_at
         FROM exam_sitting_papers esp
         JOIN exams e ON e.id = esp.exam_id
         WHERE esp.sitting_id=?
         ORDER BY esp.sort_order ASC`,
        [sittingId]
      );

      let studentList = [];
      let attemptGrid = {};
      if (paperList.length > 0) {
        const pIds = paperList.map(p => p.exam_id);
        const phQ  = pIds.map(() => "?").join(",");
        studentList = await all(
          `SELECT DISTINCT u.id, u.name
           FROM exam_attempts ea
           JOIN users u ON u.id = ea.user_id
           WHERE ea.exam_id IN (${phQ}) AND ea.tenant_id=? AND ea.status='SUBMITTED'
           ORDER BY u.name ASC`,
          [...pIds, active.tenant_id]
        );
        const attempts = await all(
          `SELECT ea.id, ea.exam_id, ea.user_id, ea.score_display,
                  ea.score_pct, ea.score_raw, ea.score_total,
                  ea.grade, ea.pass_mark_percent
           FROM exam_attempts ea
           WHERE ea.exam_id IN (${phQ}) AND ea.tenant_id=? AND ea.status='SUBMITTED'
           ORDER BY ea.attempt_no DESC`,
          [...pIds, active.tenant_id]
        );
        for (const a of attempts) {
          if (!attemptGrid[a.user_id]) attemptGrid[a.user_id] = {};
          // Keep most recent attempt per exam per student (already ordered DESC)
          if (!attemptGrid[a.user_id][a.exam_id]) attemptGrid[a.user_id][a.exam_id] = a;
        }
      }

      function cellHtml(att, paper) {
        if (!att) return `<span class="muted">&#8212;</span>`;
        const released = paper.results_published_at &&
          Date.parse(paper.results_published_at) <= Date.now();
        if (!released) return `<span class="muted small">Pending</span>`;
        const sd  = att.score_display || paper.score_display || "BOTH";
        const pct = att.score_pct  != null ? Number(att.score_pct)  : null;
        const raw = att.score_raw  != null ? Number(att.score_raw)  : null;
        const tot = att.score_total != null ? Number(att.score_total) : null;
        const parts = [];
        if (sd === "BOTH" && pct !== null && raw !== null)  parts.push(`${Math.round(pct)}% (${raw}/${tot})`);
        else if (sd === "PERCENT" && pct !== null)          parts.push(`${Math.round(pct)}%`);
        else if (sd === "MARKS"   && raw !== null)          parts.push(`${raw}/${tot}`);
        if (att.grade) parts.push(escapeHtml(String(att.grade)));
        if (att.pass_mark_percent != null && pct !== null) {
          const passed = pct >= Number(att.pass_mark_percent);
          parts.push(passed
            ? `<span style="color:#0b5e4e;font-weight:700">&#10003; PASS</span>`
            : `<span style="color:#c00;font-weight:700">&#10007; FAIL</span>`
          );
        }
        const score = parts.length > 0 ? parts.join(" &middot; ") : `<span class="muted small">Recorded</span>`;
        const link  = `<br/><a href="/attempt-results?attempt_id=${escapeAttr(att.id)}" style="font-size:11px;color:#0b7a75">View</a>`;
        return score + link;
      }

      const paperHeaders = paperList.map(p =>
        `<th style="font-size:12px;max-width:150px;white-space:normal;text-align:center">${escapeHtml(p.exam_title)}</th>`
      ).join("");

      const resultRows = studentList.map(s => {
        const cells = paperList.map(p => {
          const att = (attemptGrid[s.id] || {})[p.exam_id];
          return `<td style="font-size:13px;text-align:center;vertical-align:middle">${cellHtml(att, p)}</td>`;
        }).join("");
        return `<tr><td><b>${escapeHtml(s.name)}</b></td>${cells}</tr>`;
      }).join("");

      const resultsPane = `
        <div id="pane-results" class="pane ${activeTab === "results" ? "active" : ""}">
          <div class="card">
            <h2 style="margin:0 0 14px">Results Overview</h2>
            ${paperList.length === 0 ? `
              <p class="muted">No papers in this sitting yet. Add papers in the Papers tab.</p>
            ` : studentList.length === 0 ? `
              <p class="muted">No submitted attempts found for any paper in this sitting.</p>
            ` : `
              <div style="overflow-x:auto">
                <table class="table">
                  <thead><tr><th>Student</th>${paperHeaders}</tr></thead>
                  <tbody>${resultRows}</tbody>
                </table>
              </div>
            `}
          </div>
        </div>`;

      // ===== APPROVALS PANE DATA =====
      // Load gate counts per paper (one query across all papers)
      let gateCountMap = {};
      if (papers.length > 0) {
        const examIds = papers.map(p => p.exam_id);
        const ph = examIds.map(() => "?").join(",");
        const gateCounts = await all(
          `SELECT exam_id, gate_type, COUNT(*) AS cnt
           FROM sitting_approval_gates
           WHERE tenant_id=? AND exam_id IN (${ph})
           GROUP BY exam_id, gate_type`,
          [active.tenant_id, ...examIds]
        );
        for (const row of gateCounts) {
          if (!gateCountMap[row.exam_id]) gateCountMap[row.exam_id] = {};
          gateCountMap[row.exam_id][row.gate_type] = Number(row.cnt);
        }
      }

      const gateBadge = (letter, count) => count > 0
        ? `<span style="display:inline-block;background:#d4f5e9;color:#0b5e4e;padding:2px 7px;border-radius:999px;font-size:11px;font-weight:700">${letter}:${count}</span>`
        : `<span style="font-size:12px;color:rgba(0,0,0,.35)">${letter}:0</span>`;

      const approvalRows = papers.map((p, i) => {
        const cnts = gateCountMap[p.exam_id] || {};
        const qCnt = cnts["QUESTIONS"] || 0;
        const gCnt = cnts["GRADING"]   || 0;
        const rCnt = cnts["RESULTS"]   || 0;
        return `
          <tr>
            <td style="font-weight:700;color:rgba(0,0,0,.35);font-size:13px;width:28px">${i + 1}</td>
            <td>
              <b>${escapeHtml(p.exam_title)}</b>
            </td>
            <td class="small">${escapeHtml(p.course_title)}</td>
            <td class="small">${p.teacher_name ? escapeHtml(p.teacher_name) : '<span class="muted">—</span>'}</td>
            <td style="white-space:nowrap">
              <span style="display:inline-flex;gap:4px;align-items:center">
                ${gateBadge("Q", qCnt)}
                ${gateBadge("G", gCnt)}
                ${gateBadge("R", rCnt)}
              </span>
            </td>
            <td>
              <a href="/sitting-gate-settings?sitting_id=${escapeAttr(sittingId)}&exam_id=${escapeAttr(p.exam_id)}"
                 class="btn3" style="display:inline-block;padding:4px 10px;font-size:12px;text-decoration:none">Set Approvals</a>
            </td>
          </tr>`;
      }).join("");

      const approvalsPane = `
        <div id="pane-approvals" class="pane ${activeTab === "approvals" ? "active" : ""}">
          <div class="card">
            <h2 style="margin:0 0 14px">Approval Gates</h2>
            ${papers.length === 0 ? `
              <p class="muted">No papers in this sitting yet. Add papers in the Papers tab first.</p>
            ` : `
              <table class="table">
                <thead><tr><th>#</th><th>Paper</th><th>Course</th><th>Teacher</th><th>Gates</th><th></th></tr></thead>
                <tbody>${approvalRows}</tbody>
              </table>
            `}
          </div>
        </div>`;

      return page(`
        <style>
          .pane{display:none}.pane.active{display:block}
          .sit-tabs{display:flex;gap:0;border-bottom:2px solid rgba(0,0,0,.1);margin-bottom:0}
          .sit-tab{padding:10px 22px;border:none;border-bottom:3px solid transparent;background:none;
            color:rgba(0,0,0,.5);font-size:14px;font-weight:600;cursor:pointer;margin-bottom:-2px;
            border-radius:6px 6px 0 0;transition:color .15s}
          .sit-tab:hover{color:#0b7a75;background:rgba(11,122,117,.05)}
          .sit-tab.active{color:#0b7a75;border-bottom-color:#0b7a75}
          .sit-tab-body{background:#fff;border:1px solid rgba(0,0,0,.08);border-top:none;border-radius:0 0 14px 14px;padding:4px 0}
        </style>
        <div class="card">
          <div class="topbar">
            <div>
              <a href="/sittings" style="font-size:13px;color:rgba(0,0,0,.45)">&#8592; Sittings</a>
              <h1 style="margin:4px 0 0">${escapeHtml(sitting.title)}</h1>
              <div style="margin-top:4px">
                ${sittingBadge(sitting.status)}
                ${sitting.academic_year ? `<span class="muted small" style="margin-left:6px">${escapeHtml(sitting.academic_year)}</span>` : ""}
              </div>
            </div>
            <div class="actions">
              <a href="/sittings">All Sittings</a>
              <a href="/school">School Admin</a>
            </div>
          </div>
        </div>
        <div class="sit-tabs">
          <button class="sit-tab ${activeTab === "settings"  ? "active" : ""}" onclick="showTab('settings',this)">&#9881;&#65039; Settings</button>
          <button class="sit-tab ${activeTab === "papers"    ? "active" : ""}" onclick="showTab('papers',this)">&#128196; Papers (${papers.length})</button>
          <button class="sit-tab ${activeTab === "approvals" ? "active" : ""}" onclick="showTab('approvals',this)">&#10004; Approvals</button>
          <button class="sit-tab ${activeTab === "results"   ? "active" : ""}" onclick="showTab('results',this)">&#128202; Results</button>
        </div>
        <div class="sit-tab-body">
          ${settingsPane}
          ${papersPane}
          ${approvalsPane}
          ${resultsPane}
        </div>
        <script>
          function showTab(name, btn) {
            document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.sit-tab').forEach(b => b.classList.remove('active'));
            document.getElementById('pane-' + name).classList.add('active');
            btn.classList.add('active');
            const u = new URL(location.href);
            u.searchParams.set('tab', name);
            history.replaceState(null, '', u);
          }
        </script>
      `);
    }

    // ----------------------------------------------------------------
    // GET /sitting-gate-settings — per-paper gate configuration page
    // ----------------------------------------------------------------
    if (path === "/sitting-gate-settings" && request.method === "GET") {
      const { ok, res, r, active } = await requireAdmin();
      if (!ok) return res;

      const sittingId = url.searchParams.get("sitting_id") || "";
      const examId    = url.searchParams.get("exam_id")    || "";
      if (!sittingId || !examId) return redirect("/sittings");

      const sitting = await first(
        `SELECT id, title FROM exam_sittings WHERE id=? AND tenant_id=?`,
        [sittingId, active.tenant_id]
      );
      if (!sitting) return redirect("/sittings");

      // Verify exam is in this sitting + load paper info
      const paper = await first(
        `SELECT e.id AS exam_id, e.title AS exam_title,
                c.title AS course_title, u.name AS teacher_name
         FROM exam_sitting_papers esp
         JOIN exams e ON e.id = esp.exam_id
         JOIN courses c ON c.id = e.course_id
         LEFT JOIN users u ON u.id = e.created_by
         WHERE esp.sitting_id=? AND esp.exam_id=?`,
        [sittingId, examId]
      );
      if (!paper) return redirect(`/sitting-builder?sitting_id=${sittingId}&tab=approvals`);

      // All gates assigned for this exam
      const assignedGates = await all(
        `SELECT sag.gate_type, sag.user_id, u.name AS approver_name
         FROM sitting_approval_gates sag
         JOIN users u ON u.id = sag.user_id
         WHERE sag.exam_id=? AND sag.tenant_id=?
         ORDER BY sag.gate_type, u.name ASC`,
        [examId, active.tenant_id]
      );
      // Group by gate_type
      const assignedByGate = { QUESTIONS: [], GRADING: [], RESULTS: [] };
      for (const g of assignedGates) {
        if (assignedByGate[g.gate_type]) assignedByGate[g.gate_type].push(g);
      }

      // All active school members with roles
      const allMembers = await all(
        `SELECT u.id, u.name, m.role
         FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'
         ORDER BY u.name ASC`,
        [active.tenant_id]
      );
      const memberRoleMap = {};
      for (const m of allMembers) memberRoleMap[m.id] = m.role;

      // Active courses for the filter dropdown
      const gsPageCourses = await all(
        `SELECT id, title FROM courses WHERE tenant_id=? AND status='ACTIVE' ORDER BY title ASC`,
        [active.tenant_id]
      );

      // Distinct roles for the role filter dropdown (dynamic — no hardcoding)
      const distinctRoles = await all(
        `SELECT DISTINCT role FROM memberships WHERE tenant_id=? AND status='ACTIVE' ORDER BY role ASC`,
        [active.tenant_id]
      );

      // Course → teacher links (for JS filtering)
      const ctLinks = await all(
        `SELECT ct.course_id, ct.user_id
         FROM course_teachers ct
         JOIN courses c ON c.id = ct.course_id AND c.tenant_id=? AND c.status='ACTIVE'`,
        [active.tenant_id]
      );
      const courseTeacherMap = {};
      for (const ct of ctLinks) {
        if (!courseTeacherMap[ct.course_id]) courseTeacherMap[ct.course_id] = [];
        courseTeacherMap[ct.course_id].push(ct.user_id);
      }

      // JSON payloads for client-side JS
      const memberDataJson       = JSON.stringify(allMembers.map(m => ({ id: m.id, name: m.name, role: m.role })));
      const courseTeacherDataJson = JSON.stringify(courseTeacherMap);
      const assignedJson = JSON.stringify({
        QUESTIONS: assignedByGate.QUESTIONS.map(a => a.user_id),
        GRADING:   assignedByGate.GRADING.map(a => a.user_id),
        RESULTS:   assignedByGate.RESULTS.map(a => a.user_id),
      });

      const courseFilterOptions = gsPageCourses.map(c =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`
      ).join("");

      const roleFilterOptions = distinctRoles.map(r =>
        `<option value="${escapeAttr(r.role)}">${escapeHtml(roleLabel(r.role))}</option>`
      ).join("");

      const GATE_DEFS = [
        { type: "QUESTIONS", label: "📝 Questions Gate", desc: "Must be approved before the exam can be published" },
        { type: "GRADING",   label: "✏️ Grading Gate",   desc: "Must be approved before results can be released" },
        { type: "RESULTS",   label: "📊 Results Gate",   desc: "Final sign-off before results go live to students" },
      ];

      const gateCards = GATE_DEFS.map(def => {
        const assignees = assignedByGate[def.type] || [];
        const isActive  = assignees.length > 0;

        const approverRows = assignees.map(a => {
          const role = memberRoleMap[a.user_id] || "";
          return `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid rgba(0,0,0,.06)">
              <div>
                <span style="font-size:13px;font-weight:600">${escapeHtml(a.approver_name)}</span>
                ${role ? `<span class="muted small" style="margin-left:6px">${escapeHtml(roleLabel(role))}</span>` : ""}
              </div>
              <form method="post" action="/sitting-gate-remove-approver" style="margin:0">
                <input type="hidden" name="sitting_id" value="${escapeAttr(sittingId)}" />
                <input type="hidden" name="exam_id"    value="${escapeAttr(examId)}" />
                <input type="hidden" name="gate_type"  value="${escapeAttr(def.type)}" />
                <input type="hidden" name="user_id"    value="${escapeAttr(a.user_id)}" />
                <button type="submit" class="btn3" style="padding:2px 8px;font-size:11px">Remove</button>
              </form>
            </div>`;
        }).join("");

        return `
          <div class="card">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:4px">
              <span style="font-weight:700;font-size:15px">${def.label}</span>
              ${isActive
                ? `<span style="background:#d4f5e9;color:#0b5e4e;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">Active</span>`
                : `<span style="background:rgba(0,0,0,.06);color:rgba(0,0,0,.4);padding:3px 10px;border-radius:999px;font-size:12px">Inactive</span>`
              }
            </div>
            <p class="muted small" style="margin:0 0 12px">${def.desc}</p>

            ${isActive ? `
              <div style="margin-bottom:12px">
                ${approverRows}
              </div>
            ` : `
              <p class="muted" style="font-style:italic;margin:0 0 12px">No approvers assigned — gate inactive</p>
            `}

            <div style="border-top:1px solid rgba(0,0,0,.07);padding-top:12px">
              <div class="section-title" style="font-size:11px;font-weight:700;color:rgba(0,0,0,.45);text-transform:uppercase;letter-spacing:.05em;margin:0 0 8px">Add approver</div>
              <form method="post" action="/sitting-gate-save">
                <input type="hidden" name="sitting_id" value="${escapeAttr(sittingId)}" />
                <input type="hidden" name="exam_id"    value="${escapeAttr(examId)}" />
                <input type="hidden" name="gate_type"  value="${escapeAttr(def.type)}" />
                <input type="hidden" name="enabled"    value="1" />
                <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
                  <div style="flex:1;min-width:140px">
                    <label style="font-size:12px;color:rgba(0,0,0,.5);display:block;margin-bottom:4px">Course filter</label>
                    <select id="course-filter-${def.type}" style="width:100%;font-size:13px"
                            onchange="filterApprovers('${def.type}')">
                      <option value="">All courses</option>
                      ${courseFilterOptions}
                    </select>
                  </div>
                  <div style="flex:1;min-width:130px">
                    <label style="font-size:12px;color:rgba(0,0,0,.5);display:block;margin-bottom:4px">Role filter</label>
                    <select id="role-filter-${def.type}" style="width:100%;font-size:13px"
                            onchange="filterApprovers('${def.type}')">
                      <option value="">All roles</option>
                      ${roleFilterOptions}
                    </select>
                  </div>
                  <div style="flex:2;min-width:180px">
                    <label style="font-size:12px;color:rgba(0,0,0,.5);display:block;margin-bottom:4px">Approver</label>
                    <select id="user-sel-${def.type}" name="user_id" required style="width:100%;font-size:13px">
                      <option value="">— loading… —</option>
                    </select>
                  </div>
                  <button type="submit" class="btn2" style="font-size:13px;padding:8px 14px">+ Add</button>
                </div>
              </form>
            </div>
          </div>`;
      }).join("");

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:13px;color:rgba(0,0,0,.45);margin-bottom:4px">
                <a href="/sitting-builder?sitting_id=${escapeAttr(sittingId)}&tab=approvals">&#8592; ${escapeHtml(sitting.title)}</a>
              </div>
              <h1 style="margin:0">${escapeHtml(paper.exam_title)}</h1>
              <div class="muted" style="margin-top:4px;font-size:13px">
                ${escapeHtml(paper.course_title)}${paper.teacher_name ? ` &middot; ${escapeHtml(paper.teacher_name)}` : ""}
              </div>
            </div>
            <div class="actions">
              <a href="/sitting-builder?sitting_id=${escapeAttr(sittingId)}&tab=approvals">&#8592; Approvals</a>
              <a href="/school">School Admin</a>
            </div>
          </div>
        </div>
        ${gateCards}
        <script>
          (function() {
            const MEMBERS = ${memberDataJson};
            const COURSE_TEACHERS = ${courseTeacherDataJson};
            const ASSIGNED = ${assignedJson};

            function roleLabel(r) {
              if (r === 'SCHOOL_ADMIN') return 'School Admin';
              if (r === 'TEACHER')      return 'Teacher';
              if (r === 'STUDENT')      return 'Student';
              return r || '';
            }

            function escOpt(s) {
              return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            }

            window.filterApprovers = function(gateType) {
              const courseId  = (document.getElementById('course-filter-' + gateType) || {}).value || '';
              const roleVal   = (document.getElementById('role-filter-'   + gateType) || {}).value || '';
              const sel       = document.getElementById('user-sel-' + gateType);
              if (!sel) return;
              const assigned  = new Set(ASSIGNED[gateType] || []);
              let members = MEMBERS.filter(m => !assigned.has(m.id));
              if (courseId) {
                const teacherIds = new Set(COURSE_TEACHERS[courseId] || []);
                members = members.filter(m => teacherIds.has(m.id));
              }
              if (roleVal) {
                members = members.filter(m => m.role === roleVal);
              }
              if (members.length === 0) {
                sel.innerHTML = '<option value="">No eligible approvers available</option>';
              } else {
                sel.innerHTML = '<option value="">&#8212; select approver &#8212;</option>' +
                  members.map(m =>
                    '<option value="' + escOpt(m.id) + '">' +
                    escOpt(m.name) + ' \u2014 ' + escOpt(roleLabel(m.role)) +
                    '</option>'
                  ).join('');
              }
            };

            // Initialise all three dropdowns on page load
            ['QUESTIONS', 'GRADING', 'RESULTS'].forEach(function(g) { filterApprovers(g); });
          })();
        </script>
      `);
    }

    // ----------------------------------------------------------------
    // GET /approvals — Approval Inbox (any logged-in school user)
    // ----------------------------------------------------------------
    if (path === "/approvals" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");

      const userId   = r.user.id;
      const tenantId = active.tenant_id;

      const gateLabel = (t) => {
        if (t === "QUESTIONS") return "Questions Gate";
        if (t === "GRADING")   return "Grading Gate";
        if (t === "RESULTS")   return "Results Gate";
        return t;
      };
      const gateIcon = (t) => {
        if (t === "QUESTIONS") return "&#128221;";
        if (t === "GRADING")   return "&#9999;&#65039;";
        return "&#128202;";
      };

      // Gates where this user has a PENDING response
      const pendingItems = await all(
        `SELECT sag.exam_id, sag.gate_type, sag.sitting_id,
                e.title AS exam_title,
                es.title AS sitting_title,
                u.name AS submitter_name
         FROM sitting_approval_gates sag
         JOIN sitting_approval_responses sar
           ON sar.exam_id=sag.exam_id AND sar.gate_type=sag.gate_type
          AND sar.approver_id=sag.user_id AND sar.tenant_id=sag.tenant_id
         JOIN exams e ON e.id=sag.exam_id
         LEFT JOIN exam_sittings es ON es.id=sag.sitting_id
         LEFT JOIN users u ON u.id=e.created_by
         WHERE sag.user_id=? AND sag.tenant_id=? AND sar.status='PENDING'
         ORDER BY sar.created_at ASC`,
        [userId, tenantId]
      );

      // Gates where this user has already responded
      const recentItems = await all(
        `SELECT sag.exam_id, sag.gate_type, sag.sitting_id,
                e.title AS exam_title,
                es.title AS sitting_title,
                u.name AS submitter_name,
                sar.status AS my_status,
                sar.note AS my_note,
                sar.updated_at AS responded_at
         FROM sitting_approval_gates sag
         JOIN sitting_approval_responses sar
           ON sar.exam_id=sag.exam_id AND sar.gate_type=sag.gate_type
          AND sar.approver_id=sag.user_id AND sar.tenant_id=sag.tenant_id
         JOIN exams e ON e.id=sag.exam_id
         LEFT JOIN exam_sittings es ON es.id=sag.sitting_id
         LEFT JOIN users u ON u.id=e.created_by
         WHERE sag.user_id=? AND sag.tenant_id=? AND sar.status IN ('APPROVED','REJECTED')
         ORDER BY sar.updated_at DESC LIMIT 30`,
        [userId, tenantId]
      );

      const pendingHtml = pendingItems.length === 0
        ? `<p class="muted" style="text-align:center;padding:24px 0">&#10003; All clear — no pending approvals.</p>`
        : pendingItems.map(item => `
          <div class="card" style="margin-bottom:10px">
            <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-start">
              <div style="flex:1;min-width:200px">
                <div style="font-weight:700;font-size:16px;margin-bottom:3px">${escapeHtml(item.exam_title)}</div>
                ${item.sitting_title ? `<div class="muted small" style="margin-bottom:4px">&#128203; ${escapeHtml(item.sitting_title)}</div>` : ""}
                <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
                  <span class="pill" style="background:#fff3e0;color:#a05000;font-size:12px">${gateIcon(item.gate_type)} ${escapeHtml(gateLabel(item.gate_type))}</span>
                  ${item.submitter_name ? `<span class="muted small">by ${escapeHtml(item.submitter_name)}</span>` : ""}
                </div>
                <a href="/exam-builder?exam_id=${escapeAttr(item.exam_id)}&pane=approvals" style="font-size:13px">View exam &#8599;</a>
              </div>
              <div style="min-width:240px;flex-shrink:0">
                <form method="post" action="/approval-respond">
                  <input type="hidden" name="exam_id"   value="${escapeAttr(item.exam_id)}" />
                  <input type="hidden" name="gate_type" value="${escapeAttr(item.gate_type)}" />
                  <label style="font-size:12px;color:rgba(0,0,0,.5);margin-bottom:4px;display:block">Note <span class="muted">(optional)</span></label>
                  <textarea name="note" rows="2" style="width:100%;font-size:13px;box-sizing:border-box;margin-bottom:8px" placeholder="Add a note..."></textarea>
                  <div style="display:flex;gap:8px">
                    <button name="response" value="APPROVED" type="submit" class="btn2" style="flex:1">&#10003; Approve</button>
                    <button name="response" value="REJECTED" type="submit" style="flex:1;padding:10px 14px;border:0;border-radius:10px;background:#ffe8e8;color:#c00;font-weight:700;cursor:pointer">&#10007; Reject</button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        `).join("");

      const recentHtml = recentItems.length === 0 ? "" : `
        <div class="card">
          <h2 style="margin:0 0 14px">Recent</h2>
          <table class="table">
            <thead><tr><th>Exam</th><th>Gate</th><th>Response</th><th>Date</th><th>Note</th></tr></thead>
            <tbody>
              ${recentItems.map(item => `
                <tr>
                  <td>
                    <b>${escapeHtml(item.exam_title)}</b>
                    ${item.sitting_title ? `<br/><span class="muted small">&#128203; ${escapeHtml(item.sitting_title)}</span>` : ""}
                  </td>
                  <td class="small">${escapeHtml(gateLabel(item.gate_type))}</td>
                  <td>${item.my_status === "APPROVED"
                    ? `<span class="pill" style="background:#d4f5e9;color:#0b5e4e;font-size:11px">Approved</span>`
                    : `<span class="pill" style="background:#ffe8e8;color:#c00;font-size:11px">Rejected</span>`}
                  </td>
                  <td class="small muted">${escapeHtml(fmtISO(item.responded_at))}</td>
                  <td class="small muted">${escapeHtml(item.my_note || "—")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>&#128236; Approval Inbox</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/">Home</a>
              <a href="/profile">Profile</a>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 14px">Pending (${pendingItems.length})</h2>
          ${pendingHtml}
        </div>
        ${recentHtml}
      `);
    }

    // ----------------------------------------------------------------
    // POST /approval-respond — submit approve or reject for a gate
    // ----------------------------------------------------------------
    if (path === "/approval-respond" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");

      const f = await form();
      const examId   = (f.exam_id   || "").trim();
      const gateType = (f.gate_type || "").trim();
      const response = (f.response  || "").trim();
      const note     = (f.note      || "").trim() || null;

      if (!examId || !["QUESTIONS","GRADING","RESULTS"].includes(gateType)) {
        return redirect("/approvals");
      }
      if (!["APPROVED","REJECTED"].includes(response)) {
        return redirect("/approvals");
      }

      const userId   = r.user.id;
      const tenantId = active.tenant_id;

      // Validate this user is actually assigned as an approver for this gate
      const gate = await first(
        `SELECT id FROM sitting_approval_gates
         WHERE exam_id=? AND gate_type=? AND user_id=? AND tenant_id=?`,
        [examId, gateType, userId, tenantId]
      );
      if (!gate) return redirect("/approvals");

      const ts = nowISO();

      // Upsert: update existing row or insert a new one
      const existing = await first(
        `SELECT id FROM sitting_approval_responses
         WHERE exam_id=? AND gate_type=? AND approver_id=? AND tenant_id=?`,
        [examId, gateType, userId, tenantId]
      );
      if (existing) {
        await run(
          `UPDATE sitting_approval_responses SET status=?, note=?, updated_at=? WHERE id=?`,
          [response, note, ts, existing.id]
        );
      } else {
        await run(
          `INSERT INTO sitting_approval_responses (id, exam_id, gate_type, approver_id, status, note, tenant_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [uuid(), examId, gateType, userId, response, note, tenantId, ts, ts]
        );
      }

      return redirect("/approvals");
    }

    // Fallback
    return redirect("/sittings");

  } catch (err) {
    console.error("FATAL [sittings]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (sittings):\n\n" + msg, { status: 500 });
  }
}
