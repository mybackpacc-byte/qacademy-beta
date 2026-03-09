// functions/student.js
// Student dashboard route

import { createHelpers } from "./shared.js";

export async function handleStudentRequest(ctx) {
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
    // Student dashboard (shell)
    // =============================
    if (path === "/student") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "STUDENT") return redirect("/");

      const userId   = r.user.id;
      const tenantId = active.tenant_id;
      const now      = Date.now();

      // Load all exams this student has access to (includes results_published_at)
      const exams = await all(
        `SELECT e.id AS exam_id, e.title, e.status, e.duration_mins, e.max_attempts,
                e.starts_at, e.ends_at, e.exam_password, e.results_published_at,
                c.title AS course_title,
                (SELECT COUNT(*) FROM exam_custom_fields cf WHERE cf.exam_id = e.id) AS cf_count
         FROM exam_access ea
         JOIN exams e ON e.id = ea.exam_id
         JOIN courses c ON c.id = e.course_id
         WHERE ea.user_id = ? AND e.tenant_id = ?
         ORDER BY e.title ASC`,
        [userId, tenantId]
      );

      // Load all non-abandoned attempts (full rows, not just counts)
      const allAttempts = await all(
        `SELECT id, exam_id, status, attempt_no, submitted_at
         FROM exam_attempts
         WHERE user_id = ? AND tenant_id = ? AND status != 'ABANDONED'
         ORDER BY attempt_no ASC`,
        [userId, tenantId]
      );
      const attemptsByExam = {};
      for (const a of allAttempts) {
        if (!attemptsByExam[a.exam_id]) attemptsByExam[a.exam_id] = { all: [], submitted: [], inProgress: null };
        attemptsByExam[a.exam_id].all.push(a);
        if (a.status === "SUBMITTED")   attemptsByExam[a.exam_id].submitted.push(a);
        if (a.status === "IN_PROGRESS") attemptsByExam[a.exam_id].inProgress = a;
      }

      // ---- My Sittings: sittings where student has at least one submitted attempt ----
      const mySittings = await all(
        `SELECT DISTINCT es.id, es.title, es.academic_year
         FROM exam_sittings es
         JOIN exam_sitting_papers esp ON esp.sitting_id = es.id
         JOIN exam_attempts ea ON ea.exam_id = esp.exam_id
                               AND ea.user_id = ? AND ea.status = 'SUBMITTED'
         WHERE es.tenant_id = ?
         ORDER BY es.created_at DESC`,
        [userId, tenantId]
      );

      const sittingCards = [];
      for (const s of mySittings) {
        const totalRow = await first(
          `SELECT COUNT(*) AS c FROM exam_sitting_papers WHERE sitting_id=?`, [s.id]
        );
        const releasedRow = await first(
          `SELECT COUNT(*) AS c FROM exam_sitting_papers esp
           JOIN exams e ON e.id = esp.exam_id
           WHERE esp.sitting_id=? AND e.results_published_at IS NOT NULL
             AND e.results_published_at <= ?`,
          [s.id, new Date().toISOString()]
        );
        const total    = totalRow    ? Number(totalRow.c)    : 0;
        const released = releasedRow ? Number(releasedRow.c) : 0;
        sittingCards.push(`
          <div class="card" style="margin-bottom:10px">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
              <div>
                <div style="font-size:17px;font-weight:700;margin-bottom:2px">${escapeHtml(s.title)}</div>
                ${s.academic_year ? `<div class="muted small" style="margin-bottom:4px">${escapeHtml(s.academic_year)}</div>` : ""}
                <div style="font-size:13px;color:rgba(0,0,0,.55)">${released} of ${total} result${total !== 1 ? "s" : ""} available</div>
              </div>
              <a href="/sitting-results?sitting_id=${escapeAttr(s.id)}"
                 class="btn2" style="display:inline-block;text-decoration:none;padding:8px 16px">View Sitting Results</a>
            </div>
          </div>
        `);
      }

      const mySittingsHtml = sittingCards.length > 0
        ? `<h2 style="margin:24px 0 12px">&#128203; My Sittings</h2>${sittingCards.join("")}`
        : "";

      // isIsoInPast helper (local)
      function isIsoInPast(iso) {
        if (!iso) return false;
        const t = Date.parse(iso);
        if (Number.isNaN(t)) return false;
        return t < Date.now();
      }

      // Build exam cards
      const cards = [];
      for (const exam of exams) {
        if (exam.status === "DRAFT") continue;

        const examAtts          = attemptsByExam[exam.exam_id] || { all: [], submitted: [], inProgress: null };
        const attemptsUsed      = examAtts.all.length;
        const attemptsRemaining = Math.max(0, exam.max_attempts - attemptsUsed);
        const inProgress        = examAtts.inProgress;
        const submitted         = examAtts.submitted;
        const startsInFuture    = exam.starts_at && Date.parse(exam.starts_at) > now;
        const endsInPast        = exam.ends_at   && Date.parse(exam.ends_at)   < now;
        const resultsReleased   = isIsoInPast(exam.results_published_at);

        // Badge
        let badgeClass = "", badgeLabel = "";
        if (exam.status === "PUBLISHED") {
          if (startsInFuture) {
            badgeClass = "badge-upcoming";    badgeLabel = "Upcoming";
          } else if (endsInPast) {
            badgeClass = "badge-exam-closed"; badgeLabel = "Closed";
          } else if (inProgress || attemptsRemaining > 0) {
            badgeClass = "badge-open";        badgeLabel = "Open";
          } else {
            badgeClass = "badge-completed";   badgeLabel = "Completed";
          }
        } else if (exam.status === "CLOSED") {
          if (attemptsUsed === 0) {
            badgeClass = "badge-exam-closed"; badgeLabel = "Closed";
          } else {
            badgeClass = "badge-completed";   badgeLabel = "Completed";
          }
        }

        // Helper: build View Results button(s) for a list of submitted attempts
        const viewResultsHtml = (attempts) => {
          if (attempts.length === 0) return "";
          if (attempts.length === 1) {
            const a = attempts[0];
            return resultsReleased
              ? `<a href="/attempt-results?attempt_id=${escapeAttr(a.id)}" class="btn2" style="display:inline-block;text-decoration:none;padding:8px 16px">View Results</a>`
              : `<button class="btn2" type="button" disabled style="opacity:0.45;cursor:not-allowed" title="Results not yet released">View Results</button>`;
          }
          // Multiple submitted attempts — one small button each
          const btns = attempts.map(a =>
            resultsReleased
              ? `<a href="/attempt-results?attempt_id=${escapeAttr(a.id)}" class="btn2" style="display:inline-block;text-decoration:none;padding:6px 12px;font-size:13px">Attempt ${a.attempt_no}</a>`
              : `<button class="btn2" type="button" disabled style="opacity:0.45;cursor:not-allowed;padding:6px 12px;font-size:13px" title="Results not yet released">Attempt ${a.attempt_no}</button>`
          ).join("");
          return `<div style="display:flex;flex-wrap:wrap;gap:6px">${btns}</div>`;
        };

        // Action buttons — evaluated in priority order
        let actionHtml = "";
        if (inProgress) {
          // Case 1: resume the in-progress attempt
          actionHtml = `<a href="/attempt-take?attempt_id=${escapeAttr(inProgress.id)}" class="btn2" style="display:inline-block;text-decoration:none;padding:8px 16px">Resume Exam</a>`;
        } else if (attemptsRemaining > 0) {
          // Case 2: can start new attempt + show prior results (if any)
          const startBtn  = `<a href="/attempt-start?exam_id=${escapeAttr(exam.exam_id)}" class="btn2" style="display:inline-block;text-decoration:none;padding:8px 16px">Start Exam</a>`;
          const viewBtns  = viewResultsHtml(submitted);
          actionHtml = viewBtns
            ? `<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px">${startBtn}${viewBtns}</div>`
            : startBtn;
        } else if (submitted.length > 0) {
          // Case 3: no attempts remaining — show results only
          actionHtml = viewResultsHtml(submitted);
        }
        // Case 4: no attempts + none remaining → actionHtml stays ""

        cards.push(`
          <div class="card" style="margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
              <div style="flex:1;min-width:0">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
                  <h2 style="margin:0;font-size:18px">${escapeHtml(exam.title)}</h2>
                  ${exam.exam_password ? `<span title="Password required" style="font-size:15px">🔒</span>` : ""}
                  ${exam.cf_count > 0 ? `<span title="Requires additional info before starting" style="font-size:15px">📋</span>` : ""}
                  <span class="pill ${badgeClass}">${escapeHtml(badgeLabel)}</span>
                </div>
                <div class="muted" style="font-size:13px;margin-bottom:8px">${escapeHtml(exam.course_title)}</div>
                <div style="display:flex;gap:20px;font-size:13px;flex-wrap:wrap">
                  <span style="color:rgba(0,0,0,.55)">⏱ ${escapeHtml(String(exam.duration_mins || 60))} mins</span>
                  <span style="color:rgba(0,0,0,.55)">${attemptsRemaining} of ${exam.max_attempts} attempt${exam.max_attempts !== 1 ? "s" : ""} remaining</span>
                </div>
              </div>
              ${actionHtml ? `<div style="flex-shrink:0">${actionHtml}</div>` : ""}
            </div>
          </div>
        `);
      }

      const examListHtml = cards.length > 0
        ? cards.join("")
        : `<div class="card"><p class="muted" style="text-align:center;padding:24px 0">No exams available yet. Check back later.</p></div>`;

      return page(`
        <style>
          .badge-upcoming{background:#f0f0f0;color:#555}
          .badge-open{background:#d4f5e9;color:#0b7a75}
          .badge-completed{background:#dbeafe;color:#1d4ed8}
          .badge-exam-closed{background:#ffe8e8;color:#c00}
        </style>
        <div class="card">
          <div class="topbar">
            <div>
              <h1>Student Dashboard</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ""}
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        ${mySittingsHtml}
        <h2 style="margin:24px 0 12px">My Exams</h2>
        ${examListHtml}
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
