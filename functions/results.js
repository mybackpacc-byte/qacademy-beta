// functions/results.js
// Student Results Page — handles /attempt-results and /attempt-review

import { createHelpers } from "./shared.js";

export async function handleResultsRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    const {
      page, redirect, escapeHtml, escapeAttr,
      first, all,
      requireLogin, pickActiveMembership,
    } = createHelpers(request, env);

    // ----------------------------------------------------------------
    // GET /attempt-results
    // ----------------------------------------------------------------
    if (path === "/attempt-results" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const attemptId = url.searchParams.get("attempt_id") || "";
      if (!attemptId) return redirect("/student");

      const attempt = await first(
        `SELECT * FROM exam_attempts WHERE id=? AND user_id=? AND tenant_id=? AND status='SUBMITTED'`,
        [attemptId, r.user.id, active.tenant_id]
      );
      if (!attempt) return redirect("/student");

      const exam = await first(
        `SELECT * FROM exams WHERE id=? AND tenant_id=?`,
        [attempt.exam_id, active.tenant_id]
      );
      if (!exam) return redirect("/student");

      const resultsReleased =
        exam.results_published_at &&
        Date.parse(exam.results_published_at) <= Date.now();

      if (!resultsReleased) {
        return page(`
          <div class="card">
            <div class="topbar"><div><a href="/student">← My Exams</a></div></div>
          </div>
          <div class="card" style="text-align:center;padding:32px 24px">
            <div style="font-size:40px;margin-bottom:12px">🔒</div>
            <h1 style="margin:0 0 8px">Results not yet released</h1>
            <p class="muted">Your results have not been released yet. Please check back later.</p>
            <div style="margin-top:20px">
              <a href="/student" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">← Back to My Exams</a>
            </div>
          </div>
        `);
      }

      // Load supporting data
      const tenant = await first(`SELECT name FROM tenants WHERE id=?`, [active.tenant_id]);
      const course = await first(
        `SELECT title FROM courses WHERE id=? AND tenant_id=?`,
        [exam.course_id, active.tenant_id]
      );
      const student = await first(`SELECT name FROM users WHERE id=?`, [r.user.id]);

      // Find the class this student belongs to that has exam access for this exam
      const classRow = await first(
        `SELECT DISTINCT cl.name FROM class_students cs
         JOIN classes cl ON cl.id = cs.class_id
         WHERE cs.user_id = ? AND cl.tenant_id = ?
         AND EXISTS (
           SELECT 1 FROM class_students cs2
           JOIN exam_access ea ON ea.resource_type = 'CLASS' AND ea.resource_id = cs2.class_id
           WHERE cs2.class_id = cl.id AND ea.exam_id = ?
         )
         LIMIT 1`,
        [r.user.id, active.tenant_id, attempt.exam_id]
      );

      // Custom field definitions and answers
      const customFieldDefs = await all(
        `SELECT id, field_label FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`,
        [attempt.exam_id]
      );

      let cfAnswers = {};
      try { cfAnswers = JSON.parse(attempt.custom_fields_json || "{}"); } catch (e) {}

      let gradeBands = [];
      try { gradeBands = JSON.parse(attempt.grade_bands_json || "[]"); } catch (e) {}

      const qCountRow = await first(
        `SELECT COUNT(*) AS c FROM exam_questions WHERE exam_id=? AND tenant_id=?`,
        [attempt.exam_id, active.tenant_id]
      );
      const totalQuestions = qCountRow ? Number(qCountRow.c) : 0;

      // ---------- Format helpers ----------
      function fmtTimeTaken(secs) {
        if (!secs) return "less than a second";
        const s = Math.round(Number(secs));
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        const parts = [];
        if (h > 0) parts.push(`${h} hour${h !== 1 ? "s" : ""}`);
        if (m > 0) parts.push(`${m} minute${m !== 1 ? "s" : ""}`);
        if (sec > 0 && h === 0) parts.push(`${sec} second${sec !== 1 ? "s" : ""}`);
        return parts.join(", ") || "less than a second";
      }

      function fmtSubmittedAt(iso) {
        if (!iso) return "—";
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return iso;
        const day = String(d.getUTCDate()).padStart(2, "0");
        const months = [
          "January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December",
        ];
        const month = months[d.getUTCMonth()];
        const year = d.getUTCFullYear();
        const hh = String(d.getUTCHours()).padStart(2, "0");
        const mm = String(d.getUTCMinutes()).padStart(2, "0");
        return `${day} ${month} ${year} at ${hh}:${mm}`;
      }

      function fmtDuration(mins) {
        const m = Number(mins) || 0;
        const h = Math.floor(m / 60);
        const rem = m % 60;
        if (h > 0 && rem > 0) return `${h} hour${h !== 1 ? "s" : ""} ${rem} minute${rem !== 1 ? "s" : ""}`;
        if (h > 0) return `${h} hour${h !== 1 ? "s" : ""}`;
        return `${rem} minute${rem !== 1 ? "s" : ""}`;
      }

      // ---------- Section 2: custom field rows ----------
      const cfRows = customFieldDefs.map((cf) => {
        const val = cfAnswers[cf.id] || "";
        if (!val) return "";
        return `<div style="margin-bottom:6px"><span class="muted">${escapeHtml(cf.field_label)}:</span> <b>${escapeHtml(val)}</b></div>`;
      }).join("");

      const attemptLine = Number(exam.max_attempts) > 1
        ? `<div style="margin-bottom:6px"><span class="muted">Attempt:</span> <b>${attempt.attempt_no} of ${exam.max_attempts}</b></div>`
        : "";

      // ---------- Section 3: grade bands table ----------
      const gradeBandsTable = gradeBands.length > 0
        ? `<table class="table" style="margin-top:12px">
            <thead><tr><th>Grade</th><th>Minimum %</th></tr></thead>
            <tbody>${gradeBands.map((b) =>
              `<tr><td>${escapeHtml(b.label)}</td><td>${escapeHtml(String(b.min_percent))}%</td></tr>`
            ).join("")}</tbody>
           </table>`
        : "";

      // ---------- Section 4: result ----------
      const sd = attempt.score_display || "BOTH";
      const scorePct = attempt.score_pct !== null && attempt.score_pct !== undefined
        ? Number(attempt.score_pct) : null;
      const scoreRaw = attempt.score_raw !== null && attempt.score_raw !== undefined
        ? Number(attempt.score_raw) : null;
      const scoreTotal = attempt.score_total !== null && attempt.score_total !== undefined
        ? Number(attempt.score_total) : null;

      let scoreHtml = "";
      if (sd === "BOTH" && scorePct !== null && scoreRaw !== null) {
        scoreHtml = `<div style="font-size:42px;font-weight:800;color:#0b7a75;margin-bottom:8px">${Math.round(scorePct)}% &mdash; ${scoreRaw} / ${scoreTotal} marks</div>`;
      } else if (sd === "PERCENT" && scorePct !== null) {
        scoreHtml = `<div style="font-size:48px;font-weight:800;color:#0b7a75;margin-bottom:8px">${Math.round(scorePct)}%</div>`;
      } else if (sd === "MARKS" && scoreRaw !== null) {
        scoreHtml = `<div style="font-size:42px;font-weight:800;color:#0b7a75;margin-bottom:8px">${scoreRaw} / ${scoreTotal} marks</div>`;
      }

      const gradeHtml = attempt.grade
        ? `<div style="font-size:32px;font-weight:800;margin-bottom:8px">${escapeHtml(String(attempt.grade))}</div>`
        : "";

      let passBadgeHtml = "";
      if (attempt.pass_mark_percent !== null && attempt.pass_mark_percent !== undefined && scorePct !== null) {
        const passed = scorePct >= Number(attempt.pass_mark_percent);
        passBadgeHtml = passed
          ? `<div style="display:inline-block;background:#d4f5e9;color:#0b5e4e;border-radius:999px;padding:6px 18px;font-size:16px;font-weight:800;margin-top:8px">&#10003; PASS</div>`
          : `<div style="display:inline-block;background:#fff3f3;color:#c00;border-radius:999px;padding:6px 18px;font-size:16px;font-weight:800;margin-top:8px">&#10007; FAIL</div>`;
      }

      const noResultInfo = sd === "NONE" && !attempt.grade &&
        (attempt.pass_mark_percent === null || attempt.pass_mark_percent === undefined);
      const resultContent = noResultInfo
        ? `<div style="font-size:16px;color:rgba(0,0,0,.6)">Your result has been recorded.</div>`
        : `${scoreHtml}${gradeHtml}${passBadgeHtml}`;

      // ---------- Section 5: actions ----------
      const reviewBtn = Number(exam.allow_review) === 1
        ? `<a href="/attempt-review?attempt_id=${escapeAttr(attemptId)}" class="btn2" style="display:inline-block;padding:10px 16px;text-decoration:none">Review My Answers</a>`
        : "";

      return page(`
        <style>
          .result-wrap{max-width:680px;margin:0 auto}
          @media print{
            .no-print{display:none!important}
            .card{border:1px solid #ccc!important;box-shadow:none!important}
            body{background:#fff!important}
          }
        </style>
        <div class="result-wrap">
          <div class="card no-print" style="margin-bottom:8px">
            <a href="/student" style="font-size:13px;color:rgba(0,0,0,.45)">&#8592; Back to My Exams</a>
          </div>

          <!-- Section 1: Header -->
          <div class="card" style="text-align:center;padding:24px">
            <div style="font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:rgba(0,0,0,.45);margin-bottom:8px">${escapeHtml(tenant?.name || "")}</div>
            <h1 style="margin:0 0 6px;font-size:24px">${escapeHtml(exam.title)}</h1>
            ${course ? `<div class="muted">${escapeHtml(course.title)}</div>` : ""}
            ${classRow ? `<div class="muted" style="margin-top:4px">${escapeHtml(classRow.name)}</div>` : ""}
          </div>

          <!-- Section 2: Student details -->
          <div class="card">
            <h2 style="margin:0 0 12px">Student Details</h2>
            <div style="margin-bottom:6px"><span class="muted">Name:</span> <b>${escapeHtml(student?.name || "")}</b></div>
            ${cfRows}
            ${attemptLine}
            <div style="margin-bottom:6px"><span class="muted">Submitted:</span> <b>${fmtSubmittedAt(attempt.submitted_at)}</b></div>
            <div><span class="muted">Time taken:</span> <b>${fmtTimeTaken(attempt.time_taken_secs)}</b></div>
          </div>

          <!-- Section 3: Exam details -->
          <div class="card">
            <h2 style="margin:0 0 12px">Exam Details</h2>
            <div class="row">
              <div>
                <div style="margin-bottom:6px"><span class="muted">Total marks:</span> <b>${escapeHtml(String(attempt.score_total ?? "—"))}</b></div>
                <div style="margin-bottom:6px"><span class="muted">Questions:</span> <b>${totalQuestions}</b></div>
              </div>
              <div>
                <div style="margin-bottom:6px"><span class="muted">Duration:</span> <b>${fmtDuration(exam.duration_mins)}</b></div>
                <div><span class="muted">Pass mark:</span> <b>${attempt.pass_mark_percent !== null && attempt.pass_mark_percent !== undefined ? `${attempt.pass_mark_percent}% required to pass` : "No pass mark set"}</b></div>
              </div>
            </div>
            ${gradeBandsTable}
          </div>

          <!-- Section 4: Result -->
          <div class="card" style="text-align:center;padding:32px 24px">
            <h2 style="margin:0 0 16px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:rgba(0,0,0,.45)">Your Result</h2>
            ${resultContent}
          </div>

          <!-- Section 5: Actions -->
          <div class="card actions no-print" style="margin-bottom:24px">
            ${reviewBtn}
            <a href="/student" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">&#8592; Back to My Exams</a>
            <button class="btn3" onclick="window.print()" style="cursor:pointer">&#128438; Print</button>
          </div>
        </div>
      `);
    }

    // ----------------------------------------------------------------
    // GET /attempt-review  (stub — coming soon)
    // ----------------------------------------------------------------
    if (path === "/attempt-review" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const attemptId = url.searchParams.get("attempt_id") || "";

      return page(`
        <div class="card">
          <div class="topbar"><div><a href="/student">&#8592; My Exams</a></div></div>
        </div>
        <div class="card">
          <h1>Review My Answers</h1>
          <p class="muted">This feature is coming soon.</p>
          <div class="actions" style="margin-top:16px">
            ${attemptId
              ? `<a href="/attempt-results?attempt_id=${escapeAttr(attemptId)}" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">&#8592; Back to Results</a>`
              : `<a href="/student" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">&#8592; My Exams</a>`
            }
          </div>
        </div>
      `);
    }

    // Fallback
    return redirect("/student");

  } catch (err) {
    console.error("FATAL [results]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (results):\n\n" + msg, { status: 500 });
  }
}
