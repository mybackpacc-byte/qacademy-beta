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

      // Find a class this student belongs to within the tenant
      const classRow = await first(
        `SELECT cl.name FROM class_students cs
         JOIN classes cl ON cl.id = cs.class_id
         WHERE cs.user_id = ? AND cl.tenant_id = ?
         LIMIT 1`,
        [r.user.id, active.tenant_id]
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
    // GET /attempt-review
    // ----------------------------------------------------------------
    if (path === "/attempt-review" && request.method === "GET") {
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

      const backLink = `<a href="/attempt-results?attempt_id=${escapeAttr(attemptId)}" style="font-size:13px;color:rgba(0,0,0,.45)">&#8592; Back to Results</a>`;

      if (Number(exam.allow_review) !== 1) {
        return page(`
          <div class="card" style="margin-bottom:8px">${backLink}</div>
          <div class="card" style="text-align:center;padding:32px 24px">
            <div style="font-size:40px;margin-bottom:12px">&#128274;</div>
            <h1 style="margin:0 0 8px">Review not available</h1>
            <p class="muted">Review of answers is not enabled for this exam.</p>
            <div style="margin-top:20px">${backLink}</div>
          </div>
        `);
      }

      const resultsReleased =
        exam.results_published_at &&
        Date.parse(exam.results_published_at) <= Date.now();

      if (!resultsReleased) {
        return page(`
          <div class="card" style="margin-bottom:8px">${backLink}</div>
          <div class="card" style="text-align:center;padding:32px 24px">
            <div style="font-size:40px;margin-bottom:12px">&#128274;</div>
            <h1 style="margin:0 0 8px">Results not yet released</h1>
            <p class="muted">Your results have not been released yet. Please check back later.</p>
            <div style="margin-top:20px">${backLink}</div>
          </div>
        `);
      }

      // Parse question order (the order the student saw them)
      let questionOrder = [];
      try { questionOrder = JSON.parse(attempt.question_order_json || "[]"); } catch(e) {}

      // Load questions, then reorder to match question_order_json
      let questions = [];
      const optionsByQ = {};
      if (questionOrder.length > 0) {
        const ph = questionOrder.map(() => "?").join(",");
        const questionRows = await all(
          `SELECT id, question_type, question_text, marks, model_answer, feedback
           FROM exam_questions WHERE id IN (${ph})`,
          questionOrder
        );
        const questionMap = {};
        for (const q of questionRows) questionMap[q.id] = q;
        questions = questionOrder.map(id => questionMap[id]).filter(Boolean);

        // Load options (using question_id column)
        const optRows = await all(
          `SELECT id, question_id, option_text, is_correct, feedback, sort_order
           FROM exam_question_options WHERE question_id IN (${ph}) ORDER BY sort_order ASC`,
          questionOrder
        );
        for (const o of optRows) {
          if (!optionsByQ[o.question_id]) optionsByQ[o.question_id] = [];
          optionsByQ[o.question_id].push(o);
        }
      }

      // Load answers for this attempt
      const answerRows = await all(
        `SELECT question_id, answer_json, score_awarded, teacher_note FROM exam_answers WHERE attempt_id=?`,
        [attemptId]
      );
      const answersByQ = {};
      for (const a of answerRows) answersByQ[a.question_id] = a;

      // ---------- Compact score banner (same logic as results page) ----------
      const sd = attempt.score_display || "BOTH";
      const scorePct = attempt.score_pct !== null && attempt.score_pct !== undefined
        ? Number(attempt.score_pct) : null;
      const scoreRaw = attempt.score_raw !== null && attempt.score_raw !== undefined
        ? Number(attempt.score_raw) : null;
      const scoreTotal = attempt.score_total !== null && attempt.score_total !== undefined
        ? Number(attempt.score_total) : null;

      const bannerParts = [];
      if (sd === "BOTH" && scorePct !== null && scoreRaw !== null) {
        bannerParts.push(`<b style="font-size:16px;color:#0b7a75">${Math.round(scorePct)}%</b> <span class="muted">&mdash; ${scoreRaw} / ${scoreTotal} marks</span>`);
      } else if (sd === "PERCENT" && scorePct !== null) {
        bannerParts.push(`<b style="font-size:16px;color:#0b7a75">${Math.round(scorePct)}%</b>`);
      } else if (sd === "MARKS" && scoreRaw !== null) {
        bannerParts.push(`<b style="font-size:16px;color:#0b7a75">${scoreRaw} / ${scoreTotal} marks</b>`);
      }
      if (attempt.grade) {
        bannerParts.push(`Grade: <b>${escapeHtml(String(attempt.grade))}</b>`);
      }
      if (attempt.pass_mark_percent !== null && attempt.pass_mark_percent !== undefined && scorePct !== null) {
        const passed = scorePct >= Number(attempt.pass_mark_percent);
        bannerParts.push(passed
          ? `<span style="background:#d4f5e9;color:#0b5e4e;border-radius:999px;padding:2px 10px;font-size:13px;font-weight:700">&#10003; PASS</span>`
          : `<span style="background:#fff3f3;color:#c00;border-radius:999px;padding:2px 10px;font-size:13px;font-weight:700">&#10007; FAIL</span>`
        );
      }
      const noResultInfo = sd === "NONE" && !attempt.grade &&
        (attempt.pass_mark_percent === null || attempt.pass_mark_percent === undefined);
      const scoreBanner = noResultInfo
        ? `<span class="muted">Result recorded</span>`
        : (bannerParts.length > 0 ? bannerParts.join(" &ensp;&middot;&ensp; ") : "");

      // ---------- Helper: render one option row ----------
      function renderOption(o, isSelected, isMultiSelect) {
        const isCorrect = !!o.is_correct;
        const mark = isCorrect
          ? `<span style="color:#1a7a4a;font-weight:800;flex-shrink:0;font-size:15px">&#10003;</span>`
          : `<span style="color:#c00;flex-shrink:0;font-size:15px">&#10007;</span>`;
        let bg = "rgba(0,0,0,.03)";
        if (isSelected && isCorrect)        bg = "#d4f5e9";
        else if (isSelected && !isCorrect)  bg = "#fff3f3";
        else if (!isSelected && isCorrect && isMultiSelect) bg = "#fff8e1";
        const selectedNote = isSelected
          ? ` <span style="font-size:11px;color:rgba(0,0,0,.4);font-weight:600">(your answer)</span>`
          : "";
        const feedbackHtml = (o.feedback && o.feedback !== "")
          ? `<div style="background:#f6f8f7;border-radius:7px;padding:7px 10px;margin-top:5px;font-size:13px;color:rgba(0,0,0,.6)">${escapeHtml(o.feedback)}</div>`
          : "";
        return `
          <div style="padding:8px 12px;border-radius:8px;margin:3px 0;background:${bg}">
            <div style="display:flex;align-items:baseline;gap:8px;font-size:14px">
              ${mark}
              <span>${escapeHtml(o.option_text)}${selectedNote}</span>
            </div>
            ${feedbackHtml}
          </div>`;
      }

      // ---------- Build question cards ----------
      const questionCards = questions.map((q, qi) => {
        const qNum = qi + 1;
        const ans = answersByQ[q.id] || {};
        const sa = (ans.score_awarded !== null && ans.score_awarded !== undefined) ? Number(ans.score_awarded) : null;
        const marks = Number(q.marks || 0);
        const marksHtml = sa !== null
          ? `<span style="background:#d4f5e9;color:#0b5e4e;border-radius:6px;padding:3px 9px;font-size:13px;font-weight:700">${sa} / ${marks} mark${marks !== 1 ? "s" : ""}</span>`
          : `<span style="background:rgba(0,0,0,.06);color:rgba(0,0,0,.5);border-radius:6px;padding:3px 9px;font-size:13px;font-weight:600">${marks} mark${marks !== 1 ? "s" : ""}</span>`;

        let body = "";

        if (q.question_type === "MCQ" || q.question_type === "TRUE_FALSE") {
          const opts = optionsByQ[q.id] || [];
          let selectedId = null;
          try { if (ans.answer_json != null && ans.answer_json !== "") selectedId = String(JSON.parse(ans.answer_json)); } catch(e) {}
          if (!selectedId) {
            body += `<div style="color:rgba(0,0,0,.45);font-style:italic;font-size:13px;padding:2px 0 8px">Not answered</div>`;
          }
          body += opts.map(o => renderOption(o, selectedId !== null && String(o.id) === selectedId, false)).join("");

        } else if (q.question_type === "MULTIPLE_SELECT") {
          const opts = optionsByQ[q.id] || [];
          let selectedIds = new Set();
          try {
            if (ans.answer_json != null && ans.answer_json !== "") {
              const p = JSON.parse(ans.answer_json);
              const arr = Array.isArray(p) ? p : (p ? [p] : []);
              selectedIds = new Set(arr.map(String));
            }
          } catch(e) {}
          if (selectedIds.size === 0) {
            body += `<div style="color:rgba(0,0,0,.45);font-style:italic;font-size:13px;padding:2px 0 8px">Not answered</div>`;
          }
          body += opts.map(o => renderOption(o, selectedIds.has(String(o.id)), true)).join("");

        } else {
          // SHORT_ANSWER / ESSAY
          let displayText = "";
          try {
            if (ans.answer_json != null && ans.answer_json !== "") {
              const p = JSON.parse(ans.answer_json);
              displayText = typeof p === "string" ? p : String(p);
            }
          } catch(e) { displayText = ans.answer_json || ""; }
          body += `
            <div style="background:#f6f8f7;border-radius:10px;padding:12px;margin-bottom:8px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:rgba(0,0,0,.45);margin-bottom:6px">Your answer</div>
              <div style="font-size:14px;white-space:pre-wrap;min-height:18px">${displayText ? escapeHtml(displayText) : `<span style="font-style:italic;color:rgba(0,0,0,.35)">Not answered</span>`}</div>
            </div>`;
          if (q.model_answer && q.model_answer !== "") {
            body += `
              <div style="background:#f0fff8;border:1px solid rgba(11,122,117,.15);border-radius:10px;padding:12px;margin-bottom:8px">
                <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#0b5e4e;margin-bottom:6px">Model answer</div>
                <div style="font-size:14px;white-space:pre-wrap">${escapeHtml(q.model_answer)}</div>
              </div>`;
          }
          if (ans.teacher_note && ans.teacher_note !== "") {
            body += `
              <div style="background:#fffbeb;border:1px solid rgba(200,150,0,.2);border-radius:10px;padding:12px">
                <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#7a5f0b;margin-bottom:6px">Teacher note</div>
                <div style="font-size:14px;white-space:pre-wrap">${escapeHtml(ans.teacher_note)}</div>
              </div>`;
          }
        }

        // Question-level feedback (MCQ / TRUE_FALSE / MULTIPLE_SELECT)
        if (q.question_type !== "SHORT_ANSWER" && q.question_type !== "ESSAY" &&
            q.feedback && q.feedback !== "") {
          body += `
            <div style="background:#eef4fb;border:1px solid rgba(66,133,244,.15);border-radius:10px;padding:10px 12px;margin-top:10px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#2c5282;margin-bottom:4px">Feedback</div>
              <div style="font-size:14px;color:#2d3748">${escapeHtml(q.feedback)}</div>
            </div>`;
        }

        return `
          <div class="card" style="margin:8px 0">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px">
              <div style="font-size:13px;font-weight:700;color:rgba(0,0,0,.5);background:rgba(0,0,0,.06);padding:3px 10px;border-radius:6px">Q${qNum}</div>
              ${marksHtml}
            </div>
            <div style="font-size:15px;font-weight:600;margin-bottom:10px">${escapeHtml(q.question_text)}</div>
            ${body}
          </div>`;
      }).join("");

      return page(`
        <style>.review-wrap{max-width:720px;margin:0 auto}</style>
        <div class="review-wrap">
          <div class="card" style="margin-bottom:8px">
            <div class="topbar">
              <div>${backLink}</div>
              <div style="font-size:14px;font-weight:700">${escapeHtml(exam.title)}</div>
            </div>
          </div>

          <div class="card" style="padding:12px 16px;margin-bottom:4px">
            <div style="font-size:14px">${scoreBanner}</div>
          </div>

          ${questionCards}

          <div class="card actions" style="margin-top:4px;margin-bottom:24px">
            <a href="/attempt-results?attempt_id=${escapeAttr(attemptId)}" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">&#8592; Back to Results</a>
          </div>
        </div>
      `);
    }

    // ----------------------------------------------------------------
    // GET /sitting-results
    // ----------------------------------------------------------------
    if (path === "/sitting-results" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");
      const tenantId = active.tenant_id;

      const sittingId = url.searchParams.get("sitting_id") || "";
      if (!sittingId) return redirect("/student");

      const sitting = await first(
        `SELECT * FROM exam_sittings WHERE id=? AND tenant_id=?`,
        [sittingId, tenantId]
      );
      if (!sitting) return redirect("/student");

      // Load papers in sitting order
      const papers = await all(
        `SELECT esp.exam_id, esp.sort_order,
                e.title, e.score_display, e.results_published_at, e.status AS exam_status
         FROM exam_sitting_papers esp
         JOIN exams e ON e.id=esp.exam_id
         WHERE esp.sitting_id=?
         ORDER BY esp.sort_order`,
        [sittingId]
      );

      if (papers.length === 0) return redirect("/student");
      const examIds = papers.map(p => p.exam_id);

      // Load student's latest submitted attempt per exam
      const placeholders = examIds.map(() => "?").join(",");
      const attempts = await all(
        `SELECT * FROM exam_attempts
         WHERE user_id=? AND tenant_id=? AND status='SUBMITTED'
           AND exam_id IN (${placeholders})
         ORDER BY submitted_at DESC`,
        [r.user.id, tenantId, ...examIds]
      );

      // Guard: student must have at least one attempt in this sitting
      if (attempts.length === 0) return redirect("/student");

      // Map: exam_id → earliest/latest attempt (first match = most recent due to ORDER BY DESC)
      const attemptByExam = {};
      for (const a of attempts) {
        if (!attemptByExam[a.exam_id]) attemptByExam[a.exam_id] = a;
      }

      // Render a card per paper
      const paperCards = papers.map((p, idx) => {
        const attempt = attemptByExam[p.exam_id] || null;
        const released = p.results_published_at && Date.parse(p.results_published_at) <= Date.now();
        const sd = p.score_display || "BOTH";

        let scoreHtml = "";
        if (!attempt) {
          scoreHtml = `<span class="muted">No submission</span>`;
        } else if (!released) {
          scoreHtml = `<span class="pill badge-draft">Pending</span>`;
        } else if (sd === "HIDDEN" || sd === "NONE") {
          scoreHtml = `<span class="muted">Score hidden</span>`;
        } else if (sd === "PASS_FAIL") {
          const passed = attempt.pass_fail === "PASS";
          scoreHtml = `<span class="pill ${passed ? "badge-published" : "badge-closed"}">${passed ? "Pass" : "Fail"}</span>`;
        } else {
          const parts = [];
          if (sd === "MARKS" || sd === "BOTH") {
            parts.push(`<strong>${attempt.score_raw ?? "—"}/${attempt.score_max ?? "—"}</strong>`);
          }
          if (sd === "PERCENT" || sd === "BOTH") {
            const pct = attempt.score_pct != null ? Math.round(attempt.score_pct) + "%" : "—%";
            parts.push(`<strong>${pct}</strong>`);
          }
          scoreHtml = parts.join(" &nbsp;·&nbsp; ");
        }

        const viewLink = attempt && released
          ? `<a href="/attempt-results?attempt_id=${escapeAttr(attempt.id)}" class="btn3" style="padding:6px 12px;text-decoration:none;font-size:13px">View →</a>`
          : "";

        return `
          <div class="card" style="margin:8px 0;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
            <div>
              <div style="font-size:12px;font-weight:700;color:rgba(0,0,0,.4);margin-bottom:3px">Paper ${idx + 1}</div>
              <div style="font-size:15px;font-weight:600">${escapeHtml(p.title)}</div>
            </div>
            <div style="display:flex;align-items:center;gap:12px">
              <div style="font-size:15px">${scoreHtml}</div>
              ${viewLink}
            </div>
          </div>`;
      }).join("");

      return page(`
        <div style="max-width:720px;margin:0 auto">
          <div class="card" style="margin-bottom:8px">
            <div class="topbar">
              <div><a href="/student">← My Sittings</a></div>
              <div style="font-size:14px;font-weight:700">${escapeHtml(sitting.title)}</div>
            </div>
          </div>

          ${sitting.academic_year || sitting.description ? `
            <div class="card" style="padding:12px 16px;margin-bottom:8px">
              ${sitting.academic_year ? `<div style="font-size:13px;color:rgba(0,0,0,.45)">Academic year: ${escapeHtml(sitting.academic_year)}</div>` : ""}
              ${sitting.description ? `<div style="font-size:13px;margin-top:4px">${escapeHtml(sitting.description)}</div>` : ""}
            </div>
          ` : ""}

          ${paperCards}

          <div class="card actions" style="margin-top:4px;margin-bottom:24px">
            <a href="/student" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">← Back to My Sittings</a>
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
