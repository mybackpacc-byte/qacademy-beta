// functions/attempts.js
// Exam taking engine
// GET/POST /attempt-start  — pre-flight wizard (password → custom fields → instructions)
// GET/POST /attempt-take   — the live exam screen
// GET      /attempt-complete — post-submission screen

import { createHelpers } from "./shared.js";

export async function handleAttemptRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    const {
      nowISO, uuid,
      page, redirect, escapeHtml, escapeAttr, fmtISO, form,
      first, all, run,
      requireLogin, pickActiveMembership,
    } = createHelpers(request, env);

    // =============================
    // Misc helpers
    // =============================
    function shuffle(arr) {
      const a = arr.slice();
      for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
      }
      return a;
    }

    function fmtSecs(secs) {
      const s = Math.max(0, Math.round(secs));
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      const pad = (n) => String(n).padStart(2, "0");
      if (h > 0) return `${h}:${pad(m)}:${pad(sec)}`;
      return `${m}:${pad(sec)}`;
    }

    function fmtMins(mins) {
      const m = Number(mins) || 0;
      const h = Math.floor(m / 60);
      const rem = m % 60;
      if (h > 0 && rem > 0) return `${h} hr ${rem} min`;
      if (h > 0) return `${h} hr`;
      return `${rem} min`;
    }

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

    function errCard(msg) {
      return `
        <div class="card">
          <div class="topbar">
            <div><a href="/student">← My Exams</a></div>
          </div>
        </div>
        <div class="card err" style="margin-top:12px">
          <p style="margin:0">${escapeHtml(msg)}</p>
        </div>
      `;
    }

    // =============================
    // Verify exam access for student
    // =============================
    async function loadExamForStudent(examId, tenantId, userId) {
      const exam = await first(`SELECT * FROM exams WHERE id=? AND tenant_id=?`, [examId, tenantId]);
      if (!exam || exam.status !== "PUBLISHED") return null;
      const access = await first(
        `SELECT 1 AS x FROM exam_access WHERE exam_id=? AND user_id=? LIMIT 1`,
        [examId, userId]
      );
      return access ? exam : null;
    }

    // =============================
    // Auto-submit (timer expiry / hard cut)
    // =============================
    async function doAutoSubmit(attemptId, tenantId) {
      const attempt = await first(
        `SELECT started_at, exam_id FROM exam_attempts WHERE id=? AND tenant_id=? AND status='IN_PROGRESS'`,
        [attemptId, tenantId]
      );
      if (!attempt) return;
      const ts = nowISO();
      const timeTakenSecs = Math.round((Date.parse(ts) - Date.parse(attempt.started_at)) / 1000);
      const exam = await first(`SELECT ends_at FROM exams WHERE id=?`, [attempt.exam_id]);
      const isLate = exam && exam.ends_at && Date.parse(ts) > Date.parse(exam.ends_at) ? 1 : 0;
      await run(
        `UPDATE exam_attempts SET status='SUBMITTED', submitted_at=?, time_taken_secs=?, auto_submitted=1, is_late=?, updated_at=? WHERE id=? AND tenant_id=?`,
        [ts, timeTakenSecs, isLate, ts, attemptId, tenantId]
      );
    }

    // =============================
    // Wizard render helpers
    // =============================
    function renderPasswordStep(exam, examId, errorMsg) {
      return `
        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/student">← My Exams</a></div>
              <h1 style="margin:0">${escapeHtml(exam.title)}</h1>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 14px">Exam password required</h2>
          ${errorMsg ? `<div class="err" style="margin-bottom:12px">${escapeHtml(errorMsg)}</div>` : ""}
          <form method="post" action="/attempt-start">
            <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
            <input type="hidden" name="step" value="password" />
            <label>Enter the exam password</label>
            <input type="password" name="exam_password" required autofocus autocomplete="off" />
            <div style="margin-top:14px">
              <button type="submit" class="btn2">Continue →</button>
            </div>
          </form>
        </div>
      `;
    }

    function renderCustomFieldsStep(exam, examId, customFields, confirmedPassword, errorMsg) {
      const fieldInputs = customFields.map((cf) => {
        const opts = (cf.field_options || "").split(",").map((s) => s.trim()).filter(Boolean);
        let input = "";
        if (cf.field_type === "DROPDOWN" && opts.length > 0) {
          input = `<select name="cf_${escapeAttr(cf.id)}" ${cf.is_required ? "required" : ""}>
            <option value="">— select —</option>
            ${opts.map((o) => `<option value="${escapeAttr(o)}">${escapeHtml(o)}</option>`).join("")}
          </select>`;
        } else if (cf.field_type === "NUMBER") {
          input = `<input type="number" name="cf_${escapeAttr(cf.id)}" ${cf.is_required ? "required" : ""} />`;
        } else {
          input = `<input type="text" name="cf_${escapeAttr(cf.id)}" ${cf.is_required ? "required" : ""} />`;
        }
        return `
          <div style="margin-bottom:12px">
            <label>${escapeHtml(cf.field_label)}${cf.is_required ? ` <span style="color:#c00">*</span>` : ""}</label>
            ${input}
          </div>
        `;
      }).join("");

      return `
        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/student">← My Exams</a></div>
              <h1 style="margin:0">${escapeHtml(exam.title)}</h1>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 14px">Additional information required</h2>
          ${errorMsg ? `<div class="err" style="margin-bottom:12px">${escapeHtml(errorMsg)}</div>` : ""}
          <form method="post" action="/attempt-start">
            <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
            <input type="hidden" name="step" value="custom_fields" />
            ${confirmedPassword ? `<input type="hidden" name="confirmed_password" value="${escapeAttr(confirmedPassword)}" />` : ""}
            ${fieldInputs}
            <div style="margin-top:14px">
              <button type="submit" class="btn2">Continue →</button>
            </div>
          </form>
        </div>
      `;
    }

    async function renderInstructionsStep(exam, examId, cfAnswers, confirmedPassword, errorMsg) {
      const qCountRow = await first(
        `SELECT COUNT(*) AS c FROM exam_questions WHERE exam_id=? AND tenant_id=?`,
        [examId, exam.tenant_id]
      );
      const qCount = qCountRow ? Number(qCountRow.c) : 0;

      const cfHiddens = Object.entries(cfAnswers)
        .map(([id, val]) => `<input type="hidden" name="cf_${escapeAttr(id)}" value="${escapeAttr(val)}" />`)
        .join("");

      return `
        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/student">← My Exams</a></div>
              <h1 style="margin:0">${escapeHtml(exam.title)}</h1>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 16px">Exam instructions</h2>
          ${errorMsg ? `<div class="err" style="margin-bottom:12px">${escapeHtml(errorMsg)}</div>` : ""}
          ${exam.description ? `<p style="font-size:14px;line-height:1.6;margin:0 0 16px">${escapeHtml(exam.description)}</p>` : ""}
          <div class="row" style="margin-bottom:20px">
            <div class="card" style="background:#f6f8f7;border:none;padding:16px;text-align:center">
              <div style="font-size:26px;font-weight:800;color:#0b7a75">${fmtMins(exam.duration_mins)}</div>
              <div class="muted" style="font-size:12px;margin-top:4px">Duration</div>
            </div>
            <div class="card" style="background:#f6f8f7;border:none;padding:16px;text-align:center">
              <div style="font-size:26px;font-weight:800;color:#0b7a75">${escapeHtml(String(qCount))}</div>
              <div class="muted" style="font-size:12px;margin-top:4px">Question${qCount !== 1 ? "s" : ""}</div>
            </div>
          </div>
          <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:10px;padding:10px 14px;margin-bottom:20px;font-size:13px">
            <b>Important:</b> Once you start, the timer begins. Do not close this tab — your progress is saved automatically every 30 seconds.
          </div>
          <form method="post" action="/attempt-start">
            <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
            <input type="hidden" name="step" value="instructions" />
            ${confirmedPassword ? `<input type="hidden" name="confirmed_password" value="${escapeAttr(confirmedPassword)}" />` : ""}
            ${cfHiddens}
            <button type="submit" class="btn2" style="padding:12px 24px;font-size:15px">Start Exam →</button>
          </form>
        </div>
      `;
    }

    // =====================================================
    // GET /attempt-start
    // =====================================================
    if (path === "/attempt-start" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const examId = url.searchParams.get("exam_id") || "";
      if (!examId) return redirect("/student");

      const exam = await loadExamForStudent(examId, active.tenant_id, r.user.id);
      if (!exam) return page(errCard("Exam not found or you don't have access."));

      if (exam.ends_at && Date.parse(exam.ends_at) < Date.now()) {
        return page(errCard("This exam is no longer available."));
      }

      const inProgress = await first(
        `SELECT id FROM exam_attempts WHERE exam_id=? AND user_id=? AND tenant_id=? AND status='IN_PROGRESS' LIMIT 1`,
        [examId, r.user.id, active.tenant_id]
      );
      if (inProgress) return redirect(`/attempt-take?attempt_id=${inProgress.id}`);

      const usedRow = await first(
        `SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=? AND user_id=? AND tenant_id=? AND status != 'ABANDONED'`,
        [examId, r.user.id, active.tenant_id]
      );
      if ((usedRow ? Number(usedRow.c) : 0) >= exam.max_attempts) {
        return page(errCard("You have used all your attempts for this exam."));
      }

      const customFields = await all(
        `SELECT id, field_label, field_type, field_options, is_required FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );

      if (exam.exam_password) {
        return page(renderPasswordStep(exam, examId, ""));
      }
      if (customFields.length > 0) {
        return page(renderCustomFieldsStep(exam, examId, customFields, "", ""));
      }
      return page(await renderInstructionsStep(exam, examId, {}, "", ""));
    }

    // =====================================================
    // POST /attempt-start
    // =====================================================
    if (path === "/attempt-start" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      if (!examId) return redirect("/student");

      const exam = await loadExamForStudent(examId, active.tenant_id, r.user.id);
      if (!exam) return page(errCard("Exam not found or you don't have access."));

      if (exam.ends_at && Date.parse(exam.ends_at) < Date.now()) {
        return page(errCard("This exam is no longer available."));
      }

      const inProgress = await first(
        `SELECT id FROM exam_attempts WHERE exam_id=? AND user_id=? AND tenant_id=? AND status='IN_PROGRESS' LIMIT 1`,
        [examId, r.user.id, active.tenant_id]
      );
      if (inProgress) return redirect(`/attempt-take?attempt_id=${inProgress.id}`);

      const usedRow = await first(
        `SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=? AND user_id=? AND tenant_id=? AND status != 'ABANDONED'`,
        [examId, r.user.id, active.tenant_id]
      );
      const used = usedRow ? Number(usedRow.c) : 0;
      if (used >= exam.max_attempts) {
        return page(errCard("You have used all your attempts for this exam."));
      }

      const customFields = await all(
        `SELECT id, field_label, field_type, field_options, is_required FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );
      const hasPassword = !!(exam.exam_password);
      const hasCustomFields = customFields.length > 0;
      const step = (f.step || "").trim();

      // ---- step=password ----
      if (step === "password") {
        const pwd = (f.exam_password || "");
        if (pwd !== exam.exam_password) {
          return page(renderPasswordStep(exam, examId, "Incorrect password. Please try again."));
        }
        if (hasCustomFields) {
          return page(renderCustomFieldsStep(exam, examId, customFields, pwd, ""));
        }
        return page(await renderInstructionsStep(exam, examId, {}, pwd, ""));
      }

      // ---- step=custom_fields ----
      if (step === "custom_fields") {
        const confirmedPwd = (f.confirmed_password || "");
        if (hasPassword && confirmedPwd !== exam.exam_password) {
          return page(renderPasswordStep(exam, examId, "Session expired. Please re-enter the password."));
        }
        const cfAnswers = {};
        for (const cf of customFields) {
          cfAnswers[cf.id] = (f[`cf_${cf.id}`] || "").trim();
        }
        return page(await renderInstructionsStep(exam, examId, cfAnswers, confirmedPwd, ""));
      }

      // ---- step=instructions → create attempt ----
      if (step === "instructions") {
        const confirmedPwd = (f.confirmed_password || "");
        if (hasPassword && confirmedPwd !== exam.exam_password) {
          return page(renderPasswordStep(exam, examId, "Session expired. Please re-enter the password."));
        }

        const cfAnswers = {};
        for (const cf of customFields) {
          cfAnswers[cf.id] = (f[`cf_${cf.id}`] || "").trim();
        }

        const questions = await all(
          `SELECT id, question_type FROM exam_questions WHERE exam_id=? AND tenant_id=? ORDER BY sort_order ASC`,
          [examId, active.tenant_id]
        );
        if (questions.length === 0) return page(errCard("This exam has no questions yet."));

        let questionIds = questions.map((q) => q.id);
        if (Number(exam.shuffle_questions)) questionIds = shuffle(questionIds);

        // Effective duration
        let effectiveDurationSecs = (exam.duration_mins || 60) * 60;
        if (exam.ends_at) {
          const secsUntilClose = Math.floor((Date.parse(exam.ends_at) - Date.now()) / 1000);
          if (secsUntilClose <= 0) return page(errCard("This exam is no longer available."));
          effectiveDurationSecs = Math.min(effectiveDurationSecs, secsUntilClose);
        }

        // Snapshot grade bands
        const bands = await all(
          `SELECT label, min_percent FROM exam_grade_bands WHERE exam_id=? ORDER BY min_percent DESC`,
          [examId]
        );

        const ts = nowISO();
        const attemptId = uuid();

        await run(
          `INSERT INTO exam_attempts
           (id, tenant_id, exam_id, user_id, attempt_no, status, started_at,
            effective_duration_secs, question_order_json, custom_fields_json,
            score_display, pass_mark_percent, grade_bands_json, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [
            attemptId, active.tenant_id, examId, r.user.id,
            used + 1, "IN_PROGRESS", ts,
            effectiveDurationSecs,
            JSON.stringify(questionIds),
            Object.keys(cfAnswers).length > 0 ? JSON.stringify(cfAnswers) : null,
            exam.score_display || "BOTH",
            exam.pass_mark_percent ?? null,
            bands.length > 0 ? JSON.stringify(bands) : null,
            ts, ts,
          ]
        );

        // Pre-create blank answer rows for every question
        for (const q of questions) {
          await run(
            `INSERT INTO exam_answers (id, attempt_id, question_id, question_type, answer_json, is_flagged, created_at, updated_at)
             VALUES (?,?,?,?,null,0,?,?)`,
            [uuid(), attemptId, q.id, q.question_type, ts, ts]
          );
        }

        return redirect(`/attempt-take?attempt_id=${attemptId}`);
      }

      // Unknown step — restart
      return redirect(`/attempt-start?exam_id=${examId}`);
    }

    // =====================================================
    // GET /attempt-take
    // =====================================================
    if (path === "/attempt-take" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const attemptId = url.searchParams.get("attempt_id") || "";
      if (!attemptId) return redirect("/student");

      const attempt = await first(
        `SELECT * FROM exam_attempts WHERE id=? AND user_id=? AND tenant_id=?`,
        [attemptId, r.user.id, active.tenant_id]
      );
      if (!attempt) return redirect("/student");
      if (attempt.status !== "IN_PROGRESS") return redirect(`/attempt-complete?attempt_id=${attemptId}`);

      const exam = await first(`SELECT * FROM exams WHERE id=? AND tenant_id=?`, [attempt.exam_id, active.tenant_id]);
      if (!exam) return redirect("/student");

      const now = Date.now();

      // HARD_CUT check
      if (exam.ends_at && now > Date.parse(exam.ends_at)) {
        await doAutoSubmit(attemptId, active.tenant_id);
        return redirect(`/attempt-complete?attempt_id=${attemptId}`);
      }

      // Timer expiry check
      const deadlineMs = Date.parse(attempt.started_at) + attempt.effective_duration_secs * 1000;
      if (now >= deadlineMs) {
        await doAutoSubmit(attemptId, active.tenant_id);
        return redirect(`/attempt-complete?attempt_id=${attemptId}`);
      }

      const timeRemainingSecs = Math.ceil((deadlineMs - now) / 1000);

      // Load questions in snapshot order
      const questionOrder = JSON.parse(attempt.question_order_json || "[]");
      const allQs = await all(
        `SELECT * FROM exam_questions WHERE exam_id=? AND tenant_id=?`,
        [attempt.exam_id, active.tenant_id]
      );
      const qMap = {};
      for (const q of allQs) qMap[q.id] = q;
      const questions = questionOrder.map((id) => qMap[id]).filter(Boolean);

      if (questions.length === 0) return page(errCard("No questions found for this exam."));

      // Load options for all questions
      const allOpts = await all(
        `SELECT * FROM exam_question_options WHERE question_id IN (${questions.map(() => "?").join(",")}) ORDER BY sort_order ASC`,
        questions.map((q) => q.id)
      );
      const optsByQ = {};
      for (const o of allOpts) {
        if (!optsByQ[o.question_id]) optsByQ[o.question_id] = [];
        optsByQ[o.question_id].push(o);
      }

      // Load existing answers
      const savedAnswers = await all(`SELECT * FROM exam_answers WHERE attempt_id=?`, [attemptId]);
      const ansMap = {};
      for (const a of savedAnswers) ansMap[a.question_id] = a;

      const navMode = (exam.navigation_mode || "FREE").toUpperCase();
      const isSequential = navMode !== "FREE";
      const totalQ = questions.length;
      const currentQIdx = isSequential
        ? Math.max(0, Math.min(parseInt(url.searchParams.get("q") || "0", 10), totalQ - 1))
        : 0;

      // Warning banner: effective duration shorter than full
      const fullDurationSecs = (exam.duration_mins || 60) * 60;
      const showWarning = attempt.effective_duration_secs < fullDurationSecs;
      const warningMins = Math.ceil(attempt.effective_duration_secs / 60);

      // Initial answer/flag state arrays (used by inline JS)
      const initialAnswered = questions.map((q) => {
        const a = ansMap[q.id];
        if (!a || a.answer_json === null || a.answer_json === undefined) return false;
        try {
          const p = JSON.parse(a.answer_json);
          if (p === null || p === undefined) return false;
          if (typeof p === "string") return p.trim() !== "";
          if (Array.isArray(p)) return p.length > 0;
          return true;
        } catch(e) { return false; }
      });
      const initialFlagged = questions.map((q) => {
        const a = ansMap[q.id];
        return a ? Number(a.is_flagged) === 1 : false;
      });

      // Build individual question card HTML
      // showFlagBtn: true for FREE mode, false for SEQUENTIAL
      function buildQuestion(q, idx, savedAns, showFlagBtn) {
        const opts = optsByQ[q.id] || [];
        const isFlagged = savedAns ? Number(savedAns.is_flagged) : 0;
        let parsed = null;
        try { if (savedAns && savedAns.answer_json) parsed = JSON.parse(savedAns.answer_json); } catch (e) {}

        let inputHtml = "";
        if (q.question_type === "MCQ" || q.question_type === "TRUE_FALSE") {
          inputHtml = opts.map((o) => {
            const checked = parsed === o.id ? "checked" : "";
            return `<label style="display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid rgba(0,0,0,.1);border-radius:8px;cursor:pointer;margin-bottom:6px">
              <input type="radio" name="ans[${escapeAttr(q.id)}]" value="${escapeAttr(o.id)}" ${checked} style="width:auto;flex-shrink:0;transform:scale(1.2)" />
              <span style="font-size:14px">${escapeHtml(o.option_text)}</span>
            </label>`;
          }).join("");
        } else if (q.question_type === "MULTIPLE_SELECT") {
          const sel = Array.isArray(parsed) ? parsed : [];
          inputHtml = opts.map((o) => {
            const checked = sel.includes(o.id) ? "checked" : "";
            return `<label style="display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid rgba(0,0,0,.1);border-radius:8px;cursor:pointer;margin-bottom:6px">
              <input type="checkbox" name="ans_multi[${escapeAttr(q.id)}][]" value="${escapeAttr(o.id)}" ${checked} style="width:auto;flex-shrink:0;transform:scale(1.2)" />
              <span style="font-size:14px">${escapeHtml(o.option_text)}</span>
            </label>`;
          }).join("");
          inputHtml += `<p class="muted" style="font-size:12px;margin:4px 0">Select all that apply.</p>`;
        } else if (q.question_type === "SHORT_ANSWER") {
          const val = typeof parsed === "string" ? parsed : "";
          inputHtml = `<textarea name="ans[${escapeAttr(q.id)}]" rows="3" placeholder="Type your answer here..." style="font-size:14px">${escapeHtml(val)}</textarea>`;
        } else if (q.question_type === "ESSAY") {
          const val = typeof parsed === "string" ? parsed : "";
          inputHtml = `<textarea name="ans[${escapeAttr(q.id)}]" rows="9" placeholder="Type your essay answer here..." style="font-size:14px">${escapeHtml(val)}</textarea>`;
        }

        const marksHtml = Number(exam.show_marks_during)
          ? `<span class="muted" style="font-size:12px">${escapeHtml(String(q.marks))} mark${Number(q.marks) !== 1 ? "s" : ""}</span>`
          : "";

        const flagHtml = showFlagBtn ? `
          <input type="hidden" name="flag[${escapeAttr(q.id)}]" id="flag-${escapeAttr(q.id)}" value="${isFlagged ? "1" : "0"}" />
          <button type="button" class="flag-btn" data-qid="${escapeAttr(q.id)}" onclick="toggleFlag(this)"
            style="background:${isFlagged ? "#fff3cd" : "rgba(0,0,0,.06)"};border:1px solid ${isFlagged ? "#ffc107" : "rgba(0,0,0,.12)"};border-radius:8px;padding:5px 10px;cursor:pointer;font-size:12px;font-weight:700">
            ${isFlagged ? "🚩 Flagged" : "🏳 Flag"}
          </button>
        ` : "";

        // FREE: show only first card initially; SEQUENTIAL: show only currentQIdx
        const hidden = isSequential ? (idx !== currentQIdx) : (idx !== 0);
        return `
          <div class="card question-card" data-idx="${idx}" data-qid="${escapeAttr(q.id)}"
               style="${hidden ? "display:none" : ""}">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:10px">
              <div style="font-weight:700;font-size:13px;color:rgba(0,0,0,.45);letter-spacing:.02em">
                QUESTION ${idx + 1} <span style="font-weight:400">of ${totalQ}</span>
              </div>
              <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                ${marksHtml}
                ${flagHtml}
              </div>
            </div>
            <div style="font-size:15px;margin-bottom:16px;line-height:1.6">${escapeHtml(q.question_text)}</div>
            ${inputHtml}
          </div>
        `;
      }

      const questionsHtml = questions.map((q, i) => buildQuestion(q, i, ansMap[q.id], !isSequential)).join("");

      // SEQUENTIAL: forward-only nav; Next becomes Submit on last question
      const seqNavHtml = isSequential ? `
        <div style="display:flex;gap:10px;justify-content:flex-end;align-items:center;margin-top:8px">
          <div id="btn-next-wrap">
            ${currentQIdx === totalQ - 1
              ? `<button type="submit" name="action" value="submit" onclick="return confirmSubmit()" class="btn2" style="padding:10px 20px">Submit Exam</button>`
              : `<button type="button" id="btn-next" onclick="navTo(currentQ+1)" class="btn2">Next &#x2192;</button>`
            }
          </div>
        </div>
      ` : "";

      // FREE: two-column desktop layout + sticky sidebar grid + mobile drawer
      const freeMainHtml = !isSequential ? `
        <div class="exam-layout">
          <div class="exam-main">
            ${questionsHtml}
            <div style="display:flex;gap:10px;justify-content:space-between;align-items:center;margin-top:8px">
              <button type="button" id="btn-prev" onclick="freeNav(-1)" class="btn3"
                style="opacity:.35;cursor:not-allowed" disabled>&#x2190; Previous</button>
              <div id="free-btn-next-wrap">
                <button type="button" id="btn-next" onclick="freeNav(1)" class="btn2">Next &#x2192;</button>
              </div>
            </div>
            <div style="margin-top:16px;text-align:right">
              <button type="submit" name="action" value="submit" onclick="return confirmSubmit()"
                class="btn2" style="padding:12px 24px;font-size:15px">Submit Exam</button>
            </div>
          </div>
          <div class="exam-sidebar">
            <div class="card" style="padding:14px">
              <div style="font-weight:700;font-size:13px;margin-bottom:10px">Questions</div>
              <div style="display:flex;gap:4px;margin-bottom:10px">
                <button type="button" class="grid-view-btn active" data-view="all" onclick="setView('all')">All</button>
                <button type="button" class="grid-view-btn" data-view="flagged" onclick="setView('flagged')">&#x1F6A9; Flagged</button>
                <button type="button" class="grid-view-btn" data-view="unanswered" onclick="setView('unanswered')">&#x25A1; Unanswered</button>
              </div>
              <div id="grid-banner" style="display:none;font-size:12px;color:rgba(0,0,0,.55);background:#f6f8f7;border-radius:8px;padding:6px 10px;margin-bottom:8px"></div>
              <div id="question-grid" class="question-grid"></div>
            </div>
          </div>
        </div>
        <button type="button" id="mobile-grid-btn" onclick="openDrawer()">
          &#x1F4CB; Questions <span id="mobile-flag-badge" style="display:none"></span>
        </button>
        <div id="drawer-overlay" onclick="closeDrawer()"
          style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000"></div>
        <div id="mobile-drawer"
          style="display:none;position:fixed;bottom:0;left:0;right:0;background:#fff;border-radius:16px 16px 0 0;padding:16px;z-index:1001;max-height:70vh;overflow-y:auto">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <div style="font-weight:700;font-size:14px">Questions</div>
            <button type="button" onclick="closeDrawer()"
              style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;color:rgba(0,0,0,.5)">&#x2715;</button>
          </div>
          <div style="display:flex;gap:4px;margin-bottom:10px">
            <button type="button" class="grid-view-btn active" data-view="all" onclick="setView('all')">All</button>
            <button type="button" class="grid-view-btn" data-view="flagged" onclick="setView('flagged')">&#x1F6A9; Flagged</button>
            <button type="button" class="grid-view-btn" data-view="unanswered" onclick="setView('unanswered')">&#x25A1; Unanswered</button>
          </div>
          <div id="mob-grid-banner" style="display:none;font-size:12px;color:rgba(0,0,0,.55);background:#f6f8f7;border-radius:8px;padding:6px 10px;margin-bottom:8px"></div>
          <div id="mob-question-grid" class="question-grid"></div>
        </div>
      ` : "";

      return page(`
        <style>
          .q-topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
          .timer-box{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums;color:#0b7a75;letter-spacing:-.01em}
          .timer-box.warn{color:#c67000}
          .timer-box.danger{color:#c00}
          .warn-banner{background:#fff8e1;border:1px solid #ffe082;border-radius:10px;padding:10px 14px;margin-bottom:12px;font-size:13px}
          .save-toast{position:fixed;bottom:20px;right:20px;padding:8px 14px;border-radius:10px;font-size:13px;font-weight:700;display:none;z-index:9999}
          .save-ok{background:#d4f5e9;color:#0b7a75;border:1px solid rgba(11,122,117,.2)}
          .save-err{background:#fff3f3;color:#c00;border:1px solid rgba(255,0,0,.2)}
          .exam-layout{display:grid;grid-template-columns:1fr 220px;gap:16px;align-items:start}
          .exam-sidebar{position:sticky;top:16px}
          .question-grid{display:flex;flex-wrap:wrap;gap:6px}
          .grid-sq{width:36px;height:36px;border-radius:8px;border:2px solid transparent;font-size:13px;font-weight:700;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;background:#eaeef0;color:#1f2a28}
          .grid-sq.sq-answered{background:#d4f5e9;color:#0b7a75}
          .grid-sq.sq-flagged{background:#fff3cd;color:#c67000}
          .grid-sq.sq-current{border-color:#0b7a75 !important}
          .grid-view-btn{background:#eaeef0;color:#1f2a28;border:1px solid rgba(0,0,0,.1);border-radius:8px;padding:5px 8px;font-size:11px;font-weight:700;cursor:pointer;flex:1}
          .grid-view-btn.active{background:#0b7a75;color:#fff;border-color:#0b7a75}
          #mobile-grid-btn{position:fixed;bottom:20px;right:20px;background:#0b7a75;color:#fff;border:none;border-radius:24px;padding:10px 16px;font-size:14px;font-weight:700;cursor:pointer;z-index:990;display:none;align-items:center;gap:6px;box-shadow:0 4px 12px rgba(0,0,0,.2)}
          @media(max-width:768px){
            .exam-layout{grid-template-columns:1fr}
            .exam-sidebar{display:none}
            #mobile-grid-btn{display:flex !important}
          }
        </style>

        <form id="exam-form" method="post" action="/attempt-take">
          <input type="hidden" name="attempt_id" value="${escapeAttr(attemptId)}" />
          <input type="hidden" name="auto" id="auto-field" value="0" />
          ${isSequential ? `<input type="hidden" name="current_q" id="seq-q" value="${currentQIdx}" />` : ""}

          <div class="card q-topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/student">&#x2190; My Exams</a></div>
              <h1 style="margin:0;font-size:17px">${escapeHtml(exam.title)}</h1>
            </div>
            <div id="exam-timer" class="timer-box">${fmtSecs(timeRemainingSecs)}</div>
          </div>

          ${showWarning ? `<div class="warn-banner"><b>Note:</b> This exam closes soon. You have <b>${warningMins} minute${warningMins !== 1 ? "s" : ""}</b> available, not the full ${exam.duration_mins} minutes.</div>` : ""}

          ${isSequential ? questionsHtml + seqNavHtml : freeMainHtml}
        </form>

        <div id="save-toast" class="save-toast save-ok">Saved &#x2713;</div>

        <script>
          // JS_PLACEHOLDER
        </script>
      `);
    }

    // =====================================================
    // POST /attempt-take
    // =====================================================
    if (path === "/attempt-take" && request.method === "POST") {
      const jsonRes = (body, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

      const r = await requireLogin();
      if (!r.ok) return jsonRes({ ok: false, error: "Not logged in" }, 401);
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return jsonRes({ ok: false, error: "Forbidden" }, 403);

      const f = await form();
      const attemptId = (f.attempt_id || "").trim();
      const action = (f.action || "save").trim();

      if (!attemptId) return jsonRes({ ok: false, error: "Missing attempt_id" }, 400);

      const attempt = await first(
        `SELECT * FROM exam_attempts WHERE id=? AND user_id=? AND tenant_id=?`,
        [attemptId, r.user.id, active.tenant_id]
      );
      if (!attempt) return jsonRes({ ok: false, error: "Not found" }, 404);

      if (attempt.status !== "IN_PROGRESS") {
        if (action === "save") return jsonRes({ ok: false, error: "Attempt not in progress" });
        return redirect(`/attempt-complete?attempt_id=${attemptId}`);
      }

      // HARD_CUT check
      const exam = await first(`SELECT ends_at FROM exams WHERE id=?`, [attempt.exam_id]);
      if (exam && exam.ends_at && Date.now() > Date.parse(exam.ends_at)) {
        await doAutoSubmit(attemptId, active.tenant_id);
        if (action === "save") return jsonRes({ ok: true, submitted: true });
        return redirect(`/attempt-complete?attempt_id=${attemptId}`);
      }

      const questionOrder = JSON.parse(attempt.question_order_json || "[]");
      const ts = nowISO();

      // Parse submitted answers and flags from form data
      const updates = {}; // qid -> { answer_json, is_flagged }
      for (const key of Object.keys(f)) {
        // ans[qid] — single value (MCQ, TRUE_FALSE, SHORT_ANSWER, ESSAY)
        const m1 = key.match(/^ans\[(.+)\]$/);
        if (m1) {
          const qid = m1[1];
          if (!updates[qid]) updates[qid] = { answer_json: null, is_flagged: 0 };
          const val = f[key];
          updates[qid].answer_json = (val !== "" && val !== null && val !== undefined) ? JSON.stringify(val) : null;
          continue;
        }
        // ans_multi[qid][] — multiple values (MULTIPLE_SELECT)
        const m2 = key.match(/^ans_multi\[(.+)\]\[\]$/);
        if (m2) {
          const qid = m2[1];
          if (!updates[qid]) updates[qid] = { answer_json: null, is_flagged: 0 };
          const vals = Array.isArray(f[key]) ? f[key] : [f[key]];
          const filtered = vals.filter(Boolean);
          updates[qid].answer_json = filtered.length > 0 ? JSON.stringify(filtered) : null;
          continue;
        }
        // flag[qid]
        const m3 = key.match(/^flag\[(.+)\]$/);
        if (m3) {
          const qid = m3[1];
          if (!updates[qid]) updates[qid] = { answer_json: null, is_flagged: 0 };
          updates[qid].is_flagged = f[key] === "1" ? 1 : 0;
        }
      }

      // Upsert answers for all questions in this attempt
      for (const qid of questionOrder) {
        const upd = updates[qid];
        if (upd !== undefined) {
          await run(
            `UPDATE exam_answers SET answer_json=?, is_flagged=?, updated_at=? WHERE attempt_id=? AND question_id=?`,
            [upd.answer_json, upd.is_flagged, ts, attemptId, qid]
          );
        }
      }

      if (action === "save") {
        await run(`UPDATE exam_attempts SET updated_at=? WHERE id=?`, [ts, attemptId]);
        return jsonRes({ ok: true });
      }

      if (action === "submit") {
        const submittedAt = ts;
        const timeTakenSecs = Math.round((Date.parse(submittedAt) - Date.parse(attempt.started_at)) / 1000);
        const isAutoSubmit = f.auto === "1" ? 1 : 0;
        const fullExam = await first(`SELECT ends_at FROM exams WHERE id=?`, [attempt.exam_id]);
        const isLate = fullExam && fullExam.ends_at && Date.parse(submittedAt) > Date.parse(fullExam.ends_at) ? 1 : 0;
        await run(
          `UPDATE exam_attempts SET status='SUBMITTED', submitted_at=?, time_taken_secs=?, auto_submitted=?, is_late=?, updated_at=? WHERE id=?`,
          [submittedAt, timeTakenSecs, isAutoSubmit, isLate, ts, attemptId]
        );
        return redirect(`/attempt-complete?attempt_id=${attemptId}`);
      }

      return redirect(`/attempt-take?attempt_id=${attemptId}`);
    }

    // =====================================================
    // GET /attempt-complete
    // =====================================================
    if (path === "/attempt-complete") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "STUDENT") return redirect("/student");

      const attemptId = url.searchParams.get("attempt_id") || "";
      if (!attemptId) return redirect("/student");

      const attempt = await first(
        `SELECT * FROM exam_attempts WHERE id=? AND user_id=? AND tenant_id=?`,
        [attemptId, r.user.id, active.tenant_id]
      );
      if (!attempt) return redirect("/student");
      if (attempt.status === "IN_PROGRESS") return redirect(`/attempt-take?attempt_id=${attemptId}`);
      if (attempt.status !== "SUBMITTED") return redirect("/student");

      const exam = await first(
        `SELECT title, results_release_policy, results_published_at FROM exams WHERE id=? AND tenant_id=?`,
        [attempt.exam_id, active.tenant_id]
      );
      if (!exam) return redirect("/student");

      const resultsReleased = exam.results_published_at && Date.parse(exam.results_published_at) <= Date.now();

      return page(`
        <div class="card" style="text-align:center;padding:36px 24px">
          <div style="font-size:52px;margin-bottom:12px">&#x2705;</div>
          <h1 style="margin:0 0 8px">Exam submitted successfully</h1>
          <div style="color:rgba(0,0,0,.55);font-size:15px;margin-bottom:20px">${escapeHtml(exam.title)}</div>
          <div style="font-size:14px;color:rgba(0,0,0,.5)">
            Time taken: <b style="color:#1f2a28">${fmtTimeTaken(attempt.time_taken_secs)}</b>
          </div>
        </div>
        <div class="card">
          ${resultsReleased
            ? `<p style="margin:0 0 12px;font-size:15px">Your results are available.</p>
               <button class="btn2" disabled style="opacity:.45;cursor:not-allowed">View Results</button>`
            : `<p style="margin:0;font-size:15px;color:rgba(0,0,0,.55)">Your results will be released by your teacher.</p>`
          }
        </div>
        <div style="margin-top:16px">
          <a href="/student" class="btn3" style="display:inline-block;padding:10px 16px;text-decoration:none">&#x2190; Back to My Exams</a>
        </div>
      `);
    }

  } catch (err) {
    console.error("FATAL [attempts]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (attempts):\n\n" + msg, { status: 500 });
  }
}
