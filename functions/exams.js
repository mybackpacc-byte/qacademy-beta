// functions/exams.js
// All exam builder routes
// Includes: settings, questions, bank picker, add-from-bank

import { createHelpers, recalcAttempt } from "./shared.js";

export async function handleExamRequest(ctx) {
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
    // Helper: verify exam ownership
    // =============================
    async function verifyExamAccess(examId, tenantId, userId, role) {
      const exam = await first(`SELECT * FROM exams WHERE id=? AND tenant_id=?`, [examId, tenantId]);
      if (!exam) return null;
      if (role === "TEACHER") {
        const owns = await first(
          `SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1`,
          [exam.course_id, userId]
        );
        if (!owns) return null;
      }
      return exam;
    }

    // =============================
    // Helper: save question options
    // =============================
    async function saveQuestionOptions(qId, qType, f, ts) {
      if (qType === "TRUE_FALSE") {
        const correct = (f.tf_correct || "").trim();
        await run(
          `INSERT INTO exam_question_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), qId, "True", correct === "True" ? 1 : 0, null, 1, ts]
        );
        await run(
          `INSERT INTO exam_question_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), qId, "False", correct === "False" ? 1 : 0, null, 2, ts]
        );
        return;
      }
      if (qType === "MCQ" || qType === "MULTIPLE_SELECT") {
        const texts = [].concat(f["opt_text[]"] || []);
        const feedbacks = [].concat(f["opt_feedback[]"] || []);
        const correctRaw = f["opt_correct[]"];
        const correctIndices = new Set([].concat(correctRaw || []).map((v) => String(v)));
        for (let i = 0; i < texts.length; i++) {
          const text = (texts[i] || "").trim();
          if (!text) continue;
          const isCorrect = correctIndices.has(String(i)) ? 1 : 0;
          const optFeedback = (feedbacks[i] || "").trim() || null;
          await run(
            `INSERT INTO exam_question_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), qId, text, isCorrect, optFeedback, i + 1, ts]
          );
        }
      }
      // SHORT_ANSWER, ESSAY — no options
    }

    // =============================
    // Helper: save question to question bank
    // =============================
    async function saveToBank(bankId, tenantId, userId, qType, qText, marks, partialMarking, modelAnswer, feedback, f, ts) {
      // Upsert bank question
      const existing = bankId ? await first(`SELECT id FROM question_bank WHERE id=? AND tenant_id=?`, [bankId, tenantId]) : null;

      if (existing) {
        // Update existing bank question
        await run(
          `UPDATE question_bank SET question_type=?, question_text=?, marks=?, partial_marking=?, model_answer=?, feedback=?, updated_at=? WHERE id=?`,
          [qType, qText, marks, partialMarking, modelAnswer, feedback, ts, bankId]
        );
        // Rebuild options
        await run(`DELETE FROM question_bank_options WHERE bank_question_id=?`, [bankId]);
        await saveBankOptions(bankId, qType, f, ts);
        return bankId;
      } else {
        // Insert new bank question
        const newBankId = uuid();
        await run(
          `INSERT INTO question_bank (id,tenant_id,created_by,question_type,question_text,marks,partial_marking,model_answer,feedback,visibility,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,'PERSONAL',?,?)`,
          [newBankId, tenantId, userId, qType, qText, marks, partialMarking, modelAnswer, feedback, ts, ts]
        );
        await saveBankOptions(newBankId, qType, f, ts);
        return newBankId;
      }
    }

    async function saveBankOptions(bankQId, qType, f, ts) {
      if (qType === "TRUE_FALSE") {
        const correct = (f.tf_correct || "").trim();
        await run(
          `INSERT INTO question_bank_options (id,bank_question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), bankQId, "True", correct === "True" ? 1 : 0, null, 1, ts]
        );
        await run(
          `INSERT INTO question_bank_options (id,bank_question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), bankQId, "False", correct === "False" ? 1 : 0, null, 2, ts]
        );
        return;
      }
      if (qType === "MCQ" || qType === "MULTIPLE_SELECT") {
        const texts = [].concat(f["opt_text[]"] || []);
        const feedbacks = [].concat(f["opt_feedback[]"] || []);
        const correctRaw = f["opt_correct[]"];
        const correctIndices = new Set([].concat(correctRaw || []).map((v) => String(v)));
        for (let i = 0; i < texts.length; i++) {
          const text = (texts[i] || "").trim();
          if (!text) continue;
          const isCorrect = correctIndices.has(String(i)) ? 1 : 0;
          const optFeedback = (feedbacks[i] || "").trim() || null;
          await run(
            `INSERT INTO question_bank_options (id,bank_question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), bankQId, text, isCorrect, optFeedback, i + 1, ts]
          );
        }
      }
    }

    // =============================
    // Helper: gate status
    // Returns APPROVED | REJECTED | PENDING | NOT_CONFIGURED
    // =============================
    async function getGateStatus(examId, gateType, tenantId) {
      const assignees = await all(
        `SELECT user_id FROM sitting_approval_gates WHERE exam_id=? AND gate_type=? AND tenant_id=?`,
        [examId, gateType, tenantId]
      );
      if (assignees.length === 0) return "NOT_CONFIGURED";

      const responses = await all(
        `SELECT approver_id, status FROM sitting_approval_responses
         WHERE exam_id=? AND gate_type=? AND tenant_id=?`,
        [examId, gateType, tenantId]
      );
      const responseMap = {};
      for (const r of responses) responseMap[r.approver_id] = r.status;

      let anyRejected = false;
      let allApproved = true;
      for (const a of assignees) {
        const s = responseMap[a.user_id] || "PENDING";
        if (s === "REJECTED") anyRejected = true;
        if (s !== "APPROVED") allApproved = false;
      }
      if (anyRejected) return "REJECTED";
      if (allApproved) return "APPROVED";
      return "PENDING";
    }

    // =============================
    // Shared UI helpers
    // =============================
    const qTypeLabel = (t) => {
      if (t === "MCQ") return "MCQ";
      if (t === "MULTIPLE_SELECT") return "Multi-select";
      if (t === "TRUE_FALSE") return "True / False";
      if (t === "SHORT_ANSWER") return "Short Answer";
      if (t === "ESSAY") return "Essay";
      return t;
    };

    // =============================
    // Exam: create (POST)
    // =============================
    if (path === "/exam-create" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "").trim();
      const title = (f.title || "").trim();
      if (!courseId || !title) return redirect("/teacher");

      const c = await first(
        `SELECT c.id FROM courses c
         JOIN course_teachers ct ON ct.course_id = c.id
         WHERE c.id=? AND c.tenant_id=? AND ct.user_id=? AND c.status='ACTIVE'`,
        [courseId, active.tenant_id, r.user.id]
      );
      if (!c) return redirect("/teacher");

      const examId = uuid();
      const ts = nowISO();
      await run(
        `INSERT INTO exams (id,tenant_id,course_id,created_by,title,status,created_at,updated_at)
         VALUES (?,?,?,?,?,'DRAFT',?,?)`,
        [examId, active.tenant_id, courseId, r.user.id, title, ts, ts]
      );
      return redirect(`/exam-builder?exam_id=${examId}`);
    }

    // =============================
    // POST /exam-gate-submit — teacher submits a gate for approval
    // =============================
    if (path === "/exam-gate-submit" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "TEACHER") return redirect("/");

      const f = await form();
      const examId   = (f.exam_id   || "").trim();
      const gateType = (f.gate_type || "").trim();

      if (!examId || !["QUESTIONS","GRADING","RESULTS"].includes(gateType)) {
        return redirect("/teacher");
      }

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      // Validate submission rules
      if (gateType === "GRADING") {
        // All submitted attempts must be FULLY_GRADED
        const ungraded = await first(
          `SELECT COUNT(*) AS cnt FROM exam_attempts
           WHERE exam_id=? AND tenant_id=? AND status='SUBMITTED' AND grading_status != 'FULLY_GRADED'`,
          [examId, active.tenant_id]
        );
        if (ungraded && Number(ungraded.cnt) > 0) {
          return redirect(`/exam-builder?exam_id=${examId}&pane=approvals&gate_error=grading_not_complete`);
        }
      }

      if (gateType === "RESULTS") {
        // GRADING gate must be APPROVED (or NOT_CONFIGURED)
        const gradingStatus = await getGateStatus(examId, "GRADING", active.tenant_id);
        if (gradingStatus !== "APPROVED" && gradingStatus !== "NOT_CONFIGURED") {
          return redirect(`/exam-builder?exam_id=${examId}&pane=approvals&gate_error=grading_gate_required`);
        }
      }

      // Get all assigned approvers for this gate
      const assignees = await all(
        `SELECT user_id FROM sitting_approval_gates WHERE exam_id=? AND gate_type=? AND tenant_id=?`,
        [examId, gateType, active.tenant_id]
      );
      if (assignees.length === 0) {
        return redirect(`/exam-builder?exam_id=${examId}&pane=approvals`);
      }

      const ts = nowISO();
      // Delete any existing responses (resubmission after rejection)
      await run(
        `DELETE FROM sitting_approval_responses WHERE exam_id=? AND gate_type=? AND tenant_id=?`,
        [examId, gateType, active.tenant_id]
      );
      // Insert fresh PENDING responses for all assignees
      for (const a of assignees) {
        await run(
          `INSERT INTO sitting_approval_responses (id, exam_id, gate_type, approver_id, status, tenant_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?)`,
          [uuid(), examId, gateType, a.user_id, active.tenant_id, ts, ts]
        );
      }

      return redirect(`/exam-builder?exam_id=${examId}&pane=approvals`);
    }

    // =============================
    // Exam Builder — main page
    // =============================
    if (path === "/exam-builder") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const examId = url.searchParams.get("exam_id") || "";
      if (!examId) return redirect("/teacher");

      const exam = await first(`SELECT * FROM exams WHERE id=? AND tenant_id=?`, [examId, active.tenant_id]);
      if (!exam) return redirect("/teacher");

      if (active.role === "TEACHER") {
        const owns = await first(
          `SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1`,
          [exam.course_id, r.user.id]
        );
        if (!owns) return redirect("/teacher");
      }

      // Load questions + options
      const questions = await all(
        `SELECT id, question_type, question_text, marks, sort_order, partial_marking, model_answer, feedback, bank_question_id
         FROM exam_questions WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );

      const allOptions = questions.length > 0 ? await all(
        `SELECT id, question_id, option_text, is_correct, feedback, sort_order
         FROM exam_question_options
         WHERE question_id IN (${questions.map(() => "?").join(",")})
         ORDER BY sort_order ASC`,
        questions.map((q) => q.id)
      ) : [];

      const optionsByQuestion = {};
      for (const o of allOptions) {
        if (!optionsByQuestion[o.question_id]) optionsByQuestion[o.question_id] = [];
        optionsByQuestion[o.question_id].push(o);
      }

      const totalMarks = questions.reduce((sum, q) => sum + Number(q.marks || 0), 0);
      const locked = exam.status === "PUBLISHED" || exam.status === "CLOSED";

      // Build question list rows
      const questionRows = questions.map((q, i) => {
        const opts = optionsByQuestion[q.id] || [];
        const preview = opts.length > 0
          ? opts.map((o) => `<span style="display:inline-block;padding:2px 8px;border-radius:6px;margin:2px;font-size:11px;background:${Number(o.is_correct) ? "rgba(11,122,117,.12);color:#0b7a75" : "rgba(0,0,0,.06);color:#555"}">${escapeHtml(o.option_text)}</span>`).join("")
          : q.model_answer ? `<span class="muted small">Model answer set</span>` : "";

        return `
          <div class="q-row card" style="margin:4px 0;padding:12px" data-id="${escapeAttr(q.id)}">
            <div style="display:flex;gap:10px;align-items:flex-start">
              <div style="min-width:28px;text-align:center;padding-top:2px">
                <div style="font-weight:700;font-size:15px;color:#0b7a75">${i + 1}</div>
                <div class="muted small">${escapeHtml(String(q.marks))}m</div>
              </div>
              <div style="flex:1;min-width:0">
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px">
                  <span class="pill" style="font-size:11px">${escapeHtml(qTypeLabel(q.question_type))}</span>
                  ${q.question_type === "MULTIPLE_SELECT" ? `<span class="muted small">${Number(q.partial_marking) ? "Partial marks" : "All-or-nothing"}</span>` : ""}
                  ${q.bank_question_id ? `<span class="pill" style="font-size:10px;background:rgba(0,100,200,.08);color:#0055cc">📚 From bank</span>` : ""}
                </div>
                <div style="font-size:14px;margin-bottom:6px">${escapeHtml(q.question_text)}</div>
                <div>${preview}</div>
              </div>
              ${locked ? "" : `
              <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end">
                <div style="display:flex;gap:4px">
                  <form method="post" action="/exam-reorder-question" style="display:inline">
                    <input type="hidden" name="exam_id" value="${escapeAttr(examId)}"/>
                    <input type="hidden" name="question_id" value="${escapeAttr(q.id)}"/>
                    <input type="hidden" name="direction" value="up"/>
                    <button class="btn3" type="submit" style="padding:4px 8px" ${i === 0 ? "disabled" : ""}>↑</button>
                  </form>
                  <form method="post" action="/exam-reorder-question" style="display:inline">
                    <input type="hidden" name="exam_id" value="${escapeAttr(examId)}"/>
                    <input type="hidden" name="question_id" value="${escapeAttr(q.id)}"/>
                    <input type="hidden" name="direction" value="down"/>
                    <button class="btn3" type="submit" style="padding:4px 8px" ${i === questions.length - 1 ? "disabled" : ""}>↓</button>
                  </form>
                </div>
                <a href="/exam-builder?exam_id=${escapeAttr(examId)}&edit_q=${escapeAttr(q.id)}&pane=questions" class="btn3" style="font-size:12px;padding:4px 10px;border-radius:8px;display:inline-block">Edit</a>
                <form method="post" action="/exam-delete-question" onsubmit="return confirm('Delete this question?')" style="display:inline">
                  <input type="hidden" name="exam_id" value="${escapeAttr(examId)}"/>
                  <input type="hidden" name="question_id" value="${escapeAttr(q.id)}"/>
                  <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px;color:#c00">Delete</button>
                </form>
              </div>
              `}
            </div>
          </div>
        `;
      }).join("");

      // Editing existing question?
      const editQId = url.searchParams.get("edit_q") || "";
      const editQ = editQId ? questions.find((q) => q.id === editQId) : null;
      const editOpts = editQ ? (optionsByQuestion[editQ.id] || []) : [];
      const formType = editQ ? editQ.question_type : "MCQ";

      // Build option rows for the form
      const buildOptionRow = (isMulti, text, isCorrect, feedback, idx) => `
        <div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
          <div style="display:flex;gap:8px;align-items:center">
            <input type="${isMulti ? "checkbox" : "radio"}" name="opt_correct[]" value="${idx}" ${isCorrect ? "checked" : ""} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
            <input name="opt_text[]" value="${escapeAttr(text)}" placeholder="Option text" style="flex:1" />
            <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px;flex-shrink:0">✕</button>
          </div>
          <div style="margin-top:6px">
            <input name="opt_feedback[]" value="${escapeAttr(feedback)}" placeholder="Feedback for this option (optional)" style="font-size:12px" />
          </div>
        </div>
      `;

      const buildOptionRows = (type, opts) => {
        if (type === "TRUE_FALSE") {
          const trueCorrect = opts.find((o) => o.option_text === "True" && Number(o.is_correct));
          const falseCorrect = opts.find((o) => o.option_text === "False" && Number(o.is_correct));
          return `
            <div class="section-title" style="margin-top:14px">Correct answer</div>
            <select name="tf_correct" required style="max-width:200px">
              <option value="">— select —</option>
              <option value="True" ${trueCorrect ? "selected" : ""}>True</option>
              <option value="False" ${falseCorrect ? "selected" : ""}>False</option>
            </select>
          `;
        }
        if (type === "MCQ" || type === "MULTIPLE_SELECT") {
          const isMulti = type === "MULTIPLE_SELECT";
          const rows = opts.length > 0
            ? opts.map((o, i) => buildOptionRow(isMulti, o.option_text, Number(o.is_correct), o.feedback || "", i)).join("")
            : [0, 1, 2, 3].map((i) => buildOptionRow(isMulti, "", false, "", i)).join("");
          return `
            <div class="section-title" style="margin-top:14px">Answer options <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(tick the correct answer${isMulti ? "s" : ""})</span></div>
            <div id="options-container">${rows}</div>
            <button type="button" class="btn3" onclick="addOptionRow(${isMulti ? "true" : "false"})" style="margin-top:4px;font-size:12px">+ Add option</button>
            ${isMulti ? `
              <div style="margin-top:12px">
                <label>Partial marking</label>
                <select name="partial_marking">
                  <option value="1" ${!editQ || Number(editQ.partial_marking) ? "selected" : ""}>Partial marks (proportional to correct options)</option>
                  <option value="0" ${editQ && !Number(editQ.partial_marking) ? "selected" : ""}>All or nothing (full marks only if all correct)</option>
                </select>
              </div>` : ""}
          `;
        }
        return "";
      };

      // Grade bands + custom fields
      const bands = await all(`SELECT id,label,min_percent FROM exam_grade_bands WHERE exam_id=? ORDER BY min_percent DESC`, [examId]);
      const customFields = await all(`SELECT id,field_label,field_type,field_options,is_required FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`, [examId]);

      // Check if this exam belongs to a sitting (for publish-pane locking)
      const sittingForExam = await first(
        `SELECT esp.sitting_id, es.title AS sitting_title
         FROM exam_sitting_papers esp
         JOIN exam_sittings es ON es.id = esp.sitting_id
         WHERE esp.exam_id=?`,
        [examId]
      );

      // ── Approval gates data ──
      const GATE_TYPES_ORDERED = ["QUESTIONS", "GRADING", "RESULTS"];
      const GATE_LABEL_MAP = { QUESTIONS: "📝 Questions", GRADING: "✏️ Grading", RESULTS: "📊 Results" };

      // All configured gates for this exam (any gate_type)
      const allGates = await all(
        `SELECT sag.gate_type, sag.user_id, u.name AS approver_name
         FROM sitting_approval_gates sag
         JOIN users u ON u.id = sag.user_id
         WHERE sag.exam_id=? AND sag.tenant_id=?
         ORDER BY sag.gate_type, u.name ASC`,
        [examId, active.tenant_id]
      );
      const configuredGateTypes = [...new Set(allGates.map(g => g.gate_type))];
      const hasAnyGate = configuredGateTypes.length > 0;

      // All responses for this exam
      const allResponses = await all(
        `SELECT approver_id, gate_type, status, note
         FROM sitting_approval_responses
         WHERE exam_id=? AND tenant_id=?`,
        [examId, active.tenant_id]
      );
      // responseMap[gateType][approver_id] = {status, note}
      const responseMap = {};
      for (const resp of allResponses) {
        if (!responseMap[resp.gate_type]) responseMap[resp.gate_type] = {};
        responseMap[resp.gate_type][resp.approver_id] = { status: resp.status, note: resp.note };
      }

      // Compute gate statuses (used for both pane rendering and publish enforcement)
      const gateStatuses = {};
      for (const gt of GATE_TYPES_ORDERED) {
        gateStatuses[gt] = await getGateStatus(examId, gt, active.tenant_id);
      }

      // Check whether grading gate is already submitted (has any responses)
      function isGateSubmitted(gateType) {
        const rt = responseMap[gateType] || {};
        return Object.keys(rt).length > 0;
      }

      // Can teacher submit GRADING gate? All submitted attempts must be FULLY_GRADED
      // (We'll check this lazily below when building the pane)

      const bandRows = bands.map((b) => `
        <div class="band-row" style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
          <input name="band_label[]" value="${escapeAttr(b.label)}" placeholder="e.g. Distinction" style="flex:2" />
          <input name="band_min[]" type="number" min="0" max="100" value="${escapeAttr(b.min_percent)}" placeholder="Min %" style="flex:1" />
          <button type="button" class="btn3" onclick="this.closest('.band-row').remove()">✕</button>
        </div>
      `).join("");

      const cfRows = customFields.map((cf) => `
        <div class="cf-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:8px">
          <div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap">
            <input name="cf_label[]" value="${escapeAttr(cf.field_label)}" placeholder="Field label e.g. Index Number" style="flex:2;min-width:160px" />
            <select name="cf_type[]" style="flex:1;min-width:120px" onchange="toggleCfOptions(this)">
              <option value="TEXT" ${cf.field_type === "TEXT" ? "selected" : ""}>Text</option>
              <option value="YESNO" ${cf.field_type === "YESNO" ? "selected" : ""}>Yes / No</option>
              <option value="DROPDOWN" ${cf.field_type === "DROPDOWN" ? "selected" : ""}>Dropdown</option>
            </select>
            <label style="display:flex;align-items:center;gap:4px;font-size:13px;margin:0">
              <input type="checkbox" name="cf_required[]" value="1" ${Number(cf.is_required) === 1 ? "checked" : ""} /> Required
            </label>
            <button type="button" class="btn3" onclick="this.closest('.cf-row').remove()">✕</button>
          </div>
          <div class="cf-options-wrap" style="margin-top:8px;${cf.field_type === "DROPDOWN" ? "" : "display:none"}">
            <input name="cf_options[]" value="${escapeAttr(cf.field_options || "")}" placeholder="Dropdown options, comma separated" style="width:100%" />
          </div>
        </div>
      `).join("");

      const v = (field) => escapeAttr(exam[field] ?? "");
      const chk = (field) => Number(exam[field]) === 1 ? "checked" : "";
      const sel = (field, val) => exam[field] === val ? "selected" : "";

      const activePane = url.searchParams.get("pane") || (editQId ? "questions" : "settings");

      // === Access pane data ===
      const accessList = await all(
        `SELECT ea.id, ea.user_id, u.name AS student_name, u.email AS student_email,
                GROUP_CONCAT(c.name, ', ') AS class_names
         FROM exam_access ea
         JOIN users u ON u.id = ea.user_id
         LEFT JOIN class_students cs ON cs.user_id = ea.user_id
         LEFT JOIN classes c ON c.id = cs.class_id AND c.tenant_id=?
         WHERE ea.exam_id=?
         GROUP BY ea.id
         ORDER BY u.name ASC`,
        [active.tenant_id, examId]
      );
      const tenantClasses = await all(
        `SELECT id, name, year_group FROM classes WHERE tenant_id=? AND status='ACTIVE' ORDER BY name ASC`,
        [active.tenant_id]
      );
      const enrolledStudents = await all(
        `SELECT u.id, u.name, u.email
         FROM users u
         JOIN enrollments e ON e.user_id=u.id AND e.course_id=?
         WHERE u.id NOT IN (SELECT user_id FROM exam_access WHERE exam_id=?)
         ORDER BY u.name ASC`,
        [exam.course_id, examId]
      );
      const allStudents = await all(
        `SELECT u.id, u.name, u.email
         FROM users u
         JOIN memberships m ON m.user_id=u.id AND m.tenant_id=? AND m.role='STUDENT' AND m.status='ACTIVE'
         WHERE u.id NOT IN (SELECT user_id FROM exam_access WHERE exam_id=?)
         ORDER BY u.name ASC`,
        [active.tenant_id, examId]
      );

      // Pre-built HTML fragments for access pane (avoids deep template nesting)
      const accessRows = accessList.map((s) => `
        <tr style="border-bottom:1px solid rgba(0,0,0,.05)">
          <td style="padding:7px 8px">${escapeHtml(s.student_name)}</td>
          <td style="padding:7px 8px;color:rgba(0,0,0,.55)">${escapeHtml(s.student_email)}</td>
          <td style="padding:7px 8px;color:rgba(0,0,0,.55)">${s.class_names ? escapeHtml(s.class_names) : '<span class="muted">—</span>'}</td>
          ${exam.status !== "CLOSED" ? `<td style="padding:7px 8px">
            <form method="post" action="/exam-access-remove" style="margin:0">
              <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
              <input type="hidden" name="access_id" value="${escapeAttr(s.id)}" />
              <button type="submit" class="btn3">Remove</button>
            </form>
          </td>` : ""}
        </tr>
      `).join("");

      const classOpts = tenantClasses.map((c) =>
        `<option value="${escapeAttr(c.id)}">${escapeHtml(c.name)}${c.year_group ? ` (${escapeHtml(c.year_group)})` : ""}</option>`
      ).join("");

      const studentOpts = allStudents.map((s) =>
        `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`
      ).join("");

      // === Results pane data ===
      const submittedAttempts = await all(
        `SELECT ea.id, ea.user_id, u.name AS student_name, ea.attempt_no,
                ea.grading_status, ea.score_raw, ea.score_total, ea.score_pct,
                ea.grade, ea.pass_mark_percent, ea.started_at, ea.submitted_at,
                ea.time_taken_secs, ea.custom_fields_json
         FROM exam_attempts ea
         JOIN users u ON u.id = ea.user_id
         WHERE ea.exam_id=? AND ea.tenant_id=? AND ea.status='SUBMITTED'
         ORDER BY u.name ASC, ea.attempt_no ASC`,
        [examId, active.tenant_id]
      );
      const inProgressRow = await first(
        `SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=? AND tenant_id=? AND status='IN_PROGRESS'`,
        [examId, active.tenant_id]
      );
      const totalSubmitted = submittedAttempts.length;
      const inProgressC = Number(inProgressRow?.c || 0);
      const needsGradingC = submittedAttempts.filter((a) => a.grading_status === "AUTO_GRADED").length;
      const avgPct = totalSubmitted > 0
        ? Math.round(submittedAttempts.reduce((s, a) => s + Number(a.score_pct || 0), 0) / totalSubmitted * 10) / 10
        : null;

      const fmtSecs = (secs) => {
        if (secs === null || secs === undefined) return "—";
        const s = Number(secs);
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${sec}s`;
        return `${sec}s`;
      };

      const resultRows = submittedAttempts.map((a) => {
        let cfData = {};
        try { cfData = JSON.parse(a.custom_fields_json || "{}"); } catch(e) {}
        const passed = a.pass_mark_percent !== null && a.pass_mark_percent !== undefined && a.score_pct !== null && a.score_pct !== undefined
          ? Number(a.score_pct) >= Number(a.pass_mark_percent)
          : null;
        const statusBadge = a.grading_status === "AUTO_GRADED"
          ? `<span style="background:#fff3cd;color:#856404;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">Needs Grading</span>`
          : `<span style="background:#d4f5e9;color:#0b7a75;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">Fully Graded</span>`;
        const passBadge = passed === null ? `<span class="muted">—</span>`
          : passed
            ? `<span style="background:#d4f5e9;color:#0b7a75;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">Pass</span>`
            : `<span style="background:#ffe8e8;color:#c00;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">Fail</span>`;
        return `
          <tr data-name="${escapeAttr((a.student_name || "").toLowerCase())}"
              data-grading="${escapeAttr(a.grading_status || "")}"
              data-pass="${passed === null ? "none" : (passed ? "pass" : "fail")}"
              data-pct="${a.score_pct !== null && a.score_pct !== undefined ? a.score_pct : ""}"
              data-attempt="${a.attempt_no || ""}"
              data-time="${a.time_taken_secs !== null && a.time_taken_secs !== undefined ? a.time_taken_secs : ""}"
              data-submitted="${escapeAttr(a.submitted_at || "")}">
            <td>${escapeHtml(a.student_name)}</td>
            ${customFields.map((cf) => `<td class="muted small">${escapeHtml(cfData[cf.id] || "")}</td>`).join("")}
            ${Number(exam.max_attempts) > 1 ? `<td class="muted small">${a.attempt_no}</td>` : ""}
            <td>${statusBadge}</td>
            <td>${a.score_raw !== null && a.score_raw !== undefined ? `${Number(a.score_raw)} / ${Number(a.score_total)}` : '<span class="muted">—</span>'}</td>
            <td>${a.score_pct !== null && a.score_pct !== undefined ? `${Number(a.score_pct)}%` : '<span class="muted">—</span>'}</td>
            ${bands.length > 0 ? `<td>${a.grade ? `<span class="pill" style="font-size:11px">${escapeHtml(a.grade)}</span>` : '<span class="muted">—</span>'}</td>` : ""}
            ${exam.pass_mark_percent !== null && exam.pass_mark_percent !== undefined ? `<td>${passBadge}</td>` : ""}
            <td class="muted small">${fmtSecs(a.time_taken_secs)}</td>
            <td class="muted small" style="white-space:nowrap">${a.submitted_at ? fmtISO(a.submitted_at) : "—"}</td>
            <td>
              <a href="/exam-grade?attempt_id=${escapeAttr(a.id)}&exam_id=${escapeAttr(examId)}" class="btn2" style="font-size:12px;padding:5px 10px;border-radius:8px;text-decoration:none;display:inline-block">
                ${a.grading_status === "AUTO_GRADED" ? "Grade" : "View"}
              </a>
            </td>
          </tr>
        `;
      }).join("");

      return page(`
        <style>
          .tabs{display:flex;gap:4px;margin-bottom:0;border-bottom:2px solid rgba(0,0,0,.08);padding-bottom:0}
          .tab{padding:10px 16px;border-radius:10px 10px 0 0;font-weight:700;font-size:13px;cursor:pointer;color:rgba(0,0,0,.5);background:transparent;border:none}
          .tab.active{background:#fff;color:#0b7a75;border:2px solid rgba(0,0,0,.08);border-bottom:2px solid #fff;margin-bottom:-2px}
          .pane{display:none}.pane.active{display:block}
          .section-title{font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase;letter-spacing:.05em;margin:18px 0 10px}
          .field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
          @media(max-width:600px){.field-row{grid-template-columns:1fr}}
          .toggle-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(0,0,0,.06)}
          .toggle-row label{font-size:14px;margin:0}
          .toggle-row .desc{font-size:12px;color:rgba(0,0,0,.5);margin-top:2px}
          .save-bar{position:sticky;bottom:0;background:#fff;border-top:1px solid rgba(0,0,0,.08);padding:12px 0;margin-top:16px;display:flex;gap:10px;align-items:center}
          .badge-draft{background:#f0f0f0;color:#555}
          .badge-published{background:#d4f5e9;color:#0b7a75}
          .badge-closed{background:#ffe8e8;color:#c00}
          #pane-publish button:disabled{opacity:0.45;cursor:not-allowed}
        </style>

        <div class="card" style="margin-bottom:0;border-radius:14px 14px 0 0">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/teacher">← My Exams</a></div>
              <h1 style="margin:0">${escapeHtml(exam.title)}</h1>
              <div class="muted" style="margin-top:4px">
                <span class="pill ${exam.status === "PUBLISHED" ? "badge-published" : exam.status === "CLOSED" ? "badge-closed" : "badge-draft"}">${escapeHtml(exam.status)}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/question-bank">Question Bank</a>
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
          <div class="tabs">
            <button class="tab ${activePane === "settings" ? "active" : ""}" onclick="showPane('settings',this)">Settings</button>
            <button class="tab ${activePane === "questions" ? "active" : ""}" onclick="showPane('questions',this)">Questions</button>
            <button class="tab ${activePane === "publish" ? "active" : ""}" onclick="showPane('publish',this)">Publish</button>
            <button class="tab ${activePane === "access" ? "active" : ""}" onclick="showPane('access',this)">Access</button>
            <button class="tab" onclick="showPane('results',this)">Results</button>
            ${hasAnyGate ? `<button class="tab ${activePane === "approvals" ? "active" : ""}" onclick="showPane('approvals',this)">&#10004; Approvals</button>` : ""}
          </div>
        </div>

        <!-- ===== SETTINGS PANE ===== -->
        <div id="pane-settings" class="pane ${activePane === "settings" ? "active" : ""}">
          <form method="post" action="/exam-save-settings">
            <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />

            ${locked ? `
            <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:8px;color:#856404;font-size:13px">
              🔒 This exam is published — settings are locked.
            </div>
            ` : ""}
            ${(sittingForExam && active.role === "TEACHER") ? `
            <div style="background:#f6f8f7;border:1px solid rgba(0,0,0,.1);border-radius:8px;padding:10px 14px;margin-bottom:8px;color:rgba(0,0,0,.55);font-size:13px">
              🔒 This exam belongs to <b>${escapeHtml(sittingForExam.sitting_title)}</b>. Settings are managed by the sitting admin.
            </div>
            ` : ""}
            ${(locked || (sittingForExam && active.role === "TEACHER")) ? `<fieldset disabled style="border:none;padding:0;margin:0">` : ""}

            <div class="card">
              <div class="section-title">Basic Info</div>
              <label>Exam title</label>
              <input name="title" value="${v("title")}" required />
              <label>Instructions <span class="muted">(shown to student before timer starts — optional)</span></label>
              <textarea name="description" rows="3">${escapeHtml(exam.description || "")}</textarea>
              <div class="field-row" style="margin-top:10px">
                <div>
                  <label>Duration (minutes)</label>
                  <input name="duration_mins" type="number" min="1" value="${v("duration_mins") || 60}" required />
                </div>
                <div>
                  <label>Max attempts</label>
                  <input name="max_attempts" type="number" min="1" value="${v("max_attempts") || 1}" required />
                </div>
              </div>
            </div>

            <div class="card">
              <div class="section-title">Schedule <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional)</span></div>
              <div class="field-row">
                <div>
                  <label>Open at</label>
                  <input name="starts_at" type="datetime-local" value="${v("starts_at") ? v("starts_at").slice(0, 16) : ""}" />
                </div>
                <div>
                  <label>Close at</label>
                  <input name="ends_at" type="datetime-local" value="${v("ends_at") ? v("ends_at").slice(0, 16) : ""}" id="ends_at_input" />
                </div>
              </div>
              <div id="late-policy-wrap" style="${exam.ends_at ? "" : "display:none"}">
                <label>Late submission policy</label>
                <select name="late_submission_policy">
                  <option value="HARD_CUT" ${sel("late_submission_policy", "HARD_CUT")}>Hard cut — submit whatever they have at close time</option>
                  <option value="ALLOW_DURATION" ${sel("late_submission_policy", "ALLOW_DURATION")}>Allow full duration — let them finish their personal timer</option>
                </select>
              </div>
            </div>

            <div class="card">
              <div class="section-title">Security</div>
              <label>Exam password <span class="muted">(optional)</span></label>
              <input name="exam_password" type="text" value="${v("exam_password")}" placeholder="Leave blank for no password" autocomplete="off" />
            </div>

            <div class="card">
              <div class="section-title">Exam Behaviour</div>
              <div class="toggle-row">
                <div><label>Shuffle questions</label><div class="desc">Each student sees questions in a different random order</div></div>
                <input type="checkbox" name="shuffle_questions" value="1" ${chk("shuffle_questions")} style="width:auto;transform:scale(1.4)" />
              </div>
              <div class="toggle-row">
                <div><label>Shuffle answer options</label><div class="desc">For MCQ questions, randomise the order of options</div></div>
                <input type="checkbox" name="shuffle_options" value="1" ${chk("shuffle_options")} style="width:auto;transform:scale(1.4)" />
              </div>
              <div class="toggle-row">
                <div><label>Show question marks during exam</label><div class="desc">Students can see how many marks each question is worth</div></div>
                <input type="checkbox" name="show_marks_during" value="1" ${chk("show_marks_during")} style="width:auto;transform:scale(1.4)" />
              </div>
              <div class="toggle-row">
                <div><label>Allow review after submission</label><div class="desc">After submitting, students can re-read questions and see correct answers</div></div>
                <input type="checkbox" name="allow_review" value="1" ${chk("allow_review")} style="width:auto;transform:scale(1.4)" />
              </div>
              <label style="margin-top:14px">Question navigation</label>
              <select name="navigation_mode">
                <option value="FREE" ${sel("navigation_mode", "FREE")}>Free — student can jump between any questions</option>
                <option value="LINEAR" ${sel("navigation_mode", "LINEAR")}>Linear — must answer in order, cannot go back</option>
              </select>
            </div>

            <div class="card">
              <div class="section-title">Results & Grading</div>
              <label>Results release policy</label>
              <select name="results_release_policy">
                <option value="IMMEDIATE" ${sel("results_release_policy", "IMMEDIATE")}>Immediate — student sees results right after submitting</option>
                <option value="AFTER_CLOSE" ${sel("results_release_policy", "AFTER_CLOSE")}>After close — results visible once exam closes for everyone</option>
                <option value="MANUAL" ${sel("results_release_policy", "MANUAL") || (!exam.results_release_policy ? "selected" : "")}>Manual — teacher decides when to release results</option>
              </select>
              <label style="margin-top:12px">Score display</label>
              <select name="score_display">
                <option value="BOTH" ${sel("score_display", "BOTH")}>Raw score and percentage</option>
                <option value="RAW" ${sel("score_display", "RAW")}>Raw score only</option>
                <option value="PERCENT" ${sel("score_display", "PERCENT")}>Percentage only</option>
                <option value="PASS_FAIL" ${sel("score_display", "PASS_FAIL")}>Pass / Fail only</option>
                <option value="HIDDEN" ${sel("score_display", "HIDDEN")}>Hidden — student sees no score</option>
              </select>
              <label style="margin-top:12px">Pass mark (%) <span class="muted">(optional)</span></label>
              <input name="pass_mark_percent" type="number" min="0" max="100" value="${v("pass_mark_percent")}" placeholder="e.g. 50" />
            </div>

            <div class="card">
              <div class="section-title">Grade Bands <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional)</span></div>
              <p class="muted small">Example: Distinction = 75%+, Credit = 65%+, Pass = 50%+</p>
              <div id="bands-container">${bandRows}</div>
              <button type="button" class="btn3" onclick="addBand()" style="margin-top:4px">+ Add grade band</button>
            </div>

            <div class="card">
              <div class="section-title">Custom Fields <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional — students fill these in before starting)</span></div>
              <p class="muted small">Use for things like: Index Number, Seat Number, Do you need help? (Yes/No)</p>
              <div id="cf-container">${cfRows}</div>
              <button type="button" class="btn3" onclick="addCustomField()" style="margin-top:4px">+ Add custom field</button>
            </div>

            ${(locked || (sittingForExam && active.role === "TEACHER")) ? "</fieldset>" : ""}

            ${(locked || (sittingForExam && active.role === "TEACHER")) ? "" : `
            <div class="save-bar">
              <button type="submit" class="btn2">Save settings</button>
            </div>
            `}
          </form>
        </div>

        <!-- ===== QUESTIONS PANE ===== -->
        <div id="pane-questions" class="pane ${activePane === "questions" ? "active" : ""}">

          ${locked ? `
          <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:8px;color:#856404;font-size:13px">
            🔒 This exam is published — questions are locked and cannot be edited.
          </div>
          ` : ""}

          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
              <div>
                <h2 style="margin:0">Questions</h2>
                <div class="muted small">${questions.length} question${questions.length !== 1 ? "s" : ""} &nbsp;·&nbsp; ${totalMarks} mark${totalMarks !== 1 ? "s" : ""} total</div>
              </div>
              ${locked ? "" : `
              <div class="actions">
                <a href="/exam-bank-picker?exam_id=${escapeAttr(examId)}" class="btn3" style="display:inline-block;padding:8px 14px;border-radius:10px;text-decoration:none;font-weight:700">📚 Add from bank</a>
                <a href="/exam-builder?exam_id=${escapeAttr(examId)}&pane=questions" class="btn2" style="display:inline-block;padding:8px 14px;border-radius:10px;color:#fff;text-decoration:none;font-weight:700">+ New question</a>
              </div>
              `}
            </div>
          </div>

          ${questions.length > 0 ? `<div style="margin-bottom:8px">${questionRows}</div>` : `
            <div class="card" style="text-align:center;padding:32px">
              <p class="muted">No questions yet — add your first question below, or pick from your question bank.</p>
            </div>
          `}

          ${locked ? "" : `
          <!-- Add / Edit question form -->
          <div class="card" id="question-form-card">
            <h2 style="margin:0 0 14px">${editQ ? "Edit question" : "Add question"}</h2>
            <form method="post" action="${editQ ? "/exam-update-question" : "/exam-add-question"}">
              <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
              ${editQ ? `<input type="hidden" name="question_id" value="${escapeAttr(editQ.id)}" />` : ""}

              <div class="field-row">
                <div>
                  <label>Question type</label>
                  <select name="question_type" id="qtype-select" onchange="updateFormForType(this.value)" required>
                    <option value="MCQ" ${formType === "MCQ" ? "selected" : ""}>MCQ (single correct answer)</option>
                    <option value="MULTIPLE_SELECT" ${formType === "MULTIPLE_SELECT" ? "selected" : ""}>Multiple Select (pick all that apply)</option>
                    <option value="TRUE_FALSE" ${formType === "TRUE_FALSE" ? "selected" : ""}>True / False</option>
                    <option value="SHORT_ANSWER" ${formType === "SHORT_ANSWER" ? "selected" : ""}>Short Answer</option>
                    <option value="ESSAY" ${formType === "ESSAY" ? "selected" : ""}>Essay</option>
                  </select>
                </div>
                <div>
                  <label>Marks</label>
                  <input name="marks" type="number" min="0.5" step="0.5" value="${escapeAttr(String(editQ ? editQ.marks : 1))}" required />
                </div>
              </div>

              <label style="margin-top:12px">Question text</label>
              <textarea name="question_text" rows="3" style="font-size:14px" required>${escapeHtml(editQ ? editQ.question_text : "")}</textarea>

              <div id="dynamic-section">
                ${buildOptionRows(formType, editOpts)}
              </div>

              <div style="margin-top:12px">
                <label>Question feedback <span class="muted">(optional — shown to student during review)</span></label>
                <textarea name="feedback" rows="2" style="font-size:13px" placeholder="e.g. The correct answer is X because...">${escapeHtml(editQ ? editQ.feedback || "" : "")}</textarea>
              </div>

              <div id="model-answer-wrap" style="${formType === "SHORT_ANSWER" ? "" : "display:none"}">
                <label>Model answer <span class="muted">(optional — shown to teacher as marking reference)</span></label>
                <input name="model_answer" value="${escapeAttr(editQ ? editQ.model_answer || "" : "")}" placeholder="e.g. Paris" />
              </div>

              <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
                <button type="submit" class="btn2">${editQ ? "Save changes" : "Add question"}</button>
                ${editQ ? `<a href="/exam-builder?exam_id=${escapeAttr(examId)}&pane=questions" class="btn3" style="display:inline-block;padding:8px 12px;border-radius:10px;text-decoration:none">Cancel</a>` : ""}
              </div>
            </form>
          </div>
          `}
        </div>

        <!-- ===== PUBLISH PANE ===== -->
        <div id="pane-publish" class="pane ${activePane === "publish" ? "active" : ""}">

          <!-- Section 1: Publish Exam -->
          <div class="card">
            <div class="section-title">Publish Exam</div>
            <table style="width:100%;font-size:14px;border-collapse:collapse">
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45);width:160px">Questions</td>
                <td style="padding:6px 0;font-weight:600">${questions.length === 0 ? `<span style="color:#856404">0 ⚠️</span>` : questions.length}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Total marks</td>
                <td style="padding:6px 0;font-weight:600">${totalMarks}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Duration</td>
                <td style="padding:6px 0">${escapeHtml(String(exam.duration_mins || 60))} mins</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Max attempts</td>
                <td style="padding:6px 0">${escapeHtml(String(exam.max_attempts || 1))}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Opens at</td>
                <td style="padding:6px 0">${exam.starts_at ? escapeHtml(fmtISO(exam.starts_at)) : '<span class="muted">Not set</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Closes at</td>
                <td style="padding:6px 0">${exam.ends_at ? escapeHtml(fmtISO(exam.ends_at)) : '<span class="muted">Not set</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Late submission</td>
                <td style="padding:6px 0">${exam.late_submission_policy ? escapeHtml(exam.late_submission_policy) : '<span class="muted">Not set</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Exam password</td>
                <td style="padding:6px 0">${exam.exam_password ? "Set ✓" : '<span class="muted">Not set</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Pass mark</td>
                <td style="padding:6px 0">${exam.pass_mark_percent != null ? escapeHtml(String(exam.pass_mark_percent)) + "%" : '<span class="muted">Not set</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Results policy</td>
                <td style="padding:6px 0">${escapeHtml(exam.results_release_policy || "MANUAL")}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Score display</td>
                <td style="padding:6px 0">${escapeHtml(exam.score_display || "BOTH")}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Shuffle questions</td>
                <td style="padding:6px 0">${exam.shuffle_questions ? "Yes" : "No"}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Shuffle options</td>
                <td style="padding:6px 0">${exam.shuffle_options ? "Yes" : "No"}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Show marks during</td>
                <td style="padding:6px 0">${exam.show_marks_during ? "Yes" : "No"}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Allow review</td>
                <td style="padding:6px 0">${exam.allow_review ? "Yes" : "No"}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Navigation mode</td>
                <td style="padding:6px 0">${escapeHtml(exam.navigation_mode || "FREE")}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Grade bands</td>
                <td style="padding:6px 0">${bands.length > 0 ? `${bands.length} band${bands.length !== 1 ? "s" : ""}` : '<span class="muted">None</span>'}</td>
              </tr>
              <tr>
                <td style="padding:6px 0;color:rgba(0,0,0,.45)">Custom fields</td>
                <td style="padding:6px 0">${customFields.length > 0 ? `${customFields.length} field${customFields.length !== 1 ? "s" : ""}` : '<span class="muted">None</span>'}</td>
              </tr>
            </table>
            ${(sittingForExam && active.role === "TEACHER") ? `
              <div style="background:#f6f8f7;border:1px solid rgba(0,0,0,.1);border-radius:8px;padding:10px 14px;margin-top:14px;color:rgba(0,0,0,.55);font-size:13px">
                🔒 This exam belongs to the sitting <b>${escapeHtml(sittingForExam.sitting_title)}</b>. Publishing and results release are managed by the sitting admin.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed">🔒 Publish Exam</button>
            ` : exam.status === "DRAFT" && questions.length === 0 ? `
              <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-top:14px;color:#856404;font-size:13px">
                ⚠️ Add at least one question before publishing.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px">🔒 Publish Exam</button>
            ` : exam.status === "DRAFT" ? (() => {
              const qGate = gateStatuses["QUESTIONS"];
              const qBlocked = active.role === "SCHOOL_ADMIN" && qGate !== "NOT_CONFIGURED" && qGate !== "APPROVED";
              return qBlocked ? `
                <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-top:14px;color:#856404;font-size:13px">
                  ⚠️ Questions approval required before publishing.
                </div>
                <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed">🔒 Publish Exam</button>
              ` : `
                <form method="post" action="/exam-publish" style="margin-top:14px">
                  <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
                  <button class="btn2" type="submit">Publish Exam</button>
                </form>
              `;
            })() : `
              <div style="background:#d4f5e9;border:1px solid #0b7a75;border-radius:8px;padding:10px 14px;margin-top:14px;color:#0b7a75;font-size:13px">
                ✅ This exam has been published${exam.published_at ? " on " + escapeHtml(fmtISO(exam.published_at)) : ""}.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px">🔒 Publish Exam</button>
            `}
          </div>

          <!-- Section 2: Close Exam (always visible) -->
          <div class="card">
            <div class="section-title">Close Exam</div>
            ${exam.status === "CLOSED" ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Closed on: ${exam.closed_at ? escapeHtml(fmtISO(exam.closed_at)) : "date not recorded"}</p>
            ` : exam.status === "PUBLISHED" && exam.ends_at && new Date(exam.ends_at) > new Date() ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Scheduled to close: ${escapeHtml(fmtISO(exam.ends_at))}</p>
            ` : exam.status === "PUBLISHED" && exam.ends_at ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Scheduled close date passed: ${escapeHtml(fmtISO(exam.ends_at))}</p>
            ` : exam.status === "PUBLISHED" ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 No automatic close date set</p>
            ` : ""}
            ${(sittingForExam && active.role === "TEACHER") ? `
              <div style="background:#f6f8f7;border:1px solid rgba(0,0,0,.1);border-radius:8px;padding:10px 14px;color:rgba(0,0,0,.55);font-size:13px">
                🔒 This exam belongs to the sitting <b>${escapeHtml(sittingForExam.sitting_title)}</b>. Publishing and results release are managed by the sitting admin.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed;background:#c00;border-color:#c00">🔒 Close Exam Now</button>
            ` : exam.status === "DRAFT" ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Publish the exam first.</p>
              <button class="btn2" type="button" disabled style="background:#c00;border-color:#c00">🔒 Close Exam Now</button>
            ` : exam.status === "CLOSED" ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">This exam is already closed.</p>
              <button class="btn2" type="button" disabled style="background:#c00;border-color:#c00">🔒 Close Exam Now</button>
            ` : exam.ends_at && new Date(exam.ends_at) > new Date() ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Exam is scheduled to close automatically on <strong>${escapeHtml(fmtISO(exam.ends_at))}</strong>.</p>
              <button class="btn2" type="button" disabled style="background:#c00;border-color:#c00">🔒 Close Exam Now</button>
            ` : `
              ${exam.ends_at ? `
                <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:12px;color:#856404;font-size:13px">
                  ⚠️ Your scheduled close date has passed.
                </div>
              ` : `
                <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">No automatic close date is set. You can close it manually when ready.</p>
              `}
              <form method="post" action="/exam-close">
                <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
                <button class="btn2" type="submit" style="background:#c00;border-color:#c00" onclick="return confirm('Close this exam now? Students will no longer be able to start it.')">Close Exam Now</button>
              </form>
            `}
          </div>

          <!-- Section 3: Release Results (always visible) -->
          <div class="card">
            <div class="section-title">Release Results</div>
            ${exam.results_release_policy === "IMMEDIATE" ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Auto-releases on publish</p>
            ` : exam.results_release_policy === "AFTER_CLOSE" ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Auto-releases when exam closes</p>
            ` : exam.results_published_at ? `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Released on: ${escapeHtml(fmtISO(exam.results_published_at))}</p>
            ` : `
              <p style="font-size:13px;color:rgba(0,0,0,.45);margin:0 0 10px">📅 Not yet released</p>
            `}
            ${(sittingForExam && active.role === "TEACHER") ? `
              <div style="background:#f6f8f7;border:1px solid rgba(0,0,0,.1);border-radius:8px;padding:10px 14px;color:rgba(0,0,0,.55);font-size:13px">
                🔒 This exam belongs to the sitting <b>${escapeHtml(sittingForExam.sitting_title)}</b>. Publishing and results release are managed by the sitting admin.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed">🔒 Release Results Now</button>
            ` : exam.status !== "CLOSED" ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Close the exam first before releasing results.</p>
              <button class="btn2" type="button" disabled>🔒 Release Results Now</button>
            ` : exam.results_release_policy === "IMMEDIATE" ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Results will release automatically when published (IMMEDIATE policy).</p>
              <button class="btn2" type="button" disabled>🔒 Release Results Now</button>
            ` : exam.results_release_policy === "AFTER_CLOSE" ? `
              <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Results will release automatically when exam closes (AFTER_CLOSE policy).</p>
              <button class="btn2" type="button" disabled>🔒 Release Results Now</button>
            ` : exam.results_published_at ? `
              <div style="background:#d4f5e9;border:1px solid #0b7a75;border-radius:8px;padding:10px 14px;color:#0b7a75;font-size:13px">
                ✅ Results already released on <strong>${escapeHtml(fmtISO(exam.results_published_at))}</strong>.
              </div>
              <button class="btn2" type="button" disabled style="margin-top:14px">🔒 Release Results Now</button>
            ` : (() => {
              if (active.role === "SCHOOL_ADMIN") {
                const gradingSt = gateStatuses["GRADING"];
                const resultsSt = gateStatuses["RESULTS"];
                if (gradingSt !== "NOT_CONFIGURED" && gradingSt !== "APPROVED") {
                  return `
                    <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;color:#856404;font-size:13px">
                      ⚠️ Grading approval required before releasing results.
                    </div>
                    <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed">🔒 Release Results Now</button>
                  `;
                }
                if (resultsSt !== "NOT_CONFIGURED" && resultsSt !== "APPROVED") {
                  return `
                    <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;color:#856404;font-size:13px">
                      ⚠️ Results approval required before releasing.
                    </div>
                    <button class="btn2" type="button" disabled style="margin-top:14px;opacity:0.45;cursor:not-allowed">🔒 Release Results Now</button>
                  `;
                }
              }
              return `
                <p style="font-size:14px;color:rgba(0,0,0,.55);margin:0 0 12px">Results have not been released to students yet.</p>
                <form method="post" action="/exam-release-results">
                  <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
                  <button class="btn2" type="submit" onclick="return confirm('Release results to all students now?')">Release Results Now</button>
                </form>
              `;
            })()}
          </div>

        </div>

        <!-- ===== ACCESS PANE ===== -->
        <div id="pane-access" class="pane ${activePane === "access" ? "active" : ""}">

          <!-- Access list summary + table -->
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
              <h2 style="margin:0">Access List</h2>
              <span class="pill ${accessList.length === 0 ? "badge-draft" : "badge-published"}">${accessList.length} student${accessList.length === 1 ? "" : "s"}</span>
            </div>
            ${exam.status === "PUBLISHED" && accessList.length === 0 ? `
            <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:12px;color:#856404;font-size:13px">
              ⚠️ This exam is published but no students are on the access list — no one can take it yet.
            </div>
            ` : ""}
            ${exam.status === "CLOSED" ? `
            <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:12px;color:#856404;font-size:13px">
              🔒 This exam is closed — the access list is read-only.
            </div>
            ` : ""}
            ${accessList.length === 0 ? `
              <p class="muted">No students on the access list yet.</p>
            ` : `
              <table style="width:100%;border-collapse:collapse;font-size:13px">
                <thead>
                  <tr style="border-bottom:2px solid rgba(0,0,0,.08)">
                    <th style="text-align:left;padding:6px 8px;color:rgba(0,0,0,.5)">Name</th>
                    <th style="text-align:left;padding:6px 8px;color:rgba(0,0,0,.5)">Email</th>
                    <th style="text-align:left;padding:6px 8px;color:rgba(0,0,0,.5)">Class</th>
                    ${exam.status !== "CLOSED" ? `<th style="width:80px"></th>` : ""}
                  </tr>
                </thead>
                <tbody>${accessRows}</tbody>
              </table>
            `}
          </div>

          <!-- Add student cards — only shown when exam is not CLOSED -->
          ${exam.status !== "CLOSED" ? `
          ${tenantClasses.length > 0 ? `
          <div class="card" style="margin-top:12px">
            <h3 style="margin:0 0 10px">Add by Class</h3>
            <p class="muted" style="font-size:13px;margin:0 0 12px">All students in the selected class will be added to the access list (duplicates skipped).</p>
            <form method="post" action="/exam-access-add-class" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
              <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
              <div style="flex:1;min-width:180px">
                <label style="font-size:12px;font-weight:600;color:rgba(0,0,0,.5);display:block;margin-bottom:4px">Class</label>
                <select name="class_id" required style="width:100%">
                  <option value="">— select class —</option>
                  ${classOpts}
                </select>
              </div>
              <button class="btn2" type="submit">Add Class</button>
            </form>
          </div>
          ` : ""}
          <div class="card" style="margin-top:12px">
            <h3 style="margin:0 0 8px">Add from Course Enrollment</h3>
            <p class="muted" style="font-size:13px;margin:0 0 12px">Adds all students currently enrolled in this exam's course who aren't already on the list. ${enrolledStudents.length > 0 ? `<strong style="color:#0b7a75">${enrolledStudents.length} student${enrolledStudents.length === 1 ? "" : "s"} eligible.</strong>` : `<strong>All enrolled students are already on the list.</strong>`}</p>
            ${enrolledStudents.length > 0 ? `
            <form method="post" action="/exam-access-add-course" style="margin:0">
              <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
              <button class="btn2" type="submit">Add All Enrolled (${enrolledStudents.length})</button>
            </form>
            ` : ""}
          </div>
          ${allStudents.length > 0 ? `
          <div class="card" style="margin-top:12px">
            <h3 style="margin:0 0 10px">Add Individual Student</h3>
            <form method="post" action="/exam-access-add-student" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
              <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
              <div style="flex:1;min-width:220px">
                <label style="font-size:12px;font-weight:600;color:rgba(0,0,0,.5);display:block;margin-bottom:4px">Student</label>
                <select name="user_id" required style="width:100%">
                  <option value="">— select student —</option>
                  ${studentOpts}
                </select>
              </div>
              <button class="btn2" type="submit">Add Student</button>
            </form>
          </div>
          ` : ""}
          ` : ""}

        </div>

        <!-- ===== RESULTS PANE ===== -->
        <div id="pane-results" class="pane ${activePane === "results" ? "active" : ""}">

          <div class="card">
            <div style="display:flex;gap:12px;flex-wrap:wrap">
              <div style="flex:1;min-width:110px;text-align:center;padding:14px;background:#f6f8f7;border-radius:10px">
                <div style="font-size:28px;font-weight:800;color:#0b7a75">${totalSubmitted}</div>
                <div class="muted small">Submitted</div>
              </div>
              <div style="flex:1;min-width:110px;text-align:center;padding:14px;background:#f6f8f7;border-radius:10px">
                <div style="font-size:28px;font-weight:800;color:#555">${inProgressC}</div>
                <div class="muted small">In Progress</div>
              </div>
              <div style="flex:1;min-width:110px;text-align:center;padding:14px;background:${needsGradingC > 0 ? "#fff8e1" : "#f6f8f7"};border-radius:10px">
                <div style="font-size:28px;font-weight:800;color:${needsGradingC > 0 ? "#e65100" : "#555"}">${needsGradingC}</div>
                <div class="muted small">Needs Grading</div>
              </div>
              ${avgPct !== null ? `
              <div style="flex:1;min-width:110px;text-align:center;padding:14px;background:#f6f8f7;border-radius:10px">
                <div style="font-size:28px;font-weight:800;color:#0b7a75">${avgPct}%</div>
                <div class="muted small">Avg Score</div>
              </div>` : ""}
            </div>
          </div>

          <div class="card" style="padding:12px 16px">
            <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
              <div>
                <label style="margin:0 0 4px;font-size:12px;font-weight:700;color:rgba(0,0,0,.5)">Grading status</label>
                <select id="rf-grading" onchange="filterResults()" style="padding:7px 10px">
                  <option value="">All</option>
                  <option value="FULLY_GRADED">Fully Graded</option>
                  <option value="AUTO_GRADED">Needs Grading</option>
                </select>
              </div>
              ${exam.pass_mark_percent !== null && exam.pass_mark_percent !== undefined ? `
              <div>
                <label style="margin:0 0 4px;font-size:12px;font-weight:700;color:rgba(0,0,0,.5)">Result</label>
                <select id="rf-pass" onchange="filterResults()" style="padding:7px 10px">
                  <option value="">All</option>
                  <option value="pass">Pass</option>
                  <option value="fail">Fail</option>
                </select>
              </div>` : `<span id="rf-pass" style="display:none"></span>`}
              <div style="margin-left:auto">
                <a href="/exam-results-csv?exam_id=${escapeAttr(examId)}" class="btn3" style="font-size:13px;text-decoration:none;display:inline-block">⬇ Export CSV</a>
              </div>
            </div>
          </div>

          ${totalSubmitted === 0 ? `
          <div class="card" style="text-align:center;padding:32px">
            <p class="muted">No submissions yet.</p>
          </div>
          ` : `
          <div class="card" style="padding:0;overflow:auto">
            <table class="table" id="results-table">
              <thead>
                <tr>
                  <th onclick="sortResults('name')" style="cursor:pointer;white-space:nowrap">Student ↕</th>
                  ${customFields.map((cf) => `<th>${escapeHtml(cf.field_label)}</th>`).join("")}
                  ${Number(exam.max_attempts) > 1 ? `<th onclick="sortResults('attempt')" style="cursor:pointer"># ↕</th>` : ""}
                  <th onclick="sortResults('grading')" style="cursor:pointer;white-space:nowrap">Status ↕</th>
                  <th onclick="sortResults('score')" style="cursor:pointer;white-space:nowrap">Score ↕</th>
                  <th onclick="sortResults('pct')" style="cursor:pointer;white-space:nowrap">% ↕</th>
                  ${bands.length > 0 ? `<th>Grade</th>` : ""}
                  ${exam.pass_mark_percent !== null && exam.pass_mark_percent !== undefined ? `<th>Pass/Fail</th>` : ""}
                  <th onclick="sortResults('time')" style="cursor:pointer;white-space:nowrap">Time ↕</th>
                  <th onclick="sortResults('submitted')" style="cursor:pointer;white-space:nowrap">Submitted ↕</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="results-tbody">
                ${resultRows}
              </tbody>
            </table>
          </div>
          `}

        </div>

        ${hasAnyGate ? (() => {
          // Build the approvals pane
          const gateBlocks = configuredGateTypes.map(gateType => {
            const gateLabel = GATE_LABEL_MAP[gateType] || gateType;
            const gateSt = gateStatuses[gateType];
            const assigneesForGate = allGates.filter(g => g.gate_type === gateType);
            const respForGate = responseMap[gateType] || {};
            const submitted = isGateSubmitted(gateType);

            // Status badge
            const statusBadgeHtml = gateSt === "APPROVED"
              ? `<span style="background:#d4f5e9;color:#0b7a75;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">✅ Approved</span>`
              : gateSt === "REJECTED"
              ? `<span style="background:#ffe8e8;color:#c00;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">❌ Rejected</span>`
              : submitted
              ? `<span style="background:#f0f0f0;color:#555;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">⏳ Awaiting Response</span>`
              : `<span style="background:#fff3cd;color:#856404;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">Not Submitted</span>`;

            // Per-approver status rows
            const approverRows = assigneesForGate.map(a => {
              const resp = respForGate[a.user_id];
              const st = resp ? resp.status : "PENDING";
              const badge = st === "APPROVED"
                ? `<span style="color:#0b7a75;font-weight:700;font-size:12px">✅ Approved</span>`
                : st === "REJECTED"
                ? `<span style="color:#c00;font-weight:700;font-size:12px">❌ Rejected</span>`
                : submitted
                ? `<span style="color:rgba(0,0,0,.45);font-size:12px">⏳ Pending</span>`
                : `<span style="color:rgba(0,0,0,.35);font-size:12px">Not sent</span>`;
              return `
                <div style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(0,0,0,.05)">
                  <span style="font-size:13px">${escapeHtml(a.approver_name)}</span>
                  ${badge}
                </div>`;
            }).join("");

            // Rejection notes (from any rejecting approver)
            const rejectionNotes = assigneesForGate
              .filter(a => (respForGate[a.user_id] || {}).status === "REJECTED" && (respForGate[a.user_id] || {}).note)
              .map(a => `
                <div style="background:#ffe8e8;border:1px solid #f5c6c6;border-radius:8px;padding:8px 12px;margin-top:8px;font-size:13px">
                  <strong>${escapeHtml(a.approver_name)}:</strong> ${escapeHtml(respForGate[a.user_id].note)}
                </div>`).join("");

            // Submit button — teacher only
            let submitHtml = "";
            if (active.role === "TEACHER") {
              if (gateSt === "APPROVED") {
                submitHtml = `<div style="margin-top:10px;font-size:13px;color:#0b7a75">✅ This gate is fully approved. No further action needed.</div>`;
              } else if (submitted && gateSt !== "REJECTED") {
                submitHtml = `<div style="margin-top:10px;font-size:13px;color:rgba(0,0,0,.5)">⏳ Submitted — waiting for all approvers to respond.</div>`;
              } else {
                const canSubmit = true; // QUESTIONS: anytime; GRADING/RESULTS: validated server-side
                const submitLabel = gateSt === "REJECTED" ? "Resubmit for Approval" : "Submit for Approval";
                submitHtml = `
                  <form method="post" action="/exam-gate-submit" style="margin-top:10px">
                    <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
                    <input type="hidden" name="gate_type" value="${escapeAttr(gateType)}" />
                    <button type="submit" class="btn2" style="font-size:13px">${submitLabel}</button>
                  </form>`;
              }
            }

            return `
              <div class="card" style="margin-bottom:12px">
                <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px">
                  <span style="font-weight:700;font-size:15px">${gateLabel} Gate</span>
                  ${statusBadgeHtml}
                </div>
                <div style="margin-bottom:6px">
                  ${approverRows}
                </div>
                ${rejectionNotes}
                ${submitHtml}
              </div>`;
          }).join("");

          return `
            <!-- ===== APPROVALS PANE ===== -->
            <div id="pane-approvals" class="pane ${activePane === "approvals" ? "active" : ""}">
              ${gateBlocks}
            </div>`;
        })() : ""}

        <script>
          function showPane(name, btn) {
            document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('pane-' + name).classList.add('active');
            btn.classList.add('active');
          }

          const endsAtInput = document.getElementById('ends_at_input');
          if (endsAtInput) {
            endsAtInput.addEventListener('change', function() {
              document.getElementById('late-policy-wrap').style.display = this.value ? '' : 'none';
            });
          }

          function addBand() {
            const row = document.createElement('div');
            row.className = 'band-row';
            row.style = 'display:flex;gap:8px;align-items:center;margin-bottom:8px';
            row.innerHTML = \`
              <input name="band_label[]" placeholder="e.g. Distinction" style="flex:2" />
              <input name="band_min[]" type="number" min="0" max="100" placeholder="Min %" style="flex:1" />
              <button type="button" class="btn3" onclick="this.closest('.band-row').remove()">✕</button>
            \`;
            document.getElementById('bands-container').appendChild(row);
          }

          function addCustomField() {
            const row = document.createElement('div');
            row.className = 'cf-row';
            row.style = 'border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:8px';
            row.innerHTML = \`
              <div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap">
                <input name="cf_label[]" placeholder="Field label e.g. Index Number" style="flex:2;min-width:160px" />
                <select name="cf_type[]" style="flex:1;min-width:120px" onchange="toggleCfOptions(this)">
                  <option value="TEXT">Text</option>
                  <option value="YESNO">Yes / No</option>
                  <option value="DROPDOWN">Dropdown</option>
                </select>
                <label style="display:flex;align-items:center;gap:4px;font-size:13px;margin:0">
                  <input type="checkbox" name="cf_required[]" value="1" /> Required
                </label>
                <button type="button" class="btn3" onclick="this.closest('.cf-row').remove()">✕</button>
              </div>
              <div class="cf-options-wrap" style="margin-top:8px;display:none">
                <input name="cf_options[]" placeholder="Dropdown options, comma separated" style="width:100%" />
              </div>
            \`;
            document.getElementById('cf-container').appendChild(row);
          }

          function toggleCfOptions(sel) {
            const wrap = sel.closest('.cf-row').querySelector('.cf-options-wrap');
            wrap.style.display = sel.value === 'DROPDOWN' ? '' : 'none';
          }

          function updateFormForType(type) {
            const section = document.getElementById('dynamic-section');
            const modelWrap = document.getElementById('model-answer-wrap');
            modelWrap.style.display = type === 'SHORT_ANSWER' ? '' : 'none';
            if (type === 'TRUE_FALSE') {
              section.innerHTML = \`
                <div class="section-title" style="margin-top:14px">Correct answer</div>
                <select name="tf_correct" required style="max-width:200px">
                  <option value="">— select —</option>
                  <option value="True">True</option>
                  <option value="False">False</option>
                </select>
              \`;
            } else if (type === 'MCQ' || type === 'MULTIPLE_SELECT') {
              const isMulti = type === 'MULTIPLE_SELECT';
              section.innerHTML = \`
                <div class="section-title" style="margin-top:14px">Answer options</div>
                <div id="options-container">
                  \${[0,1,2,3].map(i => buildOptRow(isMulti,'',false,'',i)).join('')}
                </div>
                <button type="button" class="btn3" onclick="addOptionRow(\${isMulti})" style="margin-top:4px;font-size:12px">+ Add option</button>
                \${isMulti ? \`
                  <div style="margin-top:12px">
                    <label>Partial marking</label>
                    <select name="partial_marking">
                      <option value="1">Partial marks</option>
                      <option value="0">All or nothing</option>
                    </select>
                  </div>\` : ''}
              \`;
            } else {
              section.innerHTML = '';
            }
          }

          function buildOptRow(isMulti, text, isCorrect, feedback, idx) {
            return \`<div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
              <div style="display:flex;gap:8px;align-items:center">
                <input type="\${isMulti?'checkbox':'radio'}" name="opt_correct[]" value="\${idx}" \${isCorrect?'checked':''} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
                <input name="opt_text[]" value="\${text}" placeholder="Option text" style="flex:1" />
                <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px;flex-shrink:0">✕</button>
              </div>
              <div style="margin-top:6px">
                <input name="opt_feedback[]" value="\${feedback}" placeholder="Feedback for this option (optional)" style="font-size:12px" />
              </div>
            </div>\`;
          }

          function addOptionRow(isMulti) {
            const container = document.getElementById('options-container');
            const idx = container.querySelectorAll('.opt-row').length;
            container.insertAdjacentHTML('beforeend', buildOptRow(isMulti,'',false,'',idx));
          }

          function filterResults() {
            const gf = document.getElementById('rf-grading').value;
            const pfEl = document.getElementById('rf-pass');
            const pf = pfEl ? pfEl.value : '';
            document.querySelectorAll('#results-tbody tr').forEach(row => {
              let show = true;
              if (gf && row.dataset.grading !== gf) show = false;
              if (pf && row.dataset.pass !== pf) show = false;
              row.style.display = show ? '' : 'none';
            });
          }

          let _sortDir = {};
          function sortResults(col) {
            const tbody = document.getElementById('results-tbody');
            if (!tbody) return;
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const dir = (_sortDir[col] = _sortDir[col] === 'asc' ? 'desc' : 'asc');
            const numCols = ['pct', 'attempt', 'time'];
            const attrMap = {name:'name', attempt:'attempt', grading:'grading', score:'pct', pct:'pct', time:'time', submitted:'submitted'};
            const attr = attrMap[col] || col;
            rows.sort((a, b) => {
              const av = a.dataset[attr] || '';
              const bv = b.dataset[attr] || '';
              if (numCols.includes(attr)) {
                return dir === 'asc' ? (Number(av)||0) - (Number(bv)||0) : (Number(bv)||0) - (Number(av)||0);
              }
              return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
            });
            rows.forEach(r => tbody.appendChild(r));
          }
        </script>
      `);
    }

    // =============================
    // Exam: grade submission (GET)
    // =============================
    if (path === "/exam-grade" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const attemptId = url.searchParams.get("attempt_id") || "";
      const examId    = url.searchParams.get("exam_id")    || "";
      const viewOnly  = url.searchParams.get("view") === "1";
      if (!attemptId || !examId) return redirect("/teacher");

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const attempt = await first(
        `SELECT ea.*, u.name AS student_name
         FROM exam_attempts ea
         JOIN users u ON u.id = ea.user_id
         WHERE ea.id=? AND ea.exam_id=? AND ea.tenant_id=? AND ea.status='SUBMITTED'`,
        [attemptId, examId, active.tenant_id]
      );
      if (!attempt) return redirect(`/exam-builder?exam_id=${examId}&pane=results`);

      const fmtSecs = (secs) => {
        if (secs === null || secs === undefined) return "—";
        const s = Number(secs);
        const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${sec}s`;
        return `${sec}s`;
      };

      // Load ALL questions in design (sort_order) order
      const questions = await all(
        `SELECT id, question_type, question_text, marks, sort_order, partial_marking, model_answer
         FROM exam_questions WHERE exam_id=? AND tenant_id=? ORDER BY sort_order ASC`,
        [examId, active.tenant_id]
      );

      // Load ALL options for all questions
      const optionsByQ = {};
      if (questions.length > 0) {
        const ph = questions.map(() => "?").join(",");
        const optRows = await all(
          `SELECT id, question_id, option_text, is_correct, sort_order
           FROM exam_question_options WHERE question_id IN (${ph}) ORDER BY sort_order ASC`,
          questions.map(q => q.id)
        );
        for (const o of optRows) {
          if (!optionsByQ[o.question_id]) optionsByQ[o.question_id] = [];
          optionsByQ[o.question_id].push(o);
        }
      }

      // Load ALL answers with grader name
      const answRows = await all(
        `SELECT a.question_id, a.answer_json, a.score_awarded, a.teacher_note,
                a.graded_by, a.graded_at, gb.name AS graded_by_name
         FROM exam_answers a
         LEFT JOIN users gb ON gb.id = a.graded_by
         WHERE a.attempt_id=?`,
        [attemptId]
      );
      const answersByQ = {};
      for (const a of answRows) answersByQ[a.question_id] = a;

      // Compute score totals
      const manualTypes = new Set(["SHORT_ANSWER", "ESSAY"]);
      let baseScore = 0, scoreTotalAll = 0;
      for (const q of questions) {
        scoreTotalAll += Number(q.marks || 0);
        if (!manualTypes.has(q.question_type)) {
          const a = answersByQ[q.id];
          if (a && a.score_awarded !== null && a.score_awarded !== undefined)
            baseScore += Number(a.score_awarded);
        }
      }
      const manualQs = questions.filter(q => manualTypes.has(q.question_type));
      let initialManualScore = 0;
      for (const q of manualQs) {
        const a = answersByQ[q.id];
        if (a && a.score_awarded !== null && a.score_awarded !== undefined)
          initialManualScore += Number(a.score_awarded);
      }
      const initialScore  = baseScore + initialManualScore;
      const ungradedManual = manualQs.filter(q => {
        const a = answersByQ[q.id];
        return !a || a.score_awarded === null || a.score_awarded === undefined;
      });
      const initPct = scoreTotalAll > 0 ? Math.round(initialScore / scoreTotalAll * 10000) / 100 : 0;

      // Question number map
      const qNumMap = {};
      questions.forEach((q, i) => { qNumMap[q.id] = i + 1; });

      // Sidebar items (same HTML reused in desktop sidebar and mobile drawer)
      const sidebarItems = manualQs.map(q => {
        const a = answersByQ[q.id];
        const ungraded = !a || a.score_awarded === null || a.score_awarded === undefined;
        const hidden   = !viewOnly && !ungraded;
        return `<div data-sidebar-q="${escapeAttr(q.id)}" style="${hidden ? "display:none;" : ""}padding:6px 8px;border-radius:8px;cursor:pointer;font-size:13px;background:rgba(11,122,117,.07);margin:3px 0" onclick="scrollToQ('${escapeAttr(q.id)}')"><span style="font-weight:700">Q${qNumMap[q.id]}</span> — ${escapeHtml(qTypeLabel(q.question_type))}</div>`;
      }).join("");

      const allDoneInit = !viewOnly && manualQs.length > 0 && ungradedManual.length === 0;
      const noManualInit = manualQs.length === 0;

      // Helper: render option rows with colour highlighting
      const renderOptions = (opts, selectedSet) =>
        opts.map(o => {
          const sel = selectedSet.has(String(o.id));
          const cor = !!o.is_correct;
          let bg = "rgba(0,0,0,.03)", badge = "", note = "";
          if (sel && cor)  { bg = "#d4f5e9"; badge = `<span style="margin-left:6px">✅</span>`; }
          else if (sel)    { bg = "#fff3f3"; badge = `<span style="margin-left:6px">❌</span>`; }
          else if (cor)    { bg = "#fff8e1"; note  = `<span class="muted small" style="margin-left:6px">(correct answer)</span>`; }
          return `<div style="padding:8px 12px;border-radius:8px;margin:4px 0;font-size:14px;background:${bg}">${escapeHtml(o.option_text)}${badge}${note}</div>`;
        }).join("");

      // Build one card per question
      const questionCards = questions.map((q, qi) => {
        const qNum = qi + 1;
        const ans  = answersByQ[q.id] || {};
        const opts = optionsByQ[q.id] || [];
        const sa   = (ans.score_awarded !== null && ans.score_awarded !== undefined) ? Number(ans.score_awarded) : null;
        const scorePill = sa !== null
          ? `<span class="pill" style="font-size:12px;background:#d4f5e9;color:#0b5e4e">${sa} / ${escapeHtml(String(q.marks))}</span>`
          : `<span class="pill" style="font-size:12px;background:rgba(0,0,0,.07);color:rgba(0,0,0,.5)">${escapeHtml(String(q.marks))} mark${Number(q.marks) !== 1 ? "s" : ""}</span>`;

        let body = "";
        if (q.question_type === "MCQ" || q.question_type === "TRUE_FALSE") {
          let sel = null;
          try { if (ans.answer_json != null && ans.answer_json !== "") sel = JSON.parse(ans.answer_json); } catch(e) {}
          body = sel === null
            ? `<div style="color:rgba(0,0,0,.45);font-style:italic;font-size:14px;padding:4px 0">Not answered</div>`
            : renderOptions(opts, new Set([String(sel)]));

        } else if (q.question_type === "MULTIPLE_SELECT") {
          let ids = [];
          try {
            if (ans.answer_json != null && ans.answer_json !== "") {
              const p = JSON.parse(ans.answer_json);
              ids = Array.isArray(p) ? p.map(String) : (p ? [String(p)] : []);
            }
          } catch(e) {}
          body = ids.length === 0
            ? `<div style="color:rgba(0,0,0,.45);font-style:italic;font-size:14px;padding:4px 0">Not answered</div>`
            : renderOptions(opts, new Set(ids));

        } else {
          // SHORT_ANSWER / ESSAY
          const studentAns = ans.answer_json || "";
          const scoreVal   = sa !== null ? String(sa) : "";
          const noteVal    = ans.teacher_note || "";
          const dis        = viewOnly ? "disabled" : "";
          const rows       = q.question_type === "ESSAY" ? 6 : 3;
          const gradedLine = ans.graded_by_name
            ? `<div style="margin-top:8px;font-size:12px;color:rgba(0,0,0,.45)">Graded by ${escapeHtml(ans.graded_by_name)}${ans.graded_at ? " on " + fmtISO(ans.graded_at) : ""}</div>`
            : "";
          body = `
            <div style="background:#f6f8f7;border-radius:10px;padding:12px;margin-bottom:10px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:rgba(0,0,0,.45);margin-bottom:6px">Student's Answer</div>
              <div style="font-size:14px;white-space:pre-wrap;min-height:18px">${escapeHtml(studentAns)}</div>
            </div>
            ${q.model_answer ? `<details style="margin-bottom:10px"><summary style="cursor:pointer;font-size:13px;color:rgba(0,0,0,.5);font-weight:600">Show model answer</summary><div style="background:#f0fff8;border-radius:10px;padding:10px;margin-top:6px;font-size:14px;white-space:pre-wrap">${escapeHtml(q.model_answer)}</div></details>` : ""}
            <div style="margin-bottom:8px">
              <label>Score awarded <span class="muted">(max ${escapeHtml(String(q.marks))})</span></label>
              <input type="number" name="score_${escapeAttr(q.id)}" value="${escapeAttr(scoreVal)}"
                     min="0" max="${escapeAttr(String(q.marks))}" step="0.5" style="max-width:140px"
                     class="manual-score-input" data-qid="${escapeAttr(q.id)}"
                     oninput="onScoreInput('${escapeAttr(q.id)}',this)" ${dis} />
            </div>
            <div>
              <label>Teacher note <span class="muted">(optional)</span></label>
              <textarea name="note_${escapeAttr(q.id)}" rows="${rows}" style="resize:vertical" ${dis}>${escapeHtml(noteVal)}</textarea>
            </div>
            ${gradedLine}`;
        }

        return `
        <div class="card" id="q-${escapeAttr(q.id)}" style="margin:8px 0;scroll-margin-top:16px">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span style="font-size:12px;color:rgba(0,0,0,.45);font-weight:700;background:rgba(0,0,0,.06);padding:3px 8px;border-radius:6px">Q${qNum}</span>
              <span class="pill" style="font-size:11px">${escapeHtml(qTypeLabel(q.question_type))}</span>
            </div>
            ${scorePill}
          </div>
          <div style="font-size:15px;font-weight:600;margin-bottom:12px">${escapeHtml(q.question_text)}</div>
          ${body}
        </div>`;
      }).join("");

      // Wrap questions in form (or not for view-only)
      const formWrap = viewOnly
        ? questionCards
        : `<form method="post" action="/exam-grade">
            <input type="hidden" name="attempt_id" value="${escapeAttr(attemptId)}" />
            <input type="hidden" name="exam_id"    value="${escapeAttr(examId)}" />
            ${questionCards}
            <div class="card" style="padding:12px 16px">
              <div class="actions">
                <button class="btn2" type="submit">Save Grades</button>
                <a href="/exam-builder?exam_id=${escapeAttr(examId)}&pane=results" class="btn3" style="text-decoration:none">Cancel</a>
              </div>
            </div>
          </form>`;

      return page(`
        <style>
          .gl{display:grid;grid-template-columns:1fr 220px;gap:16px;align-items:start}
          .gl-side{position:sticky;top:16px}
          #mob-fab{display:none}
          #mob-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:40}
          #mob-dr{position:fixed;bottom:0;left:0;right:0;background:#fff;border-radius:16px 16px 0 0;padding:16px;z-index:50;transform:translateY(100%);transition:transform .25s ease;max-height:60vh;overflow-y:auto}
          @media(max-width:768px){.gl{grid-template-columns:1fr}.gl-side{display:none}#mob-fab{display:block;position:fixed;bottom:20px;right:16px;z-index:30;padding:10px 16px;border:0;border-radius:999px;background:#0b7a75;color:#fff;font-weight:700;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.22);font-size:14px}}
        </style>

        <div class="card" style="margin-bottom:8px">
          <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:4px"><a href="/exam-builder?exam_id=${escapeAttr(examId)}&pane=results">← Back to Results</a></div>
          <div style="display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <h1 style="margin:0">${viewOnly ? "View Submission" : "Grade Submission"}</h1>
            <span class="muted small">${escapeHtml(exam.title)}</span>
          </div>
        </div>

        ${viewOnly ? `<div style="background:#e8f4fd;border:1px solid #90caf9;border-radius:10px;padding:10px 14px;margin-bottom:8px;font-size:13px;color:#1565c0;font-weight:600">This attempt is fully graded — view only</div>` : ""}

        <div class="gl">
          <div>
            <div class="card" style="margin-bottom:8px">
              <div class="row" style="margin-bottom:12px">
                <div><div class="muted small" style="margin-bottom:2px">Student</div><div style="font-weight:600">${escapeHtml(attempt.student_name)}</div></div>
                <div><div class="muted small" style="margin-bottom:2px">Attempt</div><div>#${attempt.attempt_no}</div></div>
                <div><div class="muted small" style="margin-bottom:2px">Submitted</div><div>${attempt.submitted_at ? fmtISO(attempt.submitted_at) : "—"}</div></div>
                <div><div class="muted small" style="margin-bottom:2px">Time taken</div><div>${fmtSecs(attempt.time_taken_secs)}</div></div>
              </div>
              <div style="background:#f6f8f7;border-radius:10px;padding:10px 14px;display:flex;align-items:center;gap:10px">
                <span class="muted small">Score</span>
                <span id="live-score" style="font-weight:700;font-size:16px">${initialScore} / ${scoreTotalAll} marks (${initPct}%)</span>
              </div>
            </div>
            ${formWrap}
          </div>

          <div class="card gl-side">
            <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:rgba(0,0,0,.4);margin-bottom:8px">${viewOnly ? "Manual Questions" : "Needs Grading"}</div>
            <div id="sb-items">${sidebarItems}</div>
            <div id="sidebar-done" style="${allDoneInit ? "" : "display:none;"}font-size:13px;color:#0b7a75;font-weight:600">✅ All questions graded</div>
            <div id="sidebar-none" style="${noManualInit ? "" : "display:none;"}font-size:13px;color:rgba(0,0,0,.45)">No manual grading required</div>
          </div>
        </div>

        ${manualQs.length > 0 ? `
        <button id="mob-fab" onclick="openDrawer()">${viewOnly ? "📋 Manual Questions" : (ungradedManual.length > 0 ? `📋 Needs Grading (${ungradedManual.length})` : "✅ All Graded")}</button>
        <div id="mob-ov" onclick="closeDrawer()"></div>
        <div id="mob-dr">
          <div style="font-size:14px;font-weight:700;margin-bottom:10px">${viewOnly ? "Manual Questions" : "Needs Grading"}</div>
          <div id="dr-items">${sidebarItems}</div>
          <div id="dr-done" style="${allDoneInit ? "" : "display:none;"}font-size:13px;color:#0b7a75;font-weight:600;margin:8px 0">✅ All questions graded</div>
          <button class="btn3" style="margin-top:12px;width:100%" onclick="closeDrawer()">Close</button>
        </div>` : ""}

        <script>
          const BASE_SCORE  = ${baseScore};
          const SCORE_TOTAL = ${scoreTotalAll};
          const IS_VIEW     = ${viewOnly};

          function getLiveScore() {
            let s = BASE_SCORE;
            document.querySelectorAll('.manual-score-input').forEach(el => {
              const v = parseFloat(el.value); if (!isNaN(v)) s += v;
            });
            return Math.round(s * 100) / 100;
          }

          function refreshScoreDisplay() {
            const s = getLiveScore();
            const pct = SCORE_TOTAL > 0 ? Math.round(s / SCORE_TOTAL * 10000) / 100 : 0;
            document.getElementById('live-score').textContent = s + ' / ' + SCORE_TOTAL + ' marks (' + pct + '%)';
          }

          function refreshSidebar(qId, hasScore) {
            if (IS_VIEW) return;
            for (const cid of ['sb-items', 'dr-items']) {
              const c = document.getElementById(cid);
              if (!c) continue;
              const el = c.querySelector('[data-sidebar-q="' + qId + '"]');
              if (el) el.style.display = hasScore ? 'none' : '';
            }
            const sbItems = document.getElementById('sb-items');
            let rem = 0;
            if (sbItems) sbItems.querySelectorAll('[data-sidebar-q]').forEach(el => {
              if (el.style.display !== 'none') rem++;
            });
            const done = rem === 0;
            for (const id of ['sidebar-done', 'dr-done']) {
              const el = document.getElementById(id); if (el) el.style.display = done ? '' : 'none';
            }
            updateFab(rem);
          }

          function updateFab(rem) {
            const fab = document.getElementById('mob-fab'); if (!fab || IS_VIEW) return;
            fab.textContent = rem === 0 ? '\u2705 All Graded' : '\uD83D\uDCCB Needs Grading (' + rem + ')';
          }

          function onScoreInput(qId, inp) {
            refreshSidebar(qId, inp.value.trim() !== '');
            refreshScoreDisplay();
          }

          function scrollToQ(id) {
            const el = document.getElementById('q-' + id);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            closeDrawer();
          }

          function openDrawer() {
            document.getElementById('mob-ov').style.display = 'block';
            document.getElementById('mob-dr').style.transform = 'translateY(0)';
          }

          function closeDrawer() {
            const ov = document.getElementById('mob-ov'), dr = document.getElementById('mob-dr');
            if (ov) ov.style.display = 'none';
            if (dr) dr.style.transform = 'translateY(100%)';
          }
        </script>
      `);
    }

    // =============================
    // Exam: grade submission (POST)
    // =============================
    if (path === "/exam-grade" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const attemptId = (f.attempt_id || "").trim();
      const examId = (f.exam_id || "").trim();
      if (!attemptId || !examId) return redirect("/teacher");

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const attempt = await first(
        `SELECT id FROM exam_attempts WHERE id=? AND exam_id=? AND tenant_id=? AND status='SUBMITTED'`,
        [attemptId, examId, active.tenant_id]
      );
      if (!attempt) return redirect(`/exam-builder?exam_id=${examId}&pane=results`);

      const manualQuestions = await all(
        `SELECT id, marks FROM exam_questions
         WHERE exam_id=? AND tenant_id=? AND (question_type='SHORT_ANSWER' OR question_type='ESSAY')`,
        [examId, active.tenant_id]
      );

      const ts = nowISO();
      for (const q of manualQuestions) {
        const scoreStr = (f[`score_${q.id}`] || "").trim();
        if (scoreStr === "") continue;
        const score = Math.max(0, Math.min(Number(q.marks), parseFloat(scoreStr) || 0));
        const note = (f[`note_${q.id}`] || "").trim() || null;
        await run(
          `UPDATE exam_answers SET score_awarded=?, teacher_note=?, graded_by=?, graded_at=?, updated_at=?
           WHERE attempt_id=? AND question_id=?`,
          [score, note, r.user.id, ts, ts, attemptId, q.id]
        );
      }

      await recalcAttempt(attemptId, active.tenant_id, env.DB);
      return redirect(`/exam-builder?exam_id=${examId}&pane=results`);
    }

    // =============================
    // Exam: export results CSV (GET)
    // =============================
    if (path === "/exam-results-csv" && request.method === "GET") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const examId = url.searchParams.get("exam_id") || "";
      if (!examId) return redirect("/teacher");

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const customFieldDefs = await all(
        `SELECT id, field_label FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );

      const attempts = await all(
        `SELECT ea.id, u.name AS student_name, ea.attempt_no, ea.grading_status,
                ea.score_raw, ea.score_total, ea.score_pct, ea.grade,
                ea.pass_mark_percent, ea.time_taken_secs, ea.submitted_at, ea.custom_fields_json
         FROM exam_attempts ea
         JOIN users u ON u.id = ea.user_id
         WHERE ea.exam_id=? AND ea.tenant_id=? AND ea.status='SUBMITTED'
         ORDER BY u.name ASC, ea.attempt_no ASC`,
        [examId, active.tenant_id]
      );

      const csvEsc = (v) => {
        const s = v === null || v === undefined ? "" : String(v);
        if (s.includes(",") || s.includes('"') || s.includes("\n")) return '"' + s.replaceAll('"', '""') + '"';
        return s;
      };

      const fmtSecsCsv = (secs) => {
        if (secs === null || secs === undefined) return "";
        const s = Number(secs);
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${sec}s`;
        return `${sec}s`;
      };

      const hasAttemptNo = Number(exam.max_attempts) > 1;
      const hasPassFail = exam.pass_mark_percent !== null && exam.pass_mark_percent !== undefined;

      const headers = [
        "Student Name",
        ...customFieldDefs.map((cf) => cf.field_label),
        ...(hasAttemptNo ? ["Attempt #"] : []),
        "Grading Status",
        "Score",
        "Total",
        "%",
        "Grade",
        ...(hasPassFail ? ["Pass/Fail"] : []),
        "Time Taken",
        "Submitted At",
      ];

      const rows = attempts.map((a) => {
        let cfData = {};
        try { cfData = JSON.parse(a.custom_fields_json || "{}"); } catch(e) {}
        const passed = hasPassFail && a.score_pct !== null && a.score_pct !== undefined
          ? (Number(a.score_pct) >= Number(a.pass_mark_percent) ? "Pass" : "Fail")
          : "";
        return [
          a.student_name,
          ...customFieldDefs.map((cf) => cfData[cf.id] || ""),
          ...(hasAttemptNo ? [a.attempt_no] : []),
          a.grading_status === "AUTO_GRADED" ? "Needs Grading" : "Fully Graded",
          a.score_raw !== null && a.score_raw !== undefined ? Number(a.score_raw) : "",
          a.score_total !== null && a.score_total !== undefined ? Number(a.score_total) : "",
          a.score_pct !== null && a.score_pct !== undefined ? Number(a.score_pct) : "",
          a.grade || "",
          ...(hasPassFail ? [passed] : []),
          fmtSecsCsv(a.time_taken_secs),
          a.submitted_at ? fmtISO(a.submitted_at) : "",
        ].map(csvEsc).join(",");
      });

      const csv = [headers.map(csvEsc).join(","), ...rows].join("\n");
      const safeTitle = (exam.title || "results").replace(/[^a-z0-9-]/gi, "_").slice(0, 50);
      return new Response(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${safeTitle}-${examId.slice(0, 8)}.csv"`,
        },
      });
    }

    // =============================
    // Exam: save settings (POST)
    // =============================
    if (path === "/exam-save-settings" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      if (!examId) return redirect("/teacher");

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const ts = nowISO();
      const startsAt = f.starts_at ? new Date(f.starts_at).toISOString() : null;
      const endsAt = f.ends_at ? new Date(f.ends_at).toISOString() : null;

      await run(
        `UPDATE exams SET
          title=?, description=?, duration_mins=?, max_attempts=?,
          starts_at=?, ends_at=?, late_submission_policy=?,
          exam_password=?,
          shuffle_questions=?, shuffle_options=?, show_marks_during=?,
          allow_review=?, navigation_mode=?,
          results_release_policy=?, score_display=?, pass_mark_percent=?,
          updated_at=?
         WHERE id=? AND tenant_id=?`,
        [
          (f.title || "").trim(),
          (f.description || "").trim() || null,
          Math.max(1, parseInt(f.duration_mins || "60", 10)),
          Math.max(1, parseInt(f.max_attempts || "1", 10)),
          startsAt, endsAt,
          endsAt ? (f.late_submission_policy || "HARD_CUT") : null,
          (f.exam_password || "").trim() || null,
          f.shuffle_questions === "1" ? 1 : 0,
          f.shuffle_options === "1" ? 1 : 0,
          f.show_marks_during === "1" ? 1 : 0,
          f.allow_review === "1" ? 1 : 0,
          f.navigation_mode || "FREE",
          f.results_release_policy || "MANUAL",
          f.score_display || "BOTH",
          f.pass_mark_percent ? parseFloat(f.pass_mark_percent) : null,
          ts, examId, active.tenant_id,
        ]
      );

      // Grade bands — delete and reinsert
      await run(`DELETE FROM exam_grade_bands WHERE exam_id=?`, [examId]);
      const bandLabels = [].concat(f["band_label[]"] || []);
      const bandMins = [].concat(f["band_min[]"] || []);
      for (let i = 0; i < bandLabels.length; i++) {
        const label = (bandLabels[i] || "").trim();
        const minPct = parseFloat(bandMins[i]);
        if (label && !Number.isNaN(minPct)) {
          await run(
            `INSERT INTO exam_grade_bands (id,exam_id,label,min_percent,created_at) VALUES (?,?,?,?,?)`,
            [uuid(), examId, label, minPct, ts]
          );
        }
      }

      // Custom fields — delete and reinsert
      await run(`DELETE FROM exam_custom_fields WHERE exam_id=?`, [examId]);
      const cfLabels = [].concat(f["cf_label[]"] || []);
      const cfTypes = [].concat(f["cf_type[]"] || []);
      const cfOptions = [].concat(f["cf_options[]"] || []);
      const cfRequired = [].concat(f["cf_required[]"] || []);
      for (let i = 0; i < cfLabels.length; i++) {
        const label = (cfLabels[i] || "").trim();
        const type = cfTypes[i] || "TEXT";
        if (label) {
          await run(
            `INSERT INTO exam_custom_fields (id,exam_id,field_label,field_type,field_options,is_required,sort_order,created_at)
             VALUES (?,?,?,?,?,?,?,?)`,
            [
              uuid(), examId, label, type,
              type === "DROPDOWN" ? (cfOptions[i] || "").trim() || null : null,
              cfRequired[i] === "1" ? 1 : 0,
              i, ts,
            ]
          );
        }
      }

      return redirect(`/exam-builder?exam_id=${examId}`);
    }

    // =============================
    // Exam: add question (POST)
    // =============================
    if (path === "/exam-add-question" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const qType = (f.question_type || "MCQ").trim();
      const qText = (f.question_text || "").trim();
      const marks = Math.max(0.5, parseFloat(f.marks || "1") || 1);
      const feedback = (f.feedback || "").trim() || null;
      const modelAnswer = qType === "SHORT_ANSWER" ? (f.model_answer || "").trim() || null : null;
      const partialMarking = qType === "MULTIPLE_SELECT" ? (f.partial_marking === "1" ? 1 : 0) : 0;
      if (!qText) return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);

      const ts = nowISO();
      const maxOrder = await first(`SELECT MAX(sort_order) AS m FROM exam_questions WHERE exam_id=?`, [examId]);
      const sortOrder = (Number(maxOrder?.m) || 0) + 1;

      // Auto-save to question bank (PERSONAL)
      const bankId = await saveToBank(null, active.tenant_id, r.user.id, qType, qText, marks, partialMarking, modelAnswer, feedback, f, ts);

      const qId = uuid();
      await run(
        `INSERT INTO exam_questions
         (id,exam_id,tenant_id,question_type,question_text,marks,sort_order,partial_marking,model_answer,feedback,bank_question_id,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [qId, examId, active.tenant_id, qType, qText, marks, sortOrder, partialMarking, modelAnswer, feedback, bankId, ts, ts]
      );

      await saveQuestionOptions(qId, qType, f, ts);
      return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);
    }

    // =============================
    // Exam: update question (POST)
    // =============================
    if (path === "/exam-update-question" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const qId = (f.question_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam || !qId) return redirect("/teacher");

      const qType = (f.question_type || "MCQ").trim();
      const qText = (f.question_text || "").trim();
      const marks = Math.max(0.5, parseFloat(f.marks || "1") || 1);
      const feedback = (f.feedback || "").trim() || null;
      const modelAnswer = qType === "SHORT_ANSWER" ? (f.model_answer || "").trim() || null : null;
      const partialMarking = qType === "MULTIPLE_SELECT" ? (f.partial_marking === "1" ? 1 : 0) : 0;
      if (!qText) return redirect(`/exam-builder?exam_id=${examId}&edit_q=${qId}&pane=questions`);

      const ts = nowISO();

      // Get existing question to find bank_question_id
      const existingQ = await first(`SELECT bank_question_id FROM exam_questions WHERE id=? AND exam_id=?`, [qId, examId]);

      // If exam is DRAFT, sync back to bank
      let bankId = existingQ?.bank_question_id || null;
      if (exam.status === "DRAFT") {
        bankId = await saveToBank(bankId, active.tenant_id, r.user.id, qType, qText, marks, partialMarking, modelAnswer, feedback, f, ts);
      }

      await run(
        `UPDATE exam_questions SET
          question_type=?, question_text=?, marks=?, partial_marking=?,
          model_answer=?, feedback=?, bank_question_id=?, updated_at=?
         WHERE id=? AND exam_id=?`,
        [qType, qText, marks, partialMarking, modelAnswer, feedback, bankId, ts, qId, examId]
      );

      await run(`DELETE FROM exam_question_options WHERE question_id=?`, [qId]);
      await saveQuestionOptions(qId, qType, f, ts);
      return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);
    }

    // =============================
    // Exam: delete question (POST)
    // =============================
    if (path === "/exam-delete-question" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const qId = (f.question_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam || !qId) return redirect("/teacher");

      await run(`DELETE FROM exam_question_options WHERE question_id=?`, [qId]);
      await run(`DELETE FROM exam_questions WHERE id=? AND exam_id=?`, [qId, examId]);

      // Renumber
      const remaining = await all(`SELECT id FROM exam_questions WHERE exam_id=? ORDER BY sort_order ASC`, [examId]);
      for (let i = 0; i < remaining.length; i++) {
        await run(`UPDATE exam_questions SET sort_order=? WHERE id=?`, [i + 1, remaining[i].id]);
      }
      return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);
    }

    // =============================
    // Exam: reorder question (POST)
    // =============================
    if (path === "/exam-reorder-question" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const qId = (f.question_id || "").trim();
      const direction = (f.direction || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam || !qId) return redirect("/teacher");

      const questions = await all(`SELECT id, sort_order FROM exam_questions WHERE exam_id=? ORDER BY sort_order ASC`, [examId]);
      const idx = questions.findIndex((q) => q.id === qId);
      if (idx < 0) return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);

      const swapIdx = direction === "up" ? idx - 1 : idx + 1;
      if (swapIdx < 0 || swapIdx >= questions.length) return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);

      const ts = nowISO();
      const a = questions[idx];
      const b = questions[swapIdx];
      await run(`UPDATE exam_questions SET sort_order=?, updated_at=? WHERE id=?`, [b.sort_order, ts, a.id]);
      await run(`UPDATE exam_questions SET sort_order=?, updated_at=? WHERE id=?`, [a.sort_order, ts, b.id]);
      return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);
    }

    // =============================
    // Bank picker — browse and select questions to add to exam
    // =============================
    if (path === "/exam-bank-picker") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const examId = url.searchParams.get("exam_id") || "";
      if (!examId) return redirect("/teacher");

      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const filterType = url.searchParams.get("type") || "";
      const filterVis = url.searchParams.get("vis") || "";
      const pickerError = url.searchParams.get("error") || "";

      let whereClause = `WHERE qb.tenant_id=? AND (qb.created_by=? OR qb.visibility='SCHOOL')`;
      const params = [active.tenant_id, r.user.id];

      if (filterType) { whereClause += ` AND qb.question_type=?`; params.push(filterType); }
      if (filterVis === "PERSONAL") { whereClause += ` AND qb.created_by=? AND qb.visibility='PERSONAL'`; params.push(r.user.id); }
      else if (filterVis === "SCHOOL") { whereClause += ` AND qb.visibility='SCHOOL'`; }

      const bankQuestions = await all(
        `SELECT qb.id, qb.question_type, qb.question_text, qb.marks, qb.visibility, qb.created_by,
                u.name AS creator_name
         FROM question_bank qb
         JOIN users u ON u.id = qb.created_by
         ${whereClause}
         ORDER BY qb.updated_at DESC`,
        params
      );

      // Get options for all bank questions
      const bankOptions = bankQuestions.length > 0 ? await all(
        `SELECT bank_question_id AS question_id, option_text, is_correct FROM question_bank_options
         WHERE bank_question_id IN (${bankQuestions.map(() => "?").join(",")})
         ORDER BY sort_order ASC`,
        bankQuestions.map((q) => q.id)
      ) : [];

      const optsByQ = {};
      for (const o of bankOptions) {
        if (!optsByQ[o.question_id]) optsByQ[o.question_id] = [];
        optsByQ[o.question_id].push(o);
      }

      const typeFilter = `
        <select name="type" onchange="applyFilters()" id="f-type">
          <option value="">All types</option>
          <option value="MCQ" ${filterType === "MCQ" ? "selected" : ""}>MCQ</option>
          <option value="MULTIPLE_SELECT" ${filterType === "MULTIPLE_SELECT" ? "selected" : ""}>Multi-select</option>
          <option value="TRUE_FALSE" ${filterType === "TRUE_FALSE" ? "selected" : ""}>True / False</option>
          <option value="SHORT_ANSWER" ${filterType === "SHORT_ANSWER" ? "selected" : ""}>Short Answer</option>
          <option value="ESSAY" ${filterType === "ESSAY" ? "selected" : ""}>Essay</option>
        </select>
      `;

      const visFilter = `
        <select name="vis" onchange="applyFilters()" id="f-vis">
          <option value="">All visibility</option>
          <option value="PERSONAL" ${filterVis === "PERSONAL" ? "selected" : ""}>My questions only</option>
          <option value="SCHOOL" ${filterVis === "SCHOOL" ? "selected" : ""}>School questions</option>
        </select>
      `;

      const questionCards = bankQuestions.map((q) => {
        const opts = optsByQ[q.id] || [];
        const preview = opts.length > 0
          ? opts.map((o) => `<span style="display:inline-block;padding:2px 7px;border-radius:5px;margin:2px;font-size:11px;background:${Number(o.is_correct) ? "rgba(11,122,117,.12);color:#0b7a75" : "rgba(0,0,0,.06);color:#555"}">${escapeHtml(o.option_text)}</span>`).join("")
          : "";
        const isMine = q.created_by === r.user.id;

        return `
          <div class="card" style="margin:6px 0">
            <div style="display:flex;gap:10px;align-items:flex-start">
              <div style="flex:1;min-width:0">
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">
                  <span class="pill" style="font-size:11px">${escapeHtml(qTypeLabel(q.question_type))}</span>
                  <span class="muted small">${escapeHtml(String(q.marks))} mark${Number(q.marks) !== 1 ? "s" : ""}</span>
                  <span class="pill" style="font-size:10px;background:${q.visibility === "SCHOOL" ? "rgba(11,122,117,.08)" : "rgba(0,0,0,.05)"};color:${q.visibility === "SCHOOL" ? "#0b7a75" : "#666"}">${q.visibility === "SCHOOL" ? "School" : "Personal"}</span>
                  ${!isMine ? `<span class="muted small">by ${escapeHtml(q.creator_name)}</span>` : ""}
                </div>
                <div style="font-size:14px;margin-bottom:4px">${escapeHtml(q.question_text)}</div>
                <div>${preview}</div>
              </div>
              <form method="post" action="/exam-add-from-bank" style="flex-shrink:0">
                <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />
                <input type="hidden" name="bank_question_id" value="${escapeAttr(q.id)}" />
                <button class="btn2" type="submit" style="padding:6px 12px;font-size:13px">+ Add</button>
              </form>
            </div>
          </div>
        `;
      }).join("");

      return page(`
        <div class="card">
          <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:4px">
            <a href="/exam-builder?exam_id=${escapeAttr(examId)}&pane=questions">← Back to exam</a>
          </div>
          <h1 style="margin:0 0 4px">Add from Question Bank</h1>
          <div class="muted small">Exam: ${escapeHtml(exam.title)}</div>
        </div>

        <div class="card">
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
            <div style="flex:1;min-width:140px">
              <label>Filter by type</label>
              ${typeFilter}
            </div>
            <div style="flex:1;min-width:140px">
              <label>Filter by visibility</label>
              ${visFilter}
            </div>
          </div>
        </div>

        ${pickerError === "duplicate" ? `<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:10px 14px;margin-bottom:8px;color:#856404;font-size:13px">This question is already in the exam.</div>` : ""}
        <div class="muted small" style="margin:4px 0 8px;padding:0 4px">${bankQuestions.length} question${bankQuestions.length !== 1 ? "s" : ""} found</div>

        ${bankQuestions.length > 0 ? questionCards : `
          <div class="card" style="text-align:center;padding:32px">
            <p class="muted">No questions found. <a href="/question-bank">Go to Question Bank</a> to create some.</p>
          </div>
        `}

        <script>
          function applyFilters() {
            const type = document.getElementById('f-type').value;
            const vis = document.getElementById('f-vis').value;
            const params = new URLSearchParams();
            params.set('exam_id', '${escapeAttr(examId)}');
            if (type) params.set('type', type);
            if (vis) params.set('vis', vis);
            window.location.href = '/exam-bank-picker?' + params.toString();
          }
        </script>
      `);
    }

    // =============================
    // Add from bank (POST)
    // =============================
    if (path === "/exam-add-from-bank" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const bankQId = (f.bank_question_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam || !bankQId) return redirect("/teacher");

      // Load bank question (must be visible to this teacher)
      const bq = await first(
        `SELECT * FROM question_bank WHERE id=? AND tenant_id=? AND (created_by=? OR visibility='SCHOOL')`,
        [bankQId, active.tenant_id, r.user.id]
      );
      if (!bq) return redirect(`/exam-bank-picker?exam_id=${examId}`);

      const bankOpts = await all(
        `SELECT option_text, is_correct, feedback, sort_order FROM question_bank_options WHERE bank_question_id=? ORDER BY sort_order ASC`,
        [bankQId]
      );

      const existing = await first(
        `SELECT 1 AS x FROM exam_questions WHERE exam_id=? AND bank_question_id=? LIMIT 1`,
        [examId, bankQId]
      );
      if (existing) return redirect(`/exam-bank-picker?exam_id=${examId}&error=duplicate`);

      const ts = nowISO();
      const maxOrder = await first(`SELECT MAX(sort_order) AS m FROM exam_questions WHERE exam_id=?`, [examId]);
      const sortOrder = (Number(maxOrder?.m) || 0) + 1;

      const qId = uuid();
      await run(
        `INSERT INTO exam_questions
         (id,exam_id,tenant_id,question_type,question_text,marks,sort_order,partial_marking,model_answer,feedback,bank_question_id,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [qId, examId, active.tenant_id, bq.question_type, bq.question_text, bq.marks, sortOrder,
         bq.partial_marking, bq.model_answer, bq.feedback, bankQId, ts, ts]
      );

      // Copy options from bank to exam question
      for (const o of bankOpts) {
        await run(
          `INSERT INTO exam_question_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), qId, o.option_text, o.is_correct, o.feedback, o.sort_order, ts]
        );
      }

      return redirect(`/exam-builder?exam_id=${examId}&pane=questions`);
    }

    // =============================
    // Publish exam (POST)
    // =============================
    if (path === "/exam-publish" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const qCount = await first(`SELECT COUNT(*) AS c FROM exam_questions WHERE exam_id=?`, [examId]);
      if (!qCount || Number(qCount.c) === 0) return redirect(`/exam-builder?exam_id=${examId}&pane=publish`);

      const ts = nowISO();
      const releaseOnPublish = exam.results_release_policy === "IMMEDIATE";
      await run(
        `UPDATE exams SET status='PUBLISHED', published_at=?, published_by=?, updated_at=?${releaseOnPublish ? ", results_published_at=?" : ""} WHERE id=?`,
        releaseOnPublish ? [ts, r.user.id, ts, ts, examId] : [ts, r.user.id, ts, examId]
      );
      return redirect(`/exam-builder?exam_id=${examId}&pane=publish`);
    }

    // =============================
    // Close exam (POST)
    // =============================
    if (path === "/exam-close" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const ts = nowISO();
      const releaseOnClose = exam.results_release_policy === "AFTER_CLOSE";
      const cols = await all(`PRAGMA table_info(exams)`, []);
      const hasClosedAt = cols.some((c) => c.name === "closed_at");
      if (hasClosedAt) {
        await run(
          `UPDATE exams SET status='CLOSED', closed_at=?, updated_at=?${releaseOnClose ? ", results_published_at=?" : ""} WHERE id=?`,
          releaseOnClose ? [ts, ts, ts, examId] : [ts, ts, examId]
        );
      } else {
        await run(
          `UPDATE exams SET status='CLOSED', updated_at=?${releaseOnClose ? ", results_published_at=?" : ""} WHERE id=?`,
          releaseOnClose ? [ts, ts, examId] : [ts, examId]
        );
      }
      return redirect(`/exam-builder?exam_id=${examId}&pane=publish`);
    }

    // =============================
    // Release results (POST)
    // =============================
    if (path === "/exam-release-results" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");

      const ts = nowISO();
      await run(
        `UPDATE exams SET results_published_at=?, updated_at=? WHERE id=?`,
        [ts, ts, examId]
      );
      return redirect(`/exam-builder?exam_id=${examId}&pane=publish`);
    }

    // =============================
    // Access: add students from a class (POST)
    // =============================
    if (path === "/exam-access-add-class" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const classId = (f.class_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");
      if (exam.status === "CLOSED") return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      const cls = await first(`SELECT id FROM classes WHERE id=? AND tenant_id=?`, [classId, active.tenant_id]);
      if (!cls) return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      const toAdd = await all(
        `SELECT cs.user_id FROM class_students cs
         WHERE cs.class_id=?
         AND cs.user_id NOT IN (SELECT user_id FROM exam_access WHERE exam_id=?)`,
        [classId, examId]
      );

      const ts = nowISO();
      for (const row of toAdd) {
        await run(
          `INSERT INTO exam_access (id, exam_id, user_id, added_by, created_at) VALUES (?, ?, ?, ?, ?)`,
          [uuid(), examId, row.user_id, r.user.id, ts]
        );
      }

      return redirect(`/exam-builder?exam_id=${examId}&pane=access`);
    }

    // =============================
    // Access: add students from course enrollment (POST)
    // =============================
    if (path === "/exam-access-add-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");
      if (exam.status === "CLOSED") return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      const toAdd = await all(
        `SELECT e.user_id FROM enrollments e
         WHERE e.course_id=?
         AND e.user_id NOT IN (SELECT user_id FROM exam_access WHERE exam_id=?)`,
        [exam.course_id, examId]
      );

      const ts = nowISO();
      for (const row of toAdd) {
        await run(
          `INSERT INTO exam_access (id, exam_id, user_id, added_by, created_at) VALUES (?, ?, ?, ?, ?)`,
          [uuid(), examId, row.user_id, r.user.id, ts]
        );
      }

      return redirect(`/exam-builder?exam_id=${examId}&pane=access`);
    }

    // =============================
    // Access: add individual student (POST)
    // =============================
    if (path === "/exam-access-add-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const userId = (f.user_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");
      if (exam.status === "CLOSED") return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      const member = await first(
        `SELECT 1 AS x FROM memberships WHERE user_id=? AND tenant_id=? AND role='STUDENT' AND status='ACTIVE' LIMIT 1`,
        [userId, active.tenant_id]
      );
      if (!member) return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      const already = await first(
        `SELECT 1 AS x FROM exam_access WHERE exam_id=? AND user_id=? LIMIT 1`,
        [examId, userId]
      );
      if (!already) {
        const ts = nowISO();
        await run(
          `INSERT INTO exam_access (id, exam_id, user_id, added_by, created_at) VALUES (?, ?, ?, ?, ?)`,
          [uuid(), examId, userId, r.user.id, ts]
        );
      }

      return redirect(`/exam-builder?exam_id=${examId}&pane=access`);
    }

    // =============================
    // Access: remove student (POST)
    // =============================
    if (path === "/exam-access-remove" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const examId = (f.exam_id || "").trim();
      const accessId = (f.access_id || "").trim();
      const exam = await verifyExamAccess(examId, active.tenant_id, r.user.id, active.role);
      if (!exam) return redirect("/teacher");
      if (exam.status === "CLOSED") return redirect(`/exam-builder?exam_id=${examId}&pane=access`);

      await run(
        `DELETE FROM exam_access WHERE id=? AND exam_id=?`,
        [accessId, examId]
      );

      return redirect(`/exam-builder?exam_id=${examId}&pane=access`);
    }

  } catch (err) {
    console.error("FATAL [exams]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (exams):\n\n" + msg, { status: 500 });
  }
}
