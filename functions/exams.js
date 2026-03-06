// functions/exams.js
// All exam builder routes
// /exam-create, /exam-builder, /exam-save-settings
// (Questions, Publish, Access, Results panes will be added here)

import { createHelpers } from "./shared.js";

export async function handleExamRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    const {
      nowISO, uuid,
      page, redirect, escapeHtml, escapeAttr, roleLabel, fmtISO, form,
      first, all, run,
      requireLogin, pickActiveMembership,
    } = createHelpers(request, env);

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

      // Verify teacher is assigned to this course
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
        `INSERT INTO exams
         (id, tenant_id, course_id, created_by, title, status, created_at, updated_at)
         VALUES (?,?,?,?,?,'DRAFT',?,?)`,
        [examId, active.tenant_id, courseId, r.user.id, title, ts, ts]
      );

      return redirect(`/exam-builder?exam_id=${examId}`);
    }

    // =============================
    // Exam Builder — Settings pane
    // =============================
    if (path === "/exam-builder") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const examId = url.searchParams.get("exam_id") || "";
      if (!examId) return redirect("/teacher");

      const exam = await first(
        `SELECT * FROM exams WHERE id=? AND tenant_id=?`,
        [examId, active.tenant_id]
      );
      if (!exam) return redirect("/teacher");

      // Verify teacher owns this exam (or is school admin)
      if (active.role === "TEACHER") {
        const owns = await first(
          `SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1`,
          [exam.course_id, r.user.id]
        );
        if (!owns) return redirect("/teacher");
      }

      // Load questions + their options
      const questions = await all(
        `SELECT id, question_type, question_text, marks, sort_order, partial_marking, model_answer, feedback
         FROM exam_questions WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );

      // Load all options for all questions in one query
      const allOptions = questions.length > 0 ? await all(
        `SELECT id, question_id, option_text, is_correct, feedback, sort_order
         FROM exam_question_options
         WHERE question_id IN (${questions.map(() => "?").join(",")})
         ORDER BY sort_order ASC`,
        questions.map(q => q.id)
      ) : [];

      // Group options by question_id for easy lookup
      const optionsByQuestion = {};
      for (const o of allOptions) {
        if (!optionsByQuestion[o.question_id]) optionsByQuestion[o.question_id] = [];
        optionsByQuestion[o.question_id].push(o);
      }

      // Total marks across all questions
      const totalMarks = questions.reduce((sum, q) => sum + Number(q.marks || 0), 0);

      // Build question list rows
      const qTypeLabel = (t) => {
        if (t === "MCQ") return "MCQ";
        if (t === "MULTIPLE_SELECT") return "Multi-select";
        if (t === "TRUE_FALSE") return "True / False";
        if (t === "SHORT_ANSWER") return "Short Answer";
        if (t === "ESSAY") return "Essay";
        return t;
      };

      const questionRows = questions.map((q, i) => {
        const opts = optionsByQuestion[q.id] || [];
        const correctOpts = opts.filter(o => Number(o.is_correct) === 1);
        const preview = opts.length > 0
          ? opts.map(o => `<span style="display:inline-block;padding:2px 8px;border-radius:6px;margin:2px;font-size:11px;background:${Number(o.is_correct) ? "rgba(11,122,117,.12);color:#0b7a75" : "rgba(0,0,0,.06);color:#555"}">${escapeHtml(o.option_text)}</span>`).join("")
          : q.model_answer ? `<span class="muted small">Model answer set</span>` : "";

        return `
          <div class="q-row" data-id="${escapeAttr(q.id)}">
            <div style="display:flex;gap:10px;align-items:flex-start">
              <div style="min-width:28px;text-align:center;padding-top:2px">
                <div style="font-weight:700;font-size:15px;color:#0b7a75">${i + 1}</div>
                <div class="muted small">${escapeHtml(String(q.marks))}m</div>
              </div>
              <div style="flex:1;min-width:0">
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px">
                  <span class="pill" style="font-size:11px">${escapeHtml(qTypeLabel(q.question_type))}</span>
                  ${q.question_type === "MULTIPLE_SELECT" ? `<span class="muted small">${Number(q.partial_marking) ? "Partial marks" : "All-or-nothing"}</span>` : ""}
                </div>
                <div style="font-size:14px;margin-bottom:6px">${escapeHtml(q.question_text)}</div>
                <div>${preview}</div>
              </div>
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
                <a href="/exam-builder?exam_id=${escapeAttr(examId)}&edit_q=${escapeAttr(q.id)}#questions" class="btn3" style="font-size:12px;padding:4px 10px;border-radius:8px;display:inline-block">Edit</a>
                <form method="post" action="/exam-delete-question" onsubmit="return confirm('Delete this question?')" style="display:inline">
                  <input type="hidden" name="exam_id" value="${escapeAttr(examId)}"/>
                  <input type="hidden" name="question_id" value="${escapeAttr(q.id)}"/>
                  <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px;color:#c00">Delete</button>
                </form>
              </div>
            </div>
          </div>
        `;
      }).join("");

      // If editing an existing question, load it
      const editQId = url.searchParams.get("edit_q") || "";
      const editQ = editQId ? questions.find(q => q.id === editQId) : null;
      const editOpts = editQ ? (optionsByQuestion[editQ.id] || []) : [];

      // Build options HTML for the add/edit form
      // For MCQ and MULTIPLE_SELECT: show dynamic option rows
      // For TRUE_FALSE: fixed two rows
      // For SHORT_ANSWER / ESSAY: no options

      const buildOptionRows = (type, opts) => {
        if (type === "TRUE_FALSE") {
          const trueCorrect = opts.find(o => o.option_text === "True" && Number(o.is_correct));
          const falseCorrect = opts.find(o => o.option_text === "False" && Number(o.is_correct));
          // Default: neither pre-selected if new question
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
            ? opts.map((o, i) => buildOptionRow(isMulti, o.option_text, Number(o.is_correct), o.feedback, i)).join("")
            : [0,1,2,3].map(i => buildOptionRow(isMulti, "", false, "", i)).join("");
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
        return ""; // SHORT_ANSWER, ESSAY — no options
      };

      const buildOptionRow = (isMulti, text, isCorrect, feedback, idx) => `
        <div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
          <div style="display:flex;gap:8px;align-items:center">
            <input type="${isMulti ? "checkbox" : "radio"}" name="opt_correct[]" value="${idx}" ${isCorrect ? "checked" : ""} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
            <input name="opt_text[]" value="${escapeAttr(text)}" placeholder="Option text" style="flex:1" />
            <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px;flex-shrink:0">✕</button>
          </div>
          <div style="margin-top:6px">
            <input name="opt_feedback[]" value="${escapeAttr(feedback)}" placeholder="Feedback for this option (optional — shown during review)" style="font-size:12px" />
          </div>
        </div>
      `;

      // Determine initial type for the form (editing or default MCQ)
      const formType = editQ ? editQ.question_type : "MCQ";

      // Load grade bands
      const bands = await all(
        `SELECT id, label, min_percent FROM exam_grade_bands WHERE exam_id=? ORDER BY min_percent DESC`,
        [examId]
      );

      // Load custom fields
      const customFields = await all(
        `SELECT id, field_label, field_type, field_options, is_required FROM exam_custom_fields WHERE exam_id=? ORDER BY sort_order ASC`,
        [examId]
      );

      // Build grade band rows HTML
      const bandRows = bands.map((b, i) => `
        <div class="band-row" style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
          <input name="band_label[]" value="${escapeAttr(b.label)}" placeholder="e.g. Distinction" style="flex:2" />
          <input name="band_min[]" type="number" min="0" max="100" value="${escapeAttr(b.min_percent)}" placeholder="Min %" style="flex:1" />
          <button type="button" class="btn3" onclick="this.closest('.band-row').remove()">✕</button>
        </div>
      `).join("");

      // Build custom field rows HTML
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
            <input name="cf_options[]" value="${escapeAttr(cf.field_options || "")}" placeholder="Dropdown options, comma separated e.g. Option A, Option B" style="width:100%" />
          </div>
        </div>
      `).join("");

      const v = (field) => escapeAttr(exam[field] ?? "");
      const checked = (field) => Number(exam[field]) === 1 ? "checked" : "";
      const sel = (field, val) => exam[field] === val ? "selected" : "";

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
        </style>

        <div class="card" style="margin-bottom:0;border-radius:14px 14px 0 0">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/teacher">← My Exams</a></div>
              <h1 style="margin:0">${escapeHtml(exam.title)}</h1>
              <div class="muted" style="margin-top:4px">
                <span class="pill ${exam.status === "PUBLISHED" ? "badge-published" : exam.status === "CLOSED" ? "badge-closed" : "badge-draft"}">${escapeHtml(exam.status)}</span>
                <span class="muted small" style="margin-left:6px">${escapeHtml(active.tenant_name)}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
          <div class="tabs">
            <button class="tab active" onclick="showPane('settings',this)">Settings</button>
            <button class="tab" onclick="showPane('questions',this)">Questions</button>
            <button class="tab" onclick="showPane('publish',this)">Publish</button>
            <button class="tab" onclick="showPane('access',this)">Access</button>
            <button class="tab" onclick="showPane('results',this)">Results</button>
          </div>
        </div>

        <!-- ===== SETTINGS PANE ===== -->
        <div id="pane-settings" class="pane active">
          <form method="post" action="/exam-save-settings">
            <input type="hidden" name="exam_id" value="${escapeAttr(examId)}" />

            <div class="card">
              <div class="section-title">Basic Info</div>

              <label>Exam title</label>
              <input name="title" value="${v("title")}" required />

              <label>Instructions <span class="muted">(shown to student before timer starts — optional)</span></label>
              <textarea name="description" rows="3" style="width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px;font-family:inherit">${escapeHtml(exam.description || "")}</textarea>

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
              <div class="section-title">Schedule <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional — leave blank for no schedule)</span></div>
              <div class="field-row">
                <div>
                  <label>Open at</label>
                  <input name="starts_at" type="datetime-local" value="${v("starts_at") ? v("starts_at").slice(0,16) : ""}" />
                </div>
                <div>
                  <label>Close at</label>
                  <input name="ends_at" type="datetime-local" value="${v("ends_at") ? v("ends_at").slice(0,16) : ""}" id="ends_at_input" />
                </div>
              </div>

              <div id="late-policy-wrap" style="${exam.ends_at ? "" : "display:none"}">
                <label>Late submission policy <span class="muted">(what happens if close_at is reached while a student is mid-exam)</span></label>
                <select name="late_submission_policy">
                  <option value="HARD_CUT" ${sel("late_submission_policy","HARD_CUT")}>Hard cut — submit whatever they have at close time</option>
                  <option value="ALLOW_DURATION" ${sel("late_submission_policy","ALLOW_DURATION")}>Allow full duration — let them finish their personal timer</option>
                </select>
              </div>
            </div>

            <div class="card">
              <div class="section-title">Security</div>
              <label>Exam password <span class="muted">(optional — students must enter this before starting)</span></label>
              <input name="exam_password" type="text" value="${v("exam_password")}" placeholder="Leave blank for no password" autocomplete="off" />
            </div>

            <div class="card">
              <div class="section-title">Exam Behaviour</div>

              <div class="toggle-row">
                <div>
                  <label>Shuffle questions</label>
                  <div class="desc">Each student sees questions in a different random order</div>
                </div>
                <input type="checkbox" name="shuffle_questions" value="1" ${checked("shuffle_questions")} style="width:auto;transform:scale(1.4)" />
              </div>

              <div class="toggle-row">
                <div>
                  <label>Shuffle answer options</label>
                  <div class="desc">For MCQ questions, randomise the order of options</div>
                </div>
                <input type="checkbox" name="shuffle_options" value="1" ${checked("shuffle_options")} style="width:auto;transform:scale(1.4)" />
              </div>

              <div class="toggle-row">
                <div>
                  <label>Show question marks during exam</label>
                  <div class="desc">Students can see how many marks each question is worth</div>
                </div>
                <input type="checkbox" name="show_marks_during" value="1" ${checked("show_marks_during")} style="width:auto;transform:scale(1.4)" />
              </div>

              <div class="toggle-row">
                <div>
                  <label>Allow review after submission</label>
                  <div class="desc">After submitting, students can re-read all questions and see correct answers (controlled by results release policy)</div>
                </div>
                <input type="checkbox" name="allow_review" value="1" ${checked("allow_review")} style="width:auto;transform:scale(1.4)" />
              </div>

              <label style="margin-top:14px">Question navigation</label>
              <select name="navigation_mode">
                <option value="FREE" ${sel("navigation_mode","FREE")}>Free — student can jump between any questions</option>
                <option value="LINEAR" ${sel("navigation_mode","LINEAR")}>Linear — must answer in order, cannot go back</option>
              </select>
            </div>

            <div class="card">
              <div class="section-title">Results & Grading</div>

              <label>Results release policy</label>
              <select name="results_release_policy">
                <option value="IMMEDIATE" ${sel("results_release_policy","IMMEDIATE")}>Immediate — student sees results right after submitting</option>
                <option value="AFTER_CLOSE" ${sel("results_release_policy","AFTER_CLOSE")}>After close — results visible once exam closes for everyone</option>
                <option value="MANUAL" ${sel("results_release_policy","MANUAL") || (!exam.results_release_policy ? "selected" : "")}>Manual — teacher decides when to release results</option>
              </select>

              <label style="margin-top:12px">Score display</label>
              <select name="score_display">
                <option value="BOTH" ${sel("score_display","BOTH")}>Raw score and percentage</option>
                <option value="RAW" ${sel("score_display","RAW")}>Raw score only</option>
                <option value="PERCENT" ${sel("score_display","PERCENT")}>Percentage only</option>
                <option value="PASS_FAIL" ${sel("score_display","PASS_FAIL")}>Pass / Fail only</option>
                <option value="HIDDEN" ${sel("score_display","HIDDEN")}>Hidden — student sees no score</option>
              </select>

              <label style="margin-top:12px">Pass mark (%) <span class="muted">(optional — leave blank to disable)</span></label>
              <input name="pass_mark_percent" type="number" min="0" max="100" value="${v("pass_mark_percent")}" placeholder="e.g. 50" />
            </div>

            <div class="card">
              <div class="section-title">Grade Bands <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional — add grade labels based on score ranges)</span></div>
              <p class="muted small">Example: Distinction = 75%+, Credit = 65%+, Pass = 50%+</p>

              <div id="bands-container">
                ${bandRows}
              </div>
              <button type="button" class="btn3" onclick="addBand()" style="margin-top:4px">+ Add grade band</button>
            </div>

            <div class="card">
              <div class="section-title">Custom Fields <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(optional — students fill these in before starting)</span></div>
              <p class="muted small">Use for things like: Index Number, Seat Number, Do you need help? (Yes/No)</p>

              <div id="cf-container">
                ${cfRows}
              </div>
              <button type="button" class="btn3" onclick="addCustomField()" style="margin-top:4px">+ Add custom field</button>
            </div>

            <div class="save-bar">
              <button type="submit" class="btn2">Save settings</button>
              <span class="muted small" id="save-msg"></span>
            </div>
          </form>
        </div>

        <!-- ===== QUESTIONS PANE ===== -->
        <div id="pane-questions" class="pane${url.searchParams.get("edit_q") ? " active" : ""}">

          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
              <div>
                <h2 style="margin:0">Questions</h2>
                <div class="muted small">${questions.length} question${questions.length !== 1 ? "s" : ""} &nbsp;·&nbsp; ${totalMarks} mark${totalMarks !== 1 ? "s" : ""} total</div>
              </div>
              <a href="/exam-builder?exam_id=${escapeAttr(examId)}#questions" class="btn2" style="display:inline-block;padding:8px 14px;border-radius:10px;color:#fff;text-decoration:none;font-weight:700">+ Add question</a>
            </div>
          </div>

          ${questions.length > 0 ? `
            <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:8px">
              ${questionRows}
            </div>
          ` : `
            <div class="card" style="text-align:center;padding:32px">
              <p class="muted">No questions yet — add your first question below.</p>
            </div>
          `}

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
              <textarea name="question_text" rows="3" style="width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px;font-family:inherit;font-size:14px" required>${escapeHtml(editQ ? editQ.question_text : "")}</textarea>

              <!-- Dynamic section: options / correct answer / model answer -->
              <div id="dynamic-section">
                ${buildOptionRows(formType, editOpts)}
              </div>

              <!-- Question-level feedback (for all types) -->
              <div style="margin-top:12px">
                <label>Question feedback <span class="muted">(optional — explanation shown to student during review)</span></label>
                <textarea name="feedback" rows="2" style="width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px;font-family:inherit;font-size:13px" placeholder="e.g. The correct answer is X because...">${escapeHtml(editQ ? editQ.feedback || "" : "")}</textarea>
              </div>

              <!-- Model answer (SHORT_ANSWER only) -->
              <div id="model-answer-wrap" style="${formType === "SHORT_ANSWER" ? "" : "display:none"}">
                <label>Model answer <span class="muted">(optional — shown to teacher as marking reference)</span></label>
                <input name="model_answer" value="${escapeAttr(editQ ? editQ.model_answer || "" : "")}" placeholder="e.g. Paris" />
              </div>

              <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
                <button type="submit" class="btn2">${editQ ? "Save changes" : "Add question"}</button>
                ${editQ ? `<a href="/exam-builder?exam_id=${escapeAttr(examId)}#questions" class="btn3" style="display:inline-block;padding:8px 12px;border-radius:10px;text-decoration:none">Cancel</a>` : ""}
              </div>
            </form>
          </div>
        </div>
        <div id="pane-publish" class="pane">
          <div class="card"><h2>Publish</h2><p class="muted">Coming soon.</p></div>
        </div>
        <div id="pane-access" class="pane">
          <div class="card"><h2>Access</h2><p class="muted">Coming soon.</p></div>
        </div>
        <div id="pane-results" class="pane">
          <div class="card"><h2>Results</h2><p class="muted">Coming soon.</p></div>
        </div>

        <script>
          // Tab switching
          function showPane(name, btn) {
            document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('pane-' + name).classList.add('active');
            btn.classList.add('active');
          }

          // On load: if edit_q or pane=questions param present, activate questions tab
          (function(){
            const params = new URLSearchParams(location.search);
            if (params.get('edit_q') || params.get('pane') === 'questions') {
              document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
              document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
              document.getElementById('pane-questions').classList.add('active');
              document.querySelectorAll('.tab')[1].classList.add('active');
            }
          })();

          // Show/hide late policy based on close_at
          const endsAtInput = document.getElementById('ends_at_input');
          if (endsAtInput) {
            endsAtInput.addEventListener('change', function() {
              document.getElementById('late-policy-wrap').style.display = this.value ? '' : 'none';
            });
          }

          // Grade band management
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

          // Custom field management
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
                <input name="cf_options[]" placeholder="Dropdown options, comma separated e.g. Option A, Option B" style="width:100%" />
              </div>
            \`;
            document.getElementById('cf-container').appendChild(row);
          }

          function toggleCfOptions(sel) {
            const wrap = sel.closest('.cf-row').querySelector('.cf-options-wrap');
            wrap.style.display = sel.value === 'DROPDOWN' ? '' : 'none';
          }

          // ===== Questions pane JS =====

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
                <div class="section-title" style="margin-top:14px">Answer options <span class="muted" style="font-size:11px;text-transform:none;letter-spacing:0">(tick the correct answer\${isMulti ? 's' : ''})</span></div>
                <div id="options-container">
                  \${[0,1,2,3].map(i => buildOptRow(isMulti, '', false, '', i)).join('')}
                </div>
                <button type="button" class="btn3" onclick="addOptionRow(\${isMulti})" style="margin-top:4px;font-size:12px">+ Add option</button>
                \${isMulti ? \`
                  <div style="margin-top:12px">
                    <label>Partial marking</label>
                    <select name="partial_marking">
                      <option value="1">Partial marks (proportional to correct options)</option>
                      <option value="0">All or nothing (full marks only if all correct)</option>
                    </select>
                  </div>\` : ''}
              \`;
            } else {
              // SHORT_ANSWER, ESSAY — no options
              section.innerHTML = '';
            }
          }

          function buildOptRow(isMulti, text, isCorrect, feedback, idx) {
            return \`<div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
              <div style="display:flex;gap:8px;align-items:center">
                <input type="\${isMulti ? 'checkbox' : 'radio'}" name="opt_correct[]" value="\${idx}" \${isCorrect ? 'checked' : ''} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
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
            container.insertAdjacentHTML('beforeend', buildOptRow(isMulti, '', false, '', idx));
          }
        </script>
      `);
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

      const exam = await first(
        `SELECT * FROM exams WHERE id=? AND tenant_id=?`,
        [examId, active.tenant_id]
      );
      if (!exam) return redirect("/teacher");

      // Verify teacher owns this exam
      if (active.role === "TEACHER") {
        const owns = await first(
          `SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1`,
          [exam.course_id, r.user.id]
        );
        if (!owns) return redirect("/teacher");
      }

      const ts = nowISO();

      // Parse schedule — convert datetime-local back to ISO
      const startsAt = f.starts_at ? new Date(f.starts_at).toISOString() : null;
      const endsAt = f.ends_at ? new Date(f.ends_at).toISOString() : null;

      // Save flat fields on exams table
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
          startsAt,
          endsAt,
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
          ts,
          examId,
          active.tenant_id,
        ]
      );

      // Save grade bands — delete all then re-insert
      await run(`DELETE FROM exam_grade_bands WHERE exam_id=?`, [examId]);
      const bandLabels = [].concat(f["band_label[]"] || []);
      const bandMins = [].concat(f["band_min[]"] || []);
      for (let i = 0; i < bandLabels.length; i++) {
        const label = (bandLabels[i] || "").trim();
        const minPct = parseFloat(bandMins[i]);
        if (label && !Number.isNaN(minPct)) {
          await run(
            `INSERT INTO exam_grade_bands (id, exam_id, label, min_percent, created_at) VALUES (?,?,?,?,?)`,
            [uuid(), examId, label, minPct, ts]
          );
        }
      }

      // Save custom fields — delete all then re-insert
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
            `INSERT INTO exam_custom_fields (id, exam_id, field_label, field_type, field_options, is_required, sort_order, created_at)
             VALUES (?,?,?,?,?,?,?,?)`,
            [
              uuid(), examId, label, type,
              type === "DROPDOWN" ? (cfOptions[i] || "").trim() || null : null,
              cfRequired[i] === "1" ? 1 : 0,
              i,
              ts,
            ]
          );
        }
      }

      return redirect(`/exam-builder?exam_id=${examId}`);
    }

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

      if (!qText) return redirect(`/exam-builder?exam_id=${examId}#questions`);

      const ts = nowISO();

      // Get next sort_order
      const maxOrder = await first(`SELECT MAX(sort_order) AS m FROM exam_questions WHERE exam_id=?`, [examId]);
      const sortOrder = (Number(maxOrder?.m) || 0) + 1;

      const qId = uuid();
      await run(
        `INSERT INTO exam_questions
         (id, exam_id, tenant_id, question_type, question_text, marks, sort_order, partial_marking, model_answer, feedback, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [qId, examId, active.tenant_id, qType, qText, marks, sortOrder, partialMarking, modelAnswer, feedback, ts, ts]
      );

      // Save options for MCQ, MULTIPLE_SELECT, TRUE_FALSE
      await saveQuestionOptions(qId, qType, f, ts);

      return redirect(`/exam-builder?exam_id=${examId}&pane=questions#question-form-card`);
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

      if (!qText) return redirect(`/exam-builder?exam_id=${examId}&edit_q=${qId}#questions`);

      const ts = nowISO();
      await run(
        `UPDATE exam_questions SET
          question_type=?, question_text=?, marks=?, partial_marking=?,
          model_answer=?, feedback=?, updated_at=?
         WHERE id=? AND exam_id=?`,
        [qType, qText, marks, partialMarking, modelAnswer, feedback, ts, qId, examId]
      );

      // Rebuild options
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

      // Renumber sort_order to keep it clean
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
      const idx = questions.findIndex(q => q.id === qId);
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
    // Helper: save question options
    // =============================
    async function saveQuestionOptions(qId, qType, f, ts) {
      if (qType === "TRUE_FALSE") {
        const correct = (f.tf_correct || "").trim();
        await run(
          `INSERT INTO exam_question_options (id, question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), qId, "True", correct === "True" ? 1 : 0, null, 1, ts]
        );
        await run(
          `INSERT INTO exam_question_options (id, question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), qId, "False", correct === "False" ? 1 : 0, null, 2, ts]
        );
        return;
      }

      if (qType === "MCQ" || qType === "MULTIPLE_SELECT") {
        const texts = [].concat(f["opt_text[]"] || []);
        const feedbacks = [].concat(f["opt_feedback[]"] || []);
        // correct: for radio (MCQ) this is a single string value; for checkbox (MULTIPLE_SELECT) it's an array of indices
        const correctRaw = f["opt_correct[]"];
        const correctIndices = new Set(
          [].concat(correctRaw || []).map(v => String(v))
        );

        for (let i = 0; i < texts.length; i++) {
          const text = (texts[i] || "").trim();
          if (!text) continue;
          const isCorrect = correctIndices.has(String(i)) ? 1 : 0;
          const optFeedback = (feedbacks[i] || "").trim() || null;
          await run(
            `INSERT INTO exam_question_options (id, question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), qId, text, isCorrect, optFeedback, i + 1, ts]
          );
        }
        return;
      }
      // SHORT_ANSWER, ESSAY — no options to save
    }

  } catch (err) {
    console.error("FATAL [exams]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (exams):\n\n" + msg, { status: 500 });
  }
}
