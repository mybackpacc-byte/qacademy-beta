// functions/question-bank.js
// Question bank routes
// /question-bank            — main page (list + add/edit form)
// /qbank-add                — POST: create question in bank
// /qbank-update             — POST: update question in bank
// /qbank-delete             — POST: delete question from bank
// /qbank-share              — POST: toggle visibility PERSONAL <-> SCHOOL

import { createHelpers } from "./shared.js";

export async function handleQuestionBankRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    const {
      nowISO, uuid,
      page, redirect, escapeHtml, escapeAttr, form,
      first, all, run,
      requireLogin, pickActiveMembership,
    } = createHelpers(request, env);

    const qTypeLabel = (t) => {
      if (t === "MCQ") return "MCQ";
      if (t === "MULTIPLE_SELECT") return "Multi-select";
      if (t === "TRUE_FALSE") return "True / False";
      if (t === "SHORT_ANSWER") return "Short Answer";
      if (t === "ESSAY") return "Essay";
      return t;
    };

    // =============================
    // Helper: save bank question options
    // =============================
    async function saveBankOptions(bankQId, qType, f, ts) {
      if (qType === "TRUE_FALSE") {
        const correct = (f.tf_correct || "").trim();
        await run(
          `INSERT INTO question_bank_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), bankQId, "True", correct === "True" ? 1 : 0, null, 1, ts]
        );
        await run(
          `INSERT INTO question_bank_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
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
            `INSERT INTO question_bank_options (id,question_id,option_text,is_correct,feedback,sort_order,created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), bankQId, text, isCorrect, optFeedback, i + 1, ts]
          );
        }
      }
      // SHORT_ANSWER, ESSAY — no options
    }

    // =============================
    // Main question bank page (GET)
    // =============================
    if (path === "/question-bank") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const filterType = url.searchParams.get("type") || "";
      const filterVis = url.searchParams.get("vis") || "";
      const editId = url.searchParams.get("edit") || "";

      // Build query
      let whereClause = `WHERE qb.tenant_id=? AND (qb.created_by=? OR qb.visibility='SCHOOL')`;
      const params = [active.tenant_id, r.user.id];
      if (filterType) { whereClause += ` AND qb.question_type=?`; params.push(filterType); }
      if (filterVis === "PERSONAL") { whereClause += ` AND qb.created_by=? AND qb.visibility='PERSONAL'`; params.push(r.user.id); }
      else if (filterVis === "SCHOOL") { whereClause += ` AND qb.visibility='SCHOOL'`; }

      const questions = await all(
        `SELECT qb.id, qb.question_type, qb.question_text, qb.marks, qb.visibility,
                qb.partial_marking, qb.model_answer, qb.feedback, qb.created_by,
                qb.created_at, qb.updated_at,
                u.name AS creator_name
         FROM question_bank qb
         JOIN users u ON u.id = qb.created_by
         ${whereClause}
         ORDER BY qb.updated_at DESC`,
        params
      );

      // Load all options for displayed questions
      const allOptions = questions.length > 0 ? await all(
        `SELECT question_id, option_text, is_correct, feedback, sort_order
         FROM question_bank_options
         WHERE question_id IN (${questions.map(() => "?").join(",")})
         ORDER BY sort_order ASC`,
        questions.map((q) => q.id)
      ) : [];

      const optsByQ = {};
      for (const o of allOptions) {
        if (!optsByQ[o.question_id]) optsByQ[o.question_id] = [];
        optsByQ[o.question_id].push(o);
      }

      // Load editing question if any
      const editQ = editId ? questions.find((q) => q.id === editId) : null;
      const editOpts = editQ ? (optsByQ[editQ.id] || []) : [];
      const formType = editQ ? editQ.question_type : "MCQ";
      const isMineEdit = editQ ? editQ.created_by === r.user.id : true;

      // Build option row HTML
      const buildOptionRow = (isMulti, text, isCorrect, fb, idx) => `
        <div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
          <div style="display:flex;gap:8px;align-items:center">
            <input type="${isMulti ? "checkbox" : "radio"}" name="opt_correct[]" value="${idx}" ${isCorrect ? "checked" : ""} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
            <input name="opt_text[]" value="${escapeAttr(text)}" placeholder="Option text" style="flex:1" />
            <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px;flex-shrink:0">✕</button>
          </div>
          <div style="margin-top:6px">
            <input name="opt_feedback[]" value="${escapeAttr(fb)}" placeholder="Feedback for this option (optional)" style="font-size:12px" />
          </div>
        </div>
      `;

      const buildOptionRows = (type, opts) => {
        if (type === "TRUE_FALSE") {
          const trueCorrect = opts.find((o) => o.option_text === "True" && Number(o.is_correct));
          const falseCorrect = opts.find((o) => o.option_text === "False" && Number(o.is_correct));
          return `
            <div style="margin-top:14px;font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase;letter-spacing:.05em">Correct answer</div>
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
            <div style="margin-top:14px;font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase;letter-spacing:.05em">
              Answer options <span style="font-size:11px;text-transform:none;letter-spacing:0;font-weight:400">(tick the correct answer${isMulti ? "s" : ""})</span>
            </div>
            <div id="options-container">${rows}</div>
            <button type="button" class="btn3" onclick="addOptionRow(${isMulti ? "true" : "false"})" style="margin-top:4px;font-size:12px">+ Add option</button>
            ${isMulti ? `
              <div style="margin-top:12px">
                <label>Partial marking</label>
                <select name="partial_marking">
                  <option value="1" ${!editQ || Number(editQ.partial_marking) ? "selected" : ""}>Partial marks (proportional to correct options)</option>
                  <option value="0" ${editQ && !Number(editQ.partial_marking) ? "selected" : ""}>All or nothing</option>
                </select>
              </div>` : ""}
          `;
        }
        return "";
      };

      // Build question list
      const questionCards = questions.map((q) => {
        const opts = optsByQ[q.id] || [];
        const isMine = q.created_by === r.user.id;
        const preview = opts.length > 0
          ? opts.map((o) => `<span style="display:inline-block;padding:2px 7px;border-radius:5px;margin:2px;font-size:11px;background:${Number(o.is_correct) ? "rgba(11,122,117,.12);color:#0b7a75" : "rgba(0,0,0,.06);color:#555"}">${escapeHtml(o.option_text)}</span>`).join("")
          : q.model_answer ? `<span class="muted small">Model answer set</span>` : "";

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
              ${isMine ? `
                <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end;flex-shrink:0">
                  <a href="/question-bank?edit=${escapeAttr(q.id)}${filterType ? "&type=" + escapeAttr(filterType) : ""}${filterVis ? "&vis=" + escapeAttr(filterVis) : ""}#edit-form"
                     class="btn3" style="font-size:12px;padding:4px 10px;border-radius:8px;display:inline-block">Edit</a>
                  <form method="post" action="/qbank-share" style="display:inline">
                    <input type="hidden" name="question_id" value="${escapeAttr(q.id)}" />
                    <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px">
                      ${q.visibility === "SCHOOL" ? "Make personal" : "Share to school"}
                    </button>
                  </form>
                  <form method="post" action="/qbank-delete" onsubmit="return confirm('Delete this question from bank?')" style="display:inline">
                    <input type="hidden" name="question_id" value="${escapeAttr(q.id)}" />
                    <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px;color:#c00">Delete</button>
                  </form>
                </div>
              ` : `<div class="muted small" style="flex-shrink:0">Read-only</div>`}
            </div>
          </div>
        `;
      }).join("");

      return page(`
        <style>
          .field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
          @media(max-width:600px){.field-row{grid-template-columns:1fr}}
        </style>

        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/teacher">← Teacher Dashboard</a></div>
              <h1 style="margin:0">Question Bank</h1>
              <div class="muted small" style="margin-top:4px">${escapeHtml(active.tenant_name)}</div>
            </div>
            <div class="actions">
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>

        <!-- Filters -->
        <div class="card">
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
            <div style="flex:1;min-width:140px">
              <label>Filter by type</label>
              <select id="f-type" onchange="applyFilters()">
                <option value="">All types</option>
                <option value="MCQ" ${filterType === "MCQ" ? "selected" : ""}>MCQ</option>
                <option value="MULTIPLE_SELECT" ${filterType === "MULTIPLE_SELECT" ? "selected" : ""}>Multi-select</option>
                <option value="TRUE_FALSE" ${filterType === "TRUE_FALSE" ? "selected" : ""}>True / False</option>
                <option value="SHORT_ANSWER" ${filterType === "SHORT_ANSWER" ? "selected" : ""}>Short Answer</option>
                <option value="ESSAY" ${filterType === "ESSAY" ? "selected" : ""}>Essay</option>
              </select>
            </div>
            <div style="flex:1;min-width:140px">
              <label>Filter by visibility</label>
              <select id="f-vis" onchange="applyFilters()">
                <option value="">All (mine + school)</option>
                <option value="PERSONAL" ${filterVis === "PERSONAL" ? "selected" : ""}>My questions only</option>
                <option value="SCHOOL" ${filterVis === "SCHOOL" ? "selected" : ""}>School questions</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Question list -->
        <div class="muted small" style="margin:4px 0 8px;padding:0 4px">${questions.length} question${questions.length !== 1 ? "s" : ""}</div>

        ${questions.length > 0 ? questionCards : `
          <div class="card" style="text-align:center;padding:32px">
            <p class="muted">No questions yet — add your first question below.</p>
          </div>
        `}

        <!-- Add / Edit form -->
        <div class="card" id="edit-form">
          <h2 style="margin:0 0 14px">${editQ ? "Edit question" : "Add question to bank"}</h2>

          ${editQ && !isMineEdit ? `<div class="err" style="margin-bottom:12px">You can only edit your own questions.</div>` : ""}

          <form method="post" action="${editQ ? "/qbank-update" : "/qbank-add"}">
            ${editQ ? `<input type="hidden" name="question_id" value="${escapeAttr(editQ.id)}" />` : ""}

            <div class="field-row">
              <div>
                <label>Question type</label>
                <select name="question_type" id="qtype-select" onchange="updateFormForType(this.value)" required ${editQ && !isMineEdit ? "disabled" : ""}>
                  <option value="MCQ" ${formType === "MCQ" ? "selected" : ""}>MCQ (single correct answer)</option>
                  <option value="MULTIPLE_SELECT" ${formType === "MULTIPLE_SELECT" ? "selected" : ""}>Multiple Select (pick all that apply)</option>
                  <option value="TRUE_FALSE" ${formType === "TRUE_FALSE" ? "selected" : ""}>True / False</option>
                  <option value="SHORT_ANSWER" ${formType === "SHORT_ANSWER" ? "selected" : ""}>Short Answer</option>
                  <option value="ESSAY" ${formType === "ESSAY" ? "selected" : ""}>Essay</option>
                </select>
              </div>
              <div>
                <label>Marks</label>
                <input name="marks" type="number" min="0.5" step="0.5" value="${escapeAttr(String(editQ ? editQ.marks : 1))}" required ${editQ && !isMineEdit ? "disabled" : ""} />
              </div>
            </div>

            <label style="margin-top:12px">Question text</label>
            <textarea name="question_text" rows="3" style="font-size:14px" required ${editQ && !isMineEdit ? "disabled" : ""}>${escapeHtml(editQ ? editQ.question_text : "")}</textarea>

            <div id="dynamic-section">
              ${buildOptionRows(formType, editOpts)}
            </div>

            <div style="margin-top:12px">
              <label>Question feedback <span class="muted">(optional — shown to student during review)</span></label>
              <textarea name="feedback" rows="2" style="font-size:13px" placeholder="e.g. The correct answer is X because..." ${editQ && !isMineEdit ? "disabled" : ""}>${escapeHtml(editQ ? editQ.feedback || "" : "")}</textarea>
            </div>

            <div id="model-answer-wrap" style="${formType === "SHORT_ANSWER" ? "" : "display:none"}">
              <label>Model answer <span class="muted">(optional — marking reference)</span></label>
              <input name="model_answer" value="${escapeAttr(editQ ? editQ.model_answer || "" : "")}" placeholder="e.g. Paris" ${editQ && !isMineEdit ? "disabled" : ""} />
            </div>

            <div style="margin-top:12px">
              <label>Visibility</label>
              <select name="visibility" ${editQ && !isMineEdit ? "disabled" : ""}>
                <option value="PERSONAL" ${!editQ || editQ.visibility === "PERSONAL" ? "selected" : ""}>Personal (only I can see and use this)</option>
                <option value="SCHOOL" ${editQ && editQ.visibility === "SCHOOL" ? "selected" : ""}>School (all teachers in my school can use this)</option>
              </select>
            </div>

            <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
              ${editQ && !isMineEdit ? "" : `<button type="submit" class="btn2">${editQ ? "Save changes" : "Add to bank"}</button>`}
              ${editQ ? `<a href="/question-bank" class="btn3" style="display:inline-block;padding:8px 12px;border-radius:10px;text-decoration:none">Cancel</a>` : ""}
            </div>
          </form>
        </div>

        <script>
          function applyFilters() {
            const type = document.getElementById('f-type').value;
            const vis = document.getElementById('f-vis').value;
            const params = new URLSearchParams();
            if (type) params.set('type', type);
            if (vis) params.set('vis', vis);
            window.location.href = '/question-bank' + (params.toString() ? '?' + params.toString() : '');
          }

          function updateFormForType(type) {
            const section = document.getElementById('dynamic-section');
            const modelWrap = document.getElementById('model-answer-wrap');
            modelWrap.style.display = type === 'SHORT_ANSWER' ? '' : 'none';
            if (type === 'TRUE_FALSE') {
              section.innerHTML = \`
                <div style="margin-top:14px;font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase;letter-spacing:.05em">Correct answer</div>
                <select name="tf_correct" required style="max-width:200px">
                  <option value="">— select —</option>
                  <option value="True">True</option>
                  <option value="False">False</option>
                </select>
              \`;
            } else if (type === 'MCQ' || type === 'MULTIPLE_SELECT') {
              const isMulti = type === 'MULTIPLE_SELECT';
              section.innerHTML = \`
                <div style="margin-top:14px;font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase">Answer options</div>
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
                <input name="opt_feedback[]" value="\${feedback}" placeholder="Feedback (optional)" style="font-size:12px" />
              </div>
            </div>\`;
          }

          function addOptionRow(isMulti) {
            const container = document.getElementById('options-container');
            const idx = container.querySelectorAll('.opt-row').length;
            container.insertAdjacentHTML('beforeend', buildOptRow(isMulti,'',false,'',idx));
          }
        </script>
      `);
    }

    // =============================
    // Add question to bank (POST)
    // =============================
    if (path === "/qbank-add" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const qType = (f.question_type || "MCQ").trim();
      const qText = (f.question_text || "").trim();
      const marks = Math.max(0.5, parseFloat(f.marks || "1") || 1);
      const feedback = (f.feedback || "").trim() || null;
      const modelAnswer = qType === "SHORT_ANSWER" ? (f.model_answer || "").trim() || null : null;
      const partialMarking = qType === "MULTIPLE_SELECT" ? (f.partial_marking === "1" ? 1 : 0) : 0;
      const visibility = f.visibility === "SCHOOL" ? "SCHOOL" : "PERSONAL";
      if (!qText) return redirect("/question-bank");

      const ts = nowISO();
      const qId = uuid();
      await run(
        `INSERT INTO question_bank (id,tenant_id,created_by,question_type,question_text,marks,partial_marking,model_answer,feedback,visibility,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [qId, active.tenant_id, r.user.id, qType, qText, marks, partialMarking, modelAnswer, feedback, visibility, ts, ts]
      );
      await saveBankOptions(qId, qType, f, ts);
      return redirect("/question-bank");
    }

    // =============================
    // Update question in bank (POST)
    // =============================
    if (path === "/qbank-update" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const qId = (f.question_id || "").trim();
      if (!qId) return redirect("/question-bank");

      // Must own this question
      const existing = await first(
        `SELECT id FROM question_bank WHERE id=? AND tenant_id=? AND created_by=?`,
        [qId, active.tenant_id, r.user.id]
      );
      if (!existing) return redirect("/question-bank");

      const qType = (f.question_type || "MCQ").trim();
      const qText = (f.question_text || "").trim();
      const marks = Math.max(0.5, parseFloat(f.marks || "1") || 1);
      const feedback = (f.feedback || "").trim() || null;
      const modelAnswer = qType === "SHORT_ANSWER" ? (f.model_answer || "").trim() || null : null;
      const partialMarking = qType === "MULTIPLE_SELECT" ? (f.partial_marking === "1" ? 1 : 0) : 0;
      const visibility = f.visibility === "SCHOOL" ? "SCHOOL" : "PERSONAL";
      if (!qText) return redirect("/question-bank");

      const ts = nowISO();
      await run(
        `UPDATE question_bank SET question_type=?, question_text=?, marks=?, partial_marking=?, model_answer=?, feedback=?, visibility=?, updated_at=? WHERE id=?`,
        [qType, qText, marks, partialMarking, modelAnswer, feedback, visibility, ts, qId]
      );
      await run(`DELETE FROM question_bank_options WHERE question_id=?`, [qId]);
      await saveBankOptions(qId, qType, f, ts);
      return redirect("/question-bank");
    }

    // =============================
    // Delete question from bank (POST)
    // =============================
    if (path === "/qbank-delete" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const qId = (f.question_id || "").trim();
      if (!qId) return redirect("/question-bank");

      // Must own this question
      const existing = await first(
        `SELECT id FROM question_bank WHERE id=? AND tenant_id=? AND created_by=?`,
        [qId, active.tenant_id, r.user.id]
      );
      if (!existing) return redirect("/question-bank");

      await run(`DELETE FROM question_bank_options WHERE question_id=?`, [qId]);
      await run(`DELETE FROM question_bank WHERE id=?`, [qId]);

      // Unlink from any exam questions (don't delete exam questions — just unlink)
      await run(`UPDATE exam_questions SET bank_question_id=NULL WHERE bank_question_id=?`, [qId]);

      return redirect("/question-bank");
    }

    // =============================
    // Toggle visibility (POST)
    // =============================
    if (path === "/qbank-share" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const qId = (f.question_id || "").trim();
      if (!qId) return redirect("/question-bank");

      const existing = await first(
        `SELECT id, visibility FROM question_bank WHERE id=? AND tenant_id=? AND created_by=?`,
        [qId, active.tenant_id, r.user.id]
      );
      if (!existing) return redirect("/question-bank");

      const newVis = existing.visibility === "SCHOOL" ? "PERSONAL" : "SCHOOL";
      await run(`UPDATE question_bank SET visibility=?, updated_at=? WHERE id=?`, [newVis, nowISO(), qId]);
      return redirect("/question-bank");
    }

  } catch (err) {
    console.error("FATAL [question-bank]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (question-bank):\n\n" + msg, { status: 500 });
  }
}
