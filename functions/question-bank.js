// functions/question-bank.js
// Question Bank — standalone management page
// Routes: /question-bank, /qbank-add, /qbank-update, /qbank-delete, /qbank-toggle-visibility

import { createHelpers } from "./shared.js";

export async function handleBankRequest(ctx) {
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
    // Shared: save bank options helper
    // =============================
    async function saveBankOptions(bankQId, qType, f, ts) {
      if (qType === "TRUE_FALSE") {
        const correct = (f.tf_correct || "").trim();
        await run(
          `INSERT INTO question_bank_options (id, bank_question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), bankQId, "True", correct === "True" ? 1 : 0, null, 1, ts]
        );
        await run(
          `INSERT INTO question_bank_options (id, bank_question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
          [uuid(), bankQId, "False", correct === "False" ? 1 : 0, null, 2, ts]
        );
        return;
      }
      if (qType === "MCQ" || qType === "MULTIPLE_SELECT") {
        const texts = [].concat(f["opt_text[]"] || []);
        const feedbacks = [].concat(f["opt_feedback[]"] || []);
        const correctRaw = f["opt_correct[]"];
        const correctIndices = new Set([].concat(correctRaw || []).map(v => String(v)));
        for (let i = 0; i < texts.length; i++) {
          const text = (texts[i] || "").trim();
          if (!text) continue;
          await run(
            `INSERT INTO question_bank_options (id, bank_question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), bankQId, text, correctIndices.has(String(i)) ? 1 : 0, (feedbacks[i] || "").trim() || null, i + 1, ts]
          );
        }
      }
      // SHORT_ANSWER, ESSAY — no options
    }

    // =============================
    // Question Bank — main page (GET)
    // =============================
    if (path === "/question-bank") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      // Filters
      const filterVis = url.searchParams.get("vis") || "ALL";
      const filterType = url.searchParams.get("type") || "ALL";
      const editId = url.searchParams.get("edit") || "";

      // Build WHERE clause
      let where = `WHERE q.tenant_id=?`;
      const params = [active.tenant_id];

      // Teachers only see their own PERSONAL + all SCHOOL questions
      if (active.role === "TEACHER") {
        where += ` AND (q.visibility='SCHOOL' OR q.created_by=?)`;
        params.push(r.user.id);
      }

      if (filterVis === "PERSONAL") { where += ` AND q.visibility='PERSONAL'`; }
      else if (filterVis === "SCHOOL") { where += ` AND q.visibility='SCHOOL'`; }
      if (filterType !== "ALL") { where += ` AND q.question_type=?`; params.push(filterType); }

      const questions = await all(
        `SELECT q.*, u.name AS creator_name
         FROM question_bank q
         JOIN users u ON u.id = q.created_by
         ${where}
         ORDER BY q.created_at DESC`,
        params
      );

      // Load options for all questions
      const allOpts = questions.length > 0 ? await all(
        `SELECT * FROM question_bank_options
         WHERE bank_question_id IN (${questions.map(() => "?").join(",")})
         ORDER BY sort_order ASC`,
        questions.map(q => q.id)
      ) : [];
      const optsByQ = {};
      for (const o of allOpts) {
        if (!optsByQ[o.bank_question_id]) optsByQ[o.bank_question_id] = [];
        optsByQ[o.bank_question_id].push(o);
      }

      // If editing, load the question
      const editQ = editId ? questions.find(q => q.id === editId) : null;
      const editOpts = editQ ? (optsByQ[editQ.id] || []) : [];

      const qTypeLabel = (t) => ({MCQ:"MCQ",MULTIPLE_SELECT:"Multi-select",TRUE_FALSE:"True/False",SHORT_ANSWER:"Short Answer",ESSAY:"Essay"}[t] || t);

      const buildOptionRows = (type, opts) => {
        if (type === "TRUE_FALSE") {
          const trueCorrect = opts.find(o => o.option_text === "True" && Number(o.is_correct));
          return `
            <div class="section-title" style="margin-top:14px">Correct answer</div>
            <select name="tf_correct" required style="max-width:200px">
              <option value="">— select —</option>
              <option value="True" ${trueCorrect ? "selected" : ""}>True</option>
              <option value="False" ${!trueCorrect && opts.length ? "selected" : ""}>False</option>
            </select>`;
        }
        if (type === "MCQ" || type === "MULTIPLE_SELECT") {
          const isMulti = type === "MULTIPLE_SELECT";
          const rows = opts.length > 0
            ? opts.map((o, i) => buildOptRow(isMulti, o.option_text, Number(o.is_correct), o.feedback || "", i)).join("")
            : [0,1,2,3].map(i => buildOptRow(isMulti, "", false, "", i)).join("");
          return `
            <div class="section-title" style="margin-top:14px">Answer options</div>
            <div id="options-container">${rows}</div>
            <button type="button" class="btn3" onclick="addOptRow(${isMulti})" style="margin-top:4px;font-size:12px">+ Add option</button>
            ${isMulti ? `<div style="margin-top:12px"><label>Partial marking</label>
              <select name="partial_marking">
                <option value="1" ${!editQ || Number(editQ.partial_marking) ? "selected":""}>Partial marks</option>
                <option value="0" ${editQ && !Number(editQ.partial_marking) ? "selected":""}>All or nothing</option>
              </select></div>` : ""}`;
        }
        return "";
      };

      const buildOptRow = (isMulti, text, isCorrect, feedback, idx) => `
        <div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
          <div style="display:flex;gap:8px;align-items:center">
            <input type="${isMulti ? "checkbox" : "radio"}" name="opt_correct[]" value="${idx}" ${isCorrect ? "checked" : ""} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
            <input name="opt_text[]" value="${escapeAttr(text)}" placeholder="Option text" style="flex:1" />
            <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px">✕</button>
          </div>
          <div style="margin-top:6px">
            <input name="opt_feedback[]" value="${escapeAttr(feedback)}" placeholder="Feedback (optional)" style="font-size:12px" />
          </div>
        </div>`;

      const formType = editQ ? editQ.question_type : "MCQ";
      const v = (field) => escapeAttr(editQ ? editQ[field] ?? "" : "");

      // Build question list
      const qRows = questions.map(q => {
        const opts = optsByQ[q.id] || [];
        const canEdit = q.created_by === r.user.id || active.role === "SCHOOL_ADMIN";
        const preview = opts.length > 0
          ? opts.slice(0,4).map(o => `<span style="display:inline-block;padding:2px 7px;border-radius:6px;margin:2px;font-size:11px;background:${Number(o.is_correct)?"rgba(11,122,117,.12);color:#0b7a75":"rgba(0,0,0,.06);color:#555"}">${escapeHtml(o.option_text)}</span>`).join("")
          : q.model_answer ? `<span class="muted small">Model: ${escapeHtml(q.model_answer)}</span>` : "";

        return `
          <div class="q-row" style="background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:12px;padding:14px;margin-bottom:8px">
            <div style="display:flex;gap:10px;align-items:flex-start">
              <div style="flex:1;min-width:0">
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px">
                  <span class="pill" style="font-size:11px">${escapeHtml(qTypeLabel(q.question_type))}</span>
                  <span class="pill" style="font-size:11px;background:${q.visibility==="SCHOOL"?"rgba(11,122,117,.15)":"rgba(0,0,0,.06)"};color:${q.visibility==="SCHOOL"?"#0b7a75":"#555"}">${escapeHtml(q.visibility)}</span>
                  <span class="muted small">${escapeHtml(String(q.marks))} mark${Number(q.marks)!==1?"s":""}</span>
                  ${q.created_by !== r.user.id ? `<span class="muted small">by ${escapeHtml(q.creator_name)}</span>` : ""}
                </div>
                <div style="font-size:14px;margin-bottom:6px">${escapeHtml(q.question_text)}</div>
                <div>${preview}</div>
              </div>
              ${canEdit ? `
                <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end;flex-shrink:0">
                  <a href="/question-bank?edit=${escapeAttr(q.id)}" class="btn3" style="font-size:12px;padding:4px 10px;border-radius:8px;display:inline-block">Edit</a>
                  ${q.visibility === "PERSONAL" ? `
                    <form method="post" action="/qbank-toggle-visibility" onsubmit="return confirm('Share this question with all teachers in your school?')">
                      <input type="hidden" name="bank_question_id" value="${escapeAttr(q.id)}"/>
                      <input type="hidden" name="visibility" value="SCHOOL"/>
                      <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px">Share</button>
                    </form>` : ""}
                  <form method="post" action="/qbank-delete" onsubmit="return confirm('Delete this question from the bank?')">
                    <input type="hidden" name="bank_question_id" value="${escapeAttr(q.id)}"/>
                    <button class="btn3" type="submit" style="font-size:12px;padding:4px 10px;border-radius:8px;color:#c00">Delete</button>
                  </form>
                </div>` : ""}
            </div>
          </div>`;
      }).join("");

      return page(`
        <style>
          .section-title{font-size:13px;font-weight:700;color:rgba(0,0,0,.5);text-transform:uppercase;letter-spacing:.05em;margin:18px 0 10px}
          .field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
          @media(max-width:600px){.field-row{grid-template-columns:1fr}}
        </style>

        <div class="card">
          <div class="topbar">
            <div>
              <div style="font-size:12px;color:rgba(0,0,0,.45);margin-bottom:2px"><a href="/teacher">← Teacher Dashboard</a></div>
              <h1 style="margin:0">Question Bank</h1>
              <div class="muted small" style="margin-top:4px">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
              </div>
            </div>
            <div class="actions">
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 380px;gap:12px;align-items:start">

          <!-- Left: question list -->
          <div>
            <!-- Filters -->
            <div class="card" style="padding:12px">
              <form method="get" action="/question-bank" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
                <div>
                  <label style="margin:0 0 4px">Visibility</label>
                  <select name="vis" onchange="this.form.submit()" style="width:auto;padding:8px">
                    <option value="ALL" ${filterVis==="ALL"?"selected":""}>All</option>
                    <option value="PERSONAL" ${filterVis==="PERSONAL"?"selected":""}>Personal</option>
                    <option value="SCHOOL" ${filterVis==="SCHOOL"?"selected":""}>School</option>
                  </select>
                </div>
                <div>
                  <label style="margin:0 0 4px">Type</label>
                  <select name="type" onchange="this.form.submit()" style="width:auto;padding:8px">
                    <option value="ALL" ${filterType==="ALL"?"selected":""}>All types</option>
                    <option value="MCQ" ${filterType==="MCQ"?"selected":""}>MCQ</option>
                    <option value="MULTIPLE_SELECT" ${filterType==="MULTIPLE_SELECT"?"selected":""}>Multi-select</option>
                    <option value="TRUE_FALSE" ${filterType==="TRUE_FALSE"?"selected":""}>True/False</option>
                    <option value="SHORT_ANSWER" ${filterType==="SHORT_ANSWER"?"selected":""}>Short Answer</option>
                    <option value="ESSAY" ${filterType==="ESSAY"?"selected":""}>Essay</option>
                  </select>
                </div>
              </form>
            </div>

            <div style="margin-bottom:6px">
              <span class="muted small">${questions.length} question${questions.length!==1?"s":""}</span>
            </div>

            ${qRows || `<div class="card" style="text-align:center;padding:32px"><p class="muted">No questions yet — add your first question →</p></div>`}
          </div>

          <!-- Right: add/edit form -->
          <div class="card" style="position:sticky;top:12px">
            <h2 style="margin:0 0 14px">${editQ ? "Edit question" : "Add question"}</h2>
            <form method="post" action="${editQ ? "/qbank-update" : "/qbank-add"}">
              ${editQ ? `<input type="hidden" name="bank_question_id" value="${escapeAttr(editQ.id)}"/>` : ""}

              <label>Question type</label>
              <select name="question_type" id="qtype-select" onchange="updateForm(this.value)" required>
                <option value="MCQ" ${formType==="MCQ"?"selected":""}>MCQ</option>
                <option value="MULTIPLE_SELECT" ${formType==="MULTIPLE_SELECT"?"selected":""}>Multiple Select</option>
                <option value="TRUE_FALSE" ${formType==="TRUE_FALSE"?"selected":""}>True / False</option>
                <option value="SHORT_ANSWER" ${formType==="SHORT_ANSWER"?"selected":""}>Short Answer</option>
                <option value="ESSAY" ${formType==="ESSAY"?"selected":""}>Essay</option>
              </select>

              <div class="field-row" style="margin-top:10px">
                <div>
                  <label>Marks</label>
                  <input name="marks" type="number" min="0.5" step="0.5" value="${v("marks") || "1"}" required />
                </div>
                <div>
                  <label>Visibility</label>
                  <select name="visibility">
                    <option value="PERSONAL" ${!editQ || editQ.visibility==="PERSONAL"?"selected":""}>Personal</option>
                    <option value="SCHOOL" ${editQ && editQ.visibility==="SCHOOL"?"selected":""}>School (shared)</option>
                  </select>
                </div>
              </div>

              <label style="margin-top:10px">Question text</label>
              <textarea name="question_text" rows="3" style="width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px;font-family:inherit;font-size:14px" required>${escapeHtml(editQ ? editQ.question_text : "")}</textarea>

              <div id="dynamic-section">
                ${buildOptionRows(formType, editOpts)}
              </div>

              <div style="margin-top:10px">
                <label>Question feedback <span class="muted">(optional)</span></label>
                <textarea name="feedback" rows="2" style="width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px;font-family:inherit;font-size:13px">${escapeHtml(editQ ? editQ.feedback || "" : "")}</textarea>
              </div>

              <div id="model-answer-wrap" style="${formType==="SHORT_ANSWER"?"":"display:none"}">
                <label>Model answer <span class="muted">(optional)</span></label>
                <input name="model_answer" value="${v("model_answer")}" placeholder="e.g. Paris" />
              </div>

              <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
                <button type="submit" class="btn2">${editQ ? "Save changes" : "Add to bank"}</button>
                ${editQ ? `<a href="/question-bank" class="btn3" style="display:inline-block;padding:8px 12px;border-radius:10px;text-decoration:none">Cancel</a>` : ""}
              </div>
            </form>
          </div>
        </div>

        <script>
          function updateForm(type) {
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
                </select>\`;
            } else if (type === 'MCQ' || type === 'MULTIPLE_SELECT') {
              const isMulti = type === 'MULTIPLE_SELECT';
              section.innerHTML = \`
                <div class="section-title" style="margin-top:14px">Answer options</div>
                <div id="options-container">
                  \${[0,1,2,3].map(i => buildOptRow(isMulti,'',false,'',i)).join('')}
                </div>
                <button type="button" class="btn3" onclick="addOptRow(\${isMulti})" style="margin-top:4px;font-size:12px">+ Add option</button>
                \${isMulti ? \`<div style="margin-top:12px"><label>Partial marking</label>
                  <select name="partial_marking">
                    <option value="1">Partial marks</option>
                    <option value="0">All or nothing</option>
                  </select></div>\` : ''}\`;
            } else {
              section.innerHTML = '';
            }
          }

          function buildOptRow(isMulti, text, isCorrect, feedback, idx) {
            return \`<div class="opt-row" style="border:1px solid rgba(0,0,0,.09);border-radius:10px;padding:10px;margin-bottom:6px">
              <div style="display:flex;gap:8px;align-items:center">
                <input type="\${isMulti?'checkbox':'radio'}" name="opt_correct[]" value="\${idx}" \${isCorrect?'checked':''} style="width:auto;flex-shrink:0;transform:scale(1.3)" />
                <input name="opt_text[]" value="\${text}" placeholder="Option text" style="flex:1" />
                <button type="button" class="btn3" onclick="this.closest('.opt-row').remove()" style="padding:4px 8px">✕</button>
              </div>
              <div style="margin-top:6px">
                <input name="opt_feedback[]" value="\${feedback}" placeholder="Feedback (optional)" style="font-size:12px" />
              </div>
            </div>\`;
          }

          function addOptRow(isMulti) {
            const c = document.getElementById('options-container');
            const idx = c.querySelectorAll('.opt-row').length;
            c.insertAdjacentHTML('beforeend', buildOptRow(isMulti,'',false,'',idx));
          }
        </script>
      `);
    }

    // =============================
    // Bank: add question (POST)
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
      const bankId = uuid();
      await run(
        `INSERT INTO question_bank
         (id, tenant_id, created_by, question_type, question_text, marks, partial_marking, model_answer, feedback, visibility, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [bankId, active.tenant_id, r.user.id, qType, qText, marks, partialMarking, modelAnswer, feedback, visibility, ts, ts]
      );
      await saveBankOptions(bankId, qType, f, ts);

      return redirect("/question-bank");
    }

    // =============================
    // Bank: update question (POST)
    // =============================
    if (path === "/qbank-update" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const bankQId = (f.bank_question_id || "").trim();
      if (!bankQId) return redirect("/question-bank");

      // Verify ownership
      const bq = await first(
        `SELECT * FROM question_bank WHERE id=? AND tenant_id=?`,
        [bankQId, active.tenant_id]
      );
      if (!bq) return redirect("/question-bank");
      if (bq.created_by !== r.user.id && active.role !== "SCHOOL_ADMIN") return redirect("/question-bank");

      const qType = (f.question_type || "MCQ").trim();
      const qText = (f.question_text || "").trim();
      const marks = Math.max(0.5, parseFloat(f.marks || "1") || 1);
      const feedback = (f.feedback || "").trim() || null;
      const modelAnswer = qType === "SHORT_ANSWER" ? (f.model_answer || "").trim() || null : null;
      const partialMarking = qType === "MULTIPLE_SELECT" ? (f.partial_marking === "1" ? 1 : 0) : 0;
      const visibility = f.visibility === "SCHOOL" ? "SCHOOL" : "PERSONAL";

      if (!qText) return redirect(`/question-bank?edit=${bankQId}`);

      const ts = nowISO();
      await run(
        `UPDATE question_bank SET
          question_type=?, question_text=?, marks=?, partial_marking=?,
          model_answer=?, feedback=?, visibility=?, updated_at=?
         WHERE id=? AND tenant_id=?`,
        [qType, qText, marks, partialMarking, modelAnswer, feedback, visibility, ts, bankQId, active.tenant_id]
      );

      await run(`DELETE FROM question_bank_options WHERE bank_question_id=?`, [bankQId]);
      await saveBankOptions(bankQId, qType, f, ts);

      // If exam questions are linked to this bank question AND their exam is still DRAFT
      // — sync the update to exam copies too
      const linkedExamQs = await all(
        `SELECT eq.id, eq.exam_id FROM exam_questions eq
         JOIN exams e ON e.id = eq.exam_id
         WHERE eq.bank_question_id=? AND e.status='DRAFT'`,
        [bankQId]
      );
      for (const eq of linkedExamQs) {
        await run(
          `UPDATE exam_questions SET
            question_type=?, question_text=?, marks=?, partial_marking=?,
            model_answer=?, feedback=?, updated_at=?
           WHERE id=?`,
          [qType, qText, marks, partialMarking, modelAnswer, feedback, ts, eq.id]
        );
        // Rebuild exam options too
        await run(`DELETE FROM exam_question_options WHERE question_id=?`, [eq.id]);
        // Re-insert from the new bank options
        const newBankOpts = await all(
          `SELECT * FROM question_bank_options WHERE bank_question_id=? ORDER BY sort_order ASC`,
          [bankQId]
        );
        for (const o of newBankOpts) {
          await run(
            `INSERT INTO exam_question_options (id, question_id, option_text, is_correct, feedback, sort_order, created_at) VALUES (?,?,?,?,?,?,?)`,
            [uuid(), eq.id, o.option_text, o.is_correct, o.feedback, o.sort_order, ts]
          );
        }
      }

      return redirect("/question-bank");
    }

    // =============================
    // Bank: delete question (POST)
    // =============================
    if (path === "/qbank-delete" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const bankQId = (f.bank_question_id || "").trim();
      if (!bankQId) return redirect("/question-bank");

      const bq = await first(`SELECT * FROM question_bank WHERE id=? AND tenant_id=?`, [bankQId, active.tenant_id]);
      if (!bq) return redirect("/question-bank");
      if (bq.created_by !== r.user.id && active.role !== "SCHOOL_ADMIN") return redirect("/question-bank");

      // Unlink any exam questions that reference this bank question
      await run(`UPDATE exam_questions SET bank_question_id=NULL WHERE bank_question_id=?`, [bankQId]);

      await run(`DELETE FROM question_bank_options WHERE bank_question_id=?`, [bankQId]);
      await run(`DELETE FROM question_bank WHERE id=? AND tenant_id=?`, [bankQId, active.tenant_id]);

      return redirect("/question-bank");
    }

    // =============================
    // Bank: toggle visibility (POST)
    // =============================
    if (path === "/qbank-toggle-visibility" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || (active.role !== "TEACHER" && active.role !== "SCHOOL_ADMIN")) return redirect("/");

      const f = await form();
      const bankQId = (f.bank_question_id || "").trim();
      const visibility = f.visibility === "SCHOOL" ? "SCHOOL" : "PERSONAL";

      const bq = await first(`SELECT * FROM question_bank WHERE id=? AND tenant_id=?`, [bankQId, active.tenant_id]);
      if (!bq) return redirect("/question-bank");
      if (bq.created_by !== r.user.id && active.role !== "SCHOOL_ADMIN") return redirect("/question-bank");

      await run(`UPDATE question_bank SET visibility=?, updated_at=? WHERE id=?`, [visibility, nowISO(), bankQId]);
      return redirect("/question-bank");
    }

    return redirect("/question-bank");

  } catch (err) {
    console.error("FATAL [question-bank]", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR (question-bank):\n\n" + msg, { status: 500 });
  }
}
