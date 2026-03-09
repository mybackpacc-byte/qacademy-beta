# QAcademy Beta — Project Summary
*This document is for Claude's Project Knowledge. It summarises everything built so far, the tech stack, decisions made, and what comes next.*

---

## 🎯 What We Are Building
A **multi-tenant exam taking platform for schools.**
- Schools sign up and get their own isolated space
- Teachers create and manage exams
- Students take exams and view results
- Admins manage users and publish results
- Built to be simple, affordable, and work well in low-resource school environments
- **Beta's identity: exams are the core product, not quizzes. Everything is designed around formal exam running.**

---

## 👤 The Person Building This
- **Role:** Product Manager — no coding background
- **Approach:** Claude writes all the code, user describes features and tests them
- **Pace:** Learning as we go — explanations needed alongside code
- **Environment:** Claude Desktop (Claude Code) connected to local GitHub repo + browser Claude.ai for planning

---

## 🛠️ Tech Stack

| Layer | Tool |
|---|---|
| Frontend + Routing | Cloudflare Pages |
| Backend Logic | Cloudflare Workers |
| Database | Cloudflare D1 (SQLite) |
| Authentication | Custom built |
| Code Repository | GitHub |
| Database Management | Wrangler CLI (via Claude Desktop) |

### Important Notes On Environment
- Local repo is at `C:\Users\confi\qacademy-beta` on Windows
- Claude Desktop (Claude Code) is connected to the local repo and can run wrangler commands directly
- Always run `git pull` at the start of a Claude Desktop session if GitHub was edited directly
- Claude Desktop handles all DB changes via `wrangler d1 execute beta_db --remote`
- No more manual query pane needed for schema changes
- Browser Claude.ai is used for planning, reviewing, and generating summaries
- Always commit and push directly to the **main** branch — never create a new branch

---

## 📁 Repository Structure
```
functions/
  [[path]].js       → Entry point router — directs traffic to correct handler
  shared.js         → All shared helpers (auth, DB, crypto, cookies, HTML) + recalcAttempt
  auth.js           → Login, logout, setup, profile, join, choose-school, switch-school, /
  sys.js            → System Admin routes (/sys, /sys-create-school, /sys-add-member)
  admin.js          → School Admin routes (/school, /school-*)
  teacher.js        → Teacher dashboard (/teacher)
  student.js        → Student dashboard (/student)
  exams.js          → Exam builder routes + teacher results pane + grading screen
  question-bank.js  → Question bank routes
  attempts.js       → Exam taking engine routes (student)
  results.js        → Student results page, review page, sitting results
  sittings.js       → Sittings management + approval gates + approval inbox + exam preview

db/
  schema.sql        → Reference schema — run once in D1 for a fresh clone

wrangler.toml       → Cloudflare config
```

### Why [[path]].js?
The double brackets are **required by Cloudflare Pages** — it's their syntax for a catch-all route handler. Cannot be renamed.

### Routing Logic in [[path]].js
```
/attempt-start, /attempt-take,
/attempt-complete                       → attempts.js
/attempt-results, /attempt-review,
/sitting-results                        → results.js
/sittings, /sitting-builder,
/sitting-create, /sitting-save-settings,
/sitting-add-paper, /sitting-remove-paper,
/sitting-gate-save,
/sitting-gate-remove-approver,
/sitting-gate-settings,
/approvals, /approval-respond,
/exam-preview,
/approval-respond-with-comments         → sittings.js
/question-bank, /qbank-*               → question-bank.js
/exam-create, /exam-builder,
/exam-save-settings, /exam-*,
/exam-bank-picker, /exam-add-from-bank,
/exam-grade, /exam-results-csv,
/exam-gate-submit                       → exams.js
/sys, /sys-*                            → sys.js
/school, /school-sittings,
/school-courses, /school-classes,
/school-people, /school-join-codes,
/school-*                               → admin.js
/teacher                                → teacher.js
/student                                → student.js
everything else (/, /login, /logout,
/setup, /profile, /join, /join-*,
/choose-school, /switch-school,
/no-access, /health)                    → auth.js
```

---

## 🔐 Authentication System — COMPLETE
- Email + password login
- PBKDF2 passwords (40,000 iterations) + pepper + salt
- Sessions in D1 with hashed token in HTTP-only cookie
- Cookie: `qa_sess`, expiry: 7 days

### Auth Routes
| Route | What It Does |
|---|---|
| `/setup` | First time setup — creates System Admin |
| `/login` | Email + password login |
| `/logout` | Clears session |
| `/profile` | View profile, change password |
| `/join` | Enter join code |
| `/join-login` | Login then process join |
| `/join-create-account` | Create account then process join |
| `/choose-school` | Pick active school |
| `/switch-school` | Set active tenant |
| `/no-access` | No school memberships |

---

## 👥 Role System — COMPLETE
| Role | Access |
|---|---|
| System Admin | `/sys` — platform-wide |
| School Admin | `/school` — manages one school |
| Teacher | `/teacher` — creates exams |
| Student | `/student` — takes exams and views results |

---

## 🗄️ Database Tables — ALL CREATED IN D1

### Core tables
1. `tenants` — schools
2. `users` — all people
3. `sessions` — login sessions (includes `active_tenant_id`)
4. `memberships` — user ↔ school ↔ role
5. `courses` — subjects within a school
6. `course_teachers` — teacher ↔ course
7. `enrollments` — student ↔ course
8. `join_codes` — invite codes
9. `join_requests` — pending approvals
17. `classes` — class groups within a school
18. `class_students` — student ↔ class link

### Exam tables
10. `exams` — exam metadata + all settings
11. `exam_grade_bands` — grade band rows per exam
12. `exam_custom_fields` — custom fields per exam
13. `exam_questions` — questions per exam
14. `exam_question_options` — options per question (column: `question_id`)
19. `exam_access` — students explicitly granted access to an exam

### Exam taking engine tables
21. `exam_attempts` — one row per student attempt at an exam
22. `exam_answers` — one row per question per attempt

### Sittings tables
23. `exam_sittings` — groups multiple exam papers into one sitting (School Admin controlled)
24. `exam_sitting_papers` — which exams belong to which sitting

### Approval tables
25. `sitting_approval_gates` — assigns approvers per exam + gate type (QUESTIONS/GRADING/RESULTS)
26. `sitting_approval_responses` — records each approver's decision (PENDING/APPROVED/REJECTED) with optional note
27. `sitting_approval_comments` — per-question comments left by approvers during review (exam_id, gate_type, question_id, approver_id, tenant_id, comment)

### Question bank tables
15. `question_bank` — master question library
16. `question_bank_options` — options for bank questions (column: `bank_question_id` ⚠️ NOT `question_id`)

### Dev / Utility tables
20. `progress_log` — development log, one entry per session (category, title, description, estimated_mins)

### ⚠️ Important column name difference
`exam_question_options` uses `question_id` to link to its question.
`question_bank_options` uses `bank_question_id` to link to its question.
These are DIFFERENT — all SQL must use the correct column name for each table.

### Schema management
- `db/schema.sql` is the single source of truth — fully verified against live D1 on 2026-03-07
- For a fresh clone: paste the entire `schema.sql` into D1 query pane and run — no ALTER TABLEs needed
- For an existing DB: use `wrangler d1 execute beta_db --remote --command "..."` via Claude Desktop
- All historical ALTER TABLEs are documented at the bottom of `schema.sql` for reference
- Always update `schema.sql` AND run the wrangler command on live DB — never let them drift

### Indexes on D1
```
idx_exam_attempts_exam_id
idx_exam_attempts_user_id
idx_exam_attempts_sitting_id
idx_exam_answers_attempt_id
idx_exam_answers_question_id
```

---

## 🏗️ Dashboards Built

### System Admin (`/sys`) — COMPLETE
### School Admin — COMPLETE — 6 pages with shared nav bar
| Page | Route | Content |
|---|---|---|
| Overview | `/school` | Stats (students, teachers, courses, classes, sittings), pending approvals banner, pending join requests banner |
| Sittings | `/school-sittings` | Sittings table, new sitting button |
| Courses | `/school-courses` | Courses list, create course, assign teacher, enrol student, course rosters with remove buttons |
| Classes | `/school-classes` | Classes table, create class form, Manage links to `/school-class` detail page |
| People | `/school-people` | Members table with role update + remove, add user manually form |
| Join Codes | `/school-join-codes` | Create join code, existing codes table, pending requests (approve/reject), history |

Each page includes the shared top header card (school name, role, switch/profile/logout) and a nav bar (Overview | Sittings | Courses | Classes | People | Join Codes) with the active section highlighted. Nav bar implemented as `schoolNav(activePath)` local helper in `admin.js`.

### Teacher (`/teacher`) — COMPLETE (with exam builder + question bank + sitting badge + approvals pane + pending approvals banner)
### Student (`/student`) — COMPLETE (with My Sittings section)

---

## 🔑 Join Code System — COMPLETE

---

## 📐 Exam Builder — COMPLETE

### Tab order
**Settings → Questions → 👁 Preview → Publish → Access → Results → Approvals**

Preview is a link (not a pane) — opens `/exam-preview?exam_id=X` as a standalone page.
Approvals tab only appears when at least one gate is configured for the exam.

### Settings Pane — COMPLETE
- All fields: title, description, duration, max attempts, schedule, late policy, password, shuffle, navigation mode, results release, score display, pass mark, grade bands, custom fields
- **Locked for Teachers when exam belongs to a sitting** — fully visible but all inputs disabled, clear message shown
- **Always fully editable for School Admin** regardless of sitting membership

### Questions Pane — COMPLETE
- 5 question types: MCQ, Multiple Select, True/False, Short Answer, Essay
- Add, edit, delete, reorder (↑↓)
- Option-level and question-level feedback
- Partial marking for Multiple Select
- **📚 Add from bank** button → goes to bank picker
- Questions added inline are auto-saved to bank as PERSONAL
- Badge shows "📚 From bank" on questions linked to the bank
- Always editable for Teachers and Admins regardless of sitting membership

### Publish Pane — COMPLETE
- Three always-visible blocks: Publish, Close, Release Results
- Full settings summary before publishing
- Padlock icons and faded disabled buttons with clear explanatory messages
- Date stamps on Close and Release Results blocks
- IMMEDIATE policy sets `results_published_at` on publish
- AFTER_CLOSE policy sets `results_published_at` on close
- **Locked for Teachers when exam belongs to a sitting** — clear message shown
- **Always fully functional for School Admin**
- **Gate enforcement for Admin** — Publish blocked if QUESTIONS gate not approved; Release Results blocked if GRADING or RESULTS gate not approved; Close always free

### Access Pane — COMPLETE
- Assign students to an exam by class, by course, or individually
- Uses `exam_access` table

### Results Pane — COMPLETE
- Full submission table — one row per attempt
- Columns: student name, custom field answers, attempt number, grading status, score, percentage, grade, pass/fail, time taken, submitted at
- Summary block: total submissions, in progress, needs grading, average score
- Filters: grading status, pass/fail, class (client-side)
- Sortable columns: name, score, submitted at, time taken
- Export CSV button → `GET /exam-results-csv?exam_id=X`
- Grade button → `/exam-grade?attempt_id=X` for needs grading
- View button → `/exam-grade?attempt_id=X&view=1` for fully graded

### Approvals Pane — COMPLETE
- Tab only appears when at least one approval gate is configured for the exam
- Designed for both sitting-based and future standalone exam approvals
- One block per configured gate — QUESTIONS / GRADING / RESULTS
- Shows gate status: APPROVED ✅ / REJECTED ❌ / PENDING ⏳ / NOT_CONFIGURED
- Per-approver status shown — name + decision
- Rejection note visible when gate is rejected
- Notes available on both APPROVE and REJECT responses
- **Teacher** — sees status, Submit / Resubmit button when gate is ready
- **Admin** — sees status, read only (configures gates in sitting builder)
- Submission rules enforced server-side:
  - QUESTIONS — submittable any time while exam is DRAFT
  - GRADING — only when all attempts are FULLY_GRADED
  - RESULTS — only when GRADING gate is APPROVED or NOT_CONFIGURED
- On resubmission after rejection — old responses deleted, fresh PENDING rows created for all approvers

---

## 👁 Exam Preview Page — COMPLETE (`/exam-preview`)

### Route: `GET /exam-preview?exam_id=X`

A standalone read-only page showing the exam exactly as a student would see it. Serves two purposes: teacher/admin preview and approver review.

### Access
- Teacher who owns the exam
- School Admin of that tenant
- Any user assigned as an approver on any gate for this exam
- Anyone else → redirected away

### Features
- Clean read-only view — no edit controls, no correct answer indicators
- Questions shown in `sort_order` with marks
- Options shown as unselectable radio buttons / checkboxes (MCQ, Multiple Select, True/False)
- Short Answer / Essay shown as a blank greyed-out textarea
- **View toggle** — "All questions" (default) and "One at a time" — client-side, no reload
- One-at-a-time mode: Previous / Next navigation + question counter (e.g. "Question 3 of 12")
- Back link: teachers/admins → exam builder; approvers → `/approvals`

### Approver mode (shown when viewer is an assigned approver with PENDING gate)
- Banner at top: "You are reviewing this exam for the [GATE TYPE] gate"
- Comment textarea below each question (optional, pre-filled from DB if previously saved)
- Other approvers' comments shown read-only with their name on each question
- Gate decision form at the bottom: overall note + Approve / Reject buttons
- Submits to `POST /approval-respond-with-comments`
- Teachers see all approver comments read-only — no comment form for teachers

### Teacher / Admin read-only view
- No comment boxes, no decision form
- Other approvers' submitted comments visible per question (read-only)

---

## ✏️ Grading Screen — COMPLETE (`/exam-grade`)

- Shows ALL questions ordered by `sort_order` (original teacher order — not student shuffle order)
- MCQ/True-False/Multiple Select — read only, shows student answer with ✅ ❌ highlighting, marks awarded
- Short Answer/Essay — student answer, model answer toggle, score input, teacher note field
- Desktop: two column layout — questions left, grading attention sidebar right
- Mobile: floating button opens drawer with questions needing grading
- Sidebar shows only ungraded manual questions, removes them in real time as teacher enters scores
- Live score total updates as teacher types
- `view=1` mode — fully read only, all questions visible, used for reviewing fully graded attempts
- On save: calls `recalcAttempt` from `shared.js` to recalculate totals, redirects to results pane

---

## 📚 Question Bank — COMPLETE

### Routes
| Route | What It Does |
|---|---|
| `/question-bank` | Main page — list, add, edit questions |
| `/qbank-add` | POST: create question in bank |
| `/qbank-update` | POST: update question in bank |
| `/qbank-delete` | POST: delete question (unlinks from exams, doesn't delete exam copies) |
| `/qbank-share` | POST: toggle visibility PERSONAL ↔ SCHOOL |
| `/exam-bank-picker` | Browse bank to pick questions for an exam |
| `/exam-add-from-bank` | POST: copy bank question into exam |

---

## 🎓 Student Dashboard — COMPLETE

- **My Sittings section** — shown above standalone exams when student has at least one attempt in any sitting paper
  - Each sitting card: title, academic year, "X of Y results available"
  - [View Sitting Results] → `/sitting-results?sitting_id=X`
  - Hidden entirely if student has no sittings
- Shows all standalone exams the student has access to via `exam_access`
- Status badges: Open (green), Upcoming (grey), Closed (red), Completed (blue)
- DRAFT exams never shown to students
- Shows 🔒 icon if exam is password protected
- Shows 📋 icon if exam has custom fields
- Attempts remaining shown per exam
- **Button logic:**
  - IN_PROGRESS attempt exists → **Resume Exam** button only
  - No in progress, attempts remaining → **Start Exam** button
  - One submitted attempt → single **View Results** button (active if released, disabled if not)
  - Multiple submitted attempts → one **View Results** button per attempt labelled Attempt 1, Attempt 2 etc

---

## 🏃 Exam Taking Engine — COMPLETE (`attempts.js`)

### Routes
| Route | What It Does |
|---|---|
| `GET /attempt-start` | Pre-flight wizard — password, custom fields, instructions |
| `POST /attempt-start` | Advances wizard steps, creates attempt on final step |
| `GET /attempt-take` | Live exam screen |
| `POST /attempt-take` | Autosave (`action=save`) and submit (`action=submit`) |
| `GET /attempt-complete` | Completion screen |

### Key features
- One active attempt at a time enforcement
- Password re-validated on every POST — no cookies
- Custom field answers carried as hidden fields through wizard
- `question_order_json` snapshotted on attempt creation (shuffle happens here)
- `effective_duration_secs` = min(duration × 60, seconds until ends_at)
- Warning banner if effective duration shorter than full duration
- HARD_CUT enforcement server-side on every POST
- Auto-submit on timer expiry (client JS + server enforcement)
- Answers stored as option IDs — correct answers never in browser HTML
- Pre-submit unanswered question warning with count

### FREE mode navigation
- One question at a time
- Desktop: two column layout — question left, grid sidebar right
- Mobile: floating 📋 button opens drawer
- Question grid squares: grey (unanswered), green (answered), orange (flagged), highlighted border (current)
- Three views: All / 🚩 Flagged / ⬜ Unanswered
- Flagged and Unanswered views filter grid AND Previous/Next cycling
- Unanswered view auto-advances when student answers current question
- Grid updates live in real time — no page reload

### SEQUENTIAL mode
- One question at a time, forward only
- No Previous button
- No flagging
- No grid or sidebar
- Next becomes Submit on last question

---

## 🤖 Auto Grading — COMPLETE

Runs immediately on submit inside `POST /attempt-take`:
- **MCQ / TRUE_FALSE** — checks selected option ID against `is_correct = 1`
- **MULTIPLE_SELECT** — full marks or zero if `partial_marking = 0`; proportional marks with deductions if `partial_marking = 1`, floored at 0
- **SHORT_ANSWER / ESSAY** — skipped, left for manual grading
- Recalculates `score_raw`, `score_total`, `score_pct`, `grade`, `grading_status` via `recalcAttempt` in `shared.js`
- `grading_status` = `FULLY_GRADED` if no manual questions, `AUTO_GRADED` if manual questions remain

---

## 📊 Student Results Page — COMPLETE (`results.js`)

### Route: `GET /attempt-results?attempt_id=X`

- Only accessible when `results_published_at` is set and in the past
- If not released → clean "not released yet" message, nothing else shown

### Sections
1. **Header** — school name, exam title, course, class
2. **Student details** — name, custom field answers, attempt number, submitted at, time taken
3. **Exam details** — total marks, questions, duration, pass mark, grade bands table
4. **Result** — score/percentage/grade respecting `score_display` setting, Pass/Fail badge
5. **Actions** — Review My Answers (if `allow_review = 1`), Back to My Exams, 🖨 Print button

### score_display behaviour
- `BOTH` → percentage + raw marks
- `PERCENT` → percentage only
- `MARKS` → raw marks only
- `NONE` → grade and pass/fail only, no numbers

### Print
- `@media print` CSS hides action buttons
- Page prints as a clean official result slip

---

## 🔍 Student Review Page — COMPLETE (`results.js`)

### Route: `GET /attempt-review?attempt_id=X`

- Only accessible if `allow_review = 1` on the exam AND `results_published_at` is set and in the past
- If either condition fails → clean meaningful message shown, no content exposed
- Access is enforced server-side — students cannot bypass by visiting the URL directly
- Review button only appears on results page if `allow_review = 1` — defence in depth

### Page layout
1. **Top bar** — back arrow to `/attempt-results?attempt_id=X`, exam title
2. **Mini score banner** — compact score/grade/pass-fail respecting `score_display` from `exam_attempts`
3. **Questions** — one card per question, in `question_order_json` order (the order the student actually saw them), numbered Q1, Q2 etc. Marks awarded shown top-right of each card.

### Per question type

**MCQ / TRUE_FALSE / MULTIPLE_SELECT:**
- All options listed
- Green tick = correct option; Red cross = incorrect option
- Student's chosen option(s) highlighted
- Amber highlight for correct options the student missed (MULTIPLE_SELECT)
- Option-level `feedback` shown below each option — only if not empty
- Question-level `feedback` shown at bottom of card in soft blue/grey box — only if not empty

**SHORT_ANSWER / ESSAY:**
- Student's answer in a light grey box labelled "Your answer"
- `model_answer` shown in a soft green box labelled "Model answer" — only if not empty
- `teacher_note` from `exam_answers` shown in a yellow box labelled "Teacher note" — only if not empty
- Marks awarded shown clearly

### Design decisions
- No student name or personal details on the page — it is a learning tool, not an official document
- Print version with student name deferred — can be added later if needed
- All feedback boxes only render when content exists — no empty labels
- Read only — no forms, no inputs

---

## 📋 Sittings — COMPLETE (`sittings.js`)

### What a sitting is
A sitting groups multiple exam papers under one formal event (e.g. "June 2026 Finals"). It is a School Admin / Exams Officer tool. Individual exams are unchanged — a sitting is a grouping layer only. QAcademy does not calculate combined scores — each paper result stands on its own. Sittings are the primary workflow for schools running professional or formal exams.

### Routes
| Route | What It Does |
|---|---|
| `GET /sittings` | List all sittings for the school |
| `GET /sitting-builder?sitting_id=X` | Manage a sitting — Settings, Papers, Approvals, Results tabs |
| `POST /sitting-create` | Create new sitting |
| `POST /sitting-save-settings` | Save sitting title, description, academic year, status |
| `POST /sitting-add-paper` | Add a paper — Mode 1 (link existing) or Mode 2 (create new) |
| `POST /sitting-remove-paper` | Remove a paper from the sitting |
| `GET /sitting-gate-settings?sitting_id=X&exam_id=Y` | Configure approval gates per paper |
| `POST /sitting-gate-save` | Add an approver to a gate |
| `POST /sitting-gate-remove-approver` | Remove an approver from a gate |
| `GET /approvals` | Approval inbox — any school role |
| `POST /approval-respond` | Submit approve/reject from inbox (no per-question comments) |
| `GET /exam-preview?exam_id=X` | Standalone exam preview + approver review page |
| `POST /approval-respond-with-comments` | Submit approve/reject with per-question comments |

### Sitting builder tabs

**Settings tab:**
- Title, description, academic year, status (DRAFT/ACTIVE/CLOSED)

**Papers tab:**
- List of papers in sitting — title, course, teacher, exam status badge
- Mode 1 — link an existing exam (any status)
- Mode 2 — create new DRAFT exam — enter title, select course, assign teacher → exam auto-created and appears on teacher's dashboard immediately. Teacher added to course_teachers if not already assigned.

**Approvals tab:**
- Overview table — one row per paper: Paper | Course | Teacher | Q/G/R gate badges | [Set Approvals] button
- Gate badges show count of approvers per gate — grey if 0 (inactive), green badge if 1+ (active)
- [Set Approvals] → `/sitting-gate-settings` page for that paper

**Results tab:**
- One row per student with at least one attempt in any paper
- Columns: student name + one column per paper in sort_order
- Each cell: result respecting score_display if released, "Pending" if not, "—" if no attempt
- Clicking a released cell → `/attempt-results?attempt_id=X`
- No combined score

### Gate settings page (`/sitting-gate-settings`)
- Three gate cards — QUESTIONS / GRADING / RESULTS
- Each card: description of what gate controls, list of assigned approvers with role label and Remove button, Add approver section
- Add approver picker:
  - Role filter — dynamic, reads distinct roles from memberships table, never hardcoded, future-proof
  - Course filter — all active courses in school, default "All courses"
  - Both filters work together client-side, no page reload
  - Approver dropdown shows name + role label using `roleLabel()` helper
  - Already assigned approvers excluded from dropdown
- No approvers assigned → gate inactive, muted message shown
- Approvers assigned → green "Active" badge on card header

### Sitting rules on exams
When an exam belongs to a sitting:
- **Teacher** — Settings pane locked (visible but all inputs disabled), Publish pane locked
- **School Admin** — Settings pane fully editable, Publish pane fully functional
- Sitting rules take effect immediately when exam is added — regardless of prior status
- ⚠️ Warning when adding already-published exam to a sitting — deferred improvement

### Student sitting results (`GET /sitting-results?sitting_id=X`)
- Student role only — enforced server-side
- Student must have at least one attempt in at least one paper
- Shows all papers in sort_order: paper title, course, result or "Pending"
- [View] button on released papers → `/attempt-results?attempt_id=X`
- No combined score

---

## 🔐 Approval Gates — COMPLETE (`sittings.js` + `exams.js`)

### What approval gates are
Optional sign-off checkpoints per exam paper. Admin configures which gates are active and who the approvers are. Teacher submits work for approval. All assigned approvers must approve before the gate clears. Any one rejection sends it back to the teacher.

### Three gate types
- **QUESTIONS** — must be approved before admin can publish the exam
- **GRADING** — must be approved before admin can release results
- **RESULTS** — final sign-off before results go live (additional gate after grading)

### Approval system design
- Gates are configured per exam — designed to work for sitting-based exams now and standalone exams in the future
- Approvers are specific people — any active school user regardless of role
- Multiple approvers per gate — ALL must approve for gate to clear
- Any one rejection → gate fails, teacher notified, must fix and resubmit
- Notes are optional on both APPROVE and REJECTED responses
- On resubmission — all previous responses deleted, fresh PENDING rows created for all approvers
- `getGateStatus()` helper in exams.js — returns APPROVED / REJECTED / PENDING / NOT_CONFIGURED

### Gate progression rules
- QUESTIONS gate cleared → Admin can publish exam
- GRADING gate cleared → Admin can release results
- RESULTS gate cleared → Admin can release results (if results gate configured)
- GRADING gate submission — only allowed when all submitted attempts are FULLY_GRADED
- RESULTS gate submission — only allowed when GRADING gate is APPROVED or NOT_CONFIGURED

### DB tables
- `sitting_approval_gates` — one row per approver per gate per exam (sitting_id, exam_id, gate_type, user_id, tenant_id)
- `sitting_approval_responses` — one row per approver decision (exam_id, gate_type, approver_id, status, note, responded_at)
- `sitting_approval_comments` — per-question comments (exam_id, gate_type, question_id, approver_id, tenant_id, comment)

---

## 📬 Approval Inbox — COMPLETE (`sittings.js`)

### Route: `GET /approvals`
- Accessible to any logged-in school user (Teacher, Admin, or any role assigned as approver)
- Queries `sitting_approval_gates` for gates where `user_id = current user`
- Joins against `sitting_approval_responses` to surface items where the user's response is still PENDING
- Each pending item shows: exam title, sitting title, gate type badge, submitter (teacher) name, "View exam →" link to `/exam-preview`, inline approve/reject form with optional note
- Empty state shown when nothing pending
- Recent (previously actioned) items shown read-only below in a "Recent" table
- After responding → redirects to `/approvals`

### Route: `POST /approval-respond`
- Validates current user is an assigned approver for the gate
- Upserts response row in `sitting_approval_responses`
- Redirects to `/approvals`

### Route: `POST /approval-respond-with-comments`
- Same as above but also saves per-question comments to `sitting_approval_comments` (upsert per question)
- Used when approver submits from `/exam-preview`

### Dashboard banners
- **School Admin** (`/school`) and **Teacher** (`/teacher`) dashboards show a 📬 pending banner when the user has items waiting
- Banner: "📬 You have X pending approval(s) — View Inbox →"
- Hidden entirely when count is 0
- **Student** dashboard intentionally excluded — students are never approvers

---

## ⏳ What Comes Next (In Order)

### Phase 9 — Admin Dashboard Restructure + app.js split ✅ COMPLETE
- [x] Split `app.js` into `auth.js`, `sys.js`, `admin.js`, `teacher.js`, `student.js`
- [x] School Admin dashboard restructured into 6 separate pages with shared nav bar:
  - `/school` — Overview (stats, banners)
  - `/school-sittings` — Sittings
  - `/school-courses` — Courses, rosters, assign/enrol
  - `/school-classes` — Classes, create, manage
  - `/school-people` — Members, roles, add user
  - `/school-join-codes` — Join codes, requests

### Phase 9.5 — Grading Gate Approver Review Page
- [ ] Dedicated approver review page for the GRADING gate (similar to exam-preview for the QUESTIONS gate)

### Phase 10 — Question Bank Bulk Import (CSV/Excel)

### Phase 11 — UI & Design Polish
- [ ] Consistent visual language across the whole platform
- [ ] Proper typography, spacing, colours
- [ ] Mobile experience polished
- [ ] Loading states, empty states, error states
- [ ] Design system so everything stays consistent

### Deferred small improvements
- **Warning when adding published exam to a sitting** — "This exam is already published and may have active students. Sitting rules will apply from this point forward."
- **Results pane** — summary cards showing total pass/fail counts, filter by grade band
- **exam_access extension** — add `access_source` (CLASS/COURSE/INDIVIDUAL) and `source_id` columns
- **Anti-cheat / proctoring** — Page Visibility API, Fullscreen enforcement, violation log
- **question_display setting** — ONE_AT_A_TIME | ALL per exam
- **Printable review page** — student name shown only in `@media print`
- **Printable marksheet** — teacher prints grading screen as official marksheet

### Phase 2 — Auth Improvements (Deferred)
- [ ] Forgot password flow
- [ ] Email verification
- [ ] Bulk import students/teachers

---

## 💡 Important Decisions & Preferences

- **Modular file structure** — shared.js, auth.js, sys.js, admin.js, teacher.js, student.js, exams.js, question-bank.js, attempts.js, results.js, sittings.js
- **app.js split into auth.js, sys.js, admin.js, teacher.js, student.js in Phase 9** — each handler file owns its own routes, [[path]].js is pure routing with no logic
- **School Admin dashboard restructured into 6 separate pages in Phase 9** — /school (overview), /school-sittings, /school-courses, /school-classes, /school-people, /school-join-codes; shared nav bar via schoolNav(activePath) helper in admin.js
- **No third party auth** — custom built
- **SQLite via D1** — TEXT for IDs and timestamps
- **PBKDF2** passwords, 40,000 iterations, pepper from `env.APP_SECRET`
- **Tenant isolation** — every query includes `tenant_id`
- **Status fields** uppercase: `DRAFT`, `PUBLISHED`, `ACTIVE`, `CLOSED` etc.
- **Delete-and-reinsert** pattern for repeating rows (grade bands, custom fields, options)
- **Question bank sync rule**: DRAFT exam = sync to bank; PUBLISHED exam = frozen copy
- **Visibility**: PERSONAL (teacher only) or SCHOOL (all teachers in tenant)
- **System Admin stays in `/sys` only** — no access to school content unless given a membership
- **Two exam access modes**: Structured (course/class based) and Open (password only)
- **Questions and settings locked once exam is PUBLISHED** — teachers contact support for edits (deferred)
- **Always commit directly to main** — never create a new branch
- **Exam taking engine is specialised** — it only runs exams, never handles results or grading
- **Exam complete screen** — engine shows "results available" or "results released later" depending on policy, then student navigates to results page separately
- **Two results paths** — standalone exam results and sitting results (combined papers)
- **Sittings are a grouping layer only** — individual exams are unchanged, sitting just links them together
- **No combined scores in sittings** — QAcademy delivers clean individual paper results; schools apply their own grading formula externally
- **Sittings = primary workflow for serious schools** — formal exam bodies, professional certifications, national exams all use sitting-based organisation
- **Approval gates are configurable per sitting** — not hardcoded; each sitting defines its own rules. Designed to support standalone exam approvals in future too.
- **Approvers are specific people not roles** — any active school user can be assigned as approver regardless of their role
- **Role filter in approver picker is dynamic** — reads distinct roles from memberships table, never hardcoded, future-proof
- **Approval notes on both approve and reject** — approver can always leave a note regardless of decision
- **Per-question comments saved with gate decision** — not autosaved; approver reviews all questions then submits in one action
- **Per-question comments visible to all approvers on that gate + the teacher** — comments persist across resubmissions
- **Exam preview page serves dual purpose** — teacher/admin preview AND approver review page; same route, approver mode activated automatically
- **Students excluded from approval inbox banner** — students are never approvers
- **Key settings snapshotted on attempt** — `score_display`, `pass_mark_percent`, `grade_bands_json`, `question_order_json` stored on `exam_attempts` so results always reflect settings at time of sitting
- **Publish pane design principle** — always show all blocks, explain why buttons are disabled, never hide
- **Grading screen shows questions in `sort_order`** — original teacher order, not student shuffle order
- **Student review page shows questions in `question_order_json` order** — the order the student actually saw
- **Teacher always sees full scores** — `score_display` setting only affects what students see
- **New columns before new tables** — always consider adding columns to existing tables before creating new ones
- **recalcAttempt lives in shared.js** — used by both auto grading (attempts.js) and manual grading (exams.js)
- **Review page is a learning tool** — no personal details shown on screen; print version with name deferred
- **app.js will be split in Phase 9** — into admin.js, teacher.js, student.js alongside admin dashboard restructure
- **UI polish deferred to Phase 11** — build logic and flows correctly first, then do one focused design sprint across the whole platform
- When doing a full rewrite of all files, always verify actual D1 column names match code before deploying

---

## 🔧 Environment Variables
```
APP_SECRET   → pepper for password hashing (set in Cloudflare Pages settings)
```

---

## 🐛 Bugs Fixed & Lessons Learned

- `question_bank_options` table uses `bank_question_id` (not `question_id`) — always check actual D1 column names with `PRAGMA table_info(table_name)` before writing SQL
- When rewriting files, the safest approach is to rewrite ALL files at once to guarantee they are in sync
- Cloudflare D1 does not support `pragma_table_info` in a JOIN or `WHERE m.type = 'table'` — use `PRAGMA table_info(table_name)` directly, one table at a time
- Duplicate add-from-bank bug fixed — check for existing `bank_question_id` before inserting
- `ends_at` past date edge case fixed in Publish pane
- IMMEDIATE policy sets `results_published_at` on publish; AFTER_CLOSE sets it on close
- Claude Desktop defaults to creating new branches — always explicitly instruct it to commit directly to main
- `exam_access` does not have a `resource_type` column — class lookup must go via `class_students` joined to `classes`, not via `exam_access`
- Large handler rewrites frequently hit the 32000 output token limit — always instruct Claude to split into two parts if this happens
- Sitting lock on publish and settings pane must check role — Teachers locked, School Admins always have full access
- When exam is added to a sitting, sitting rules take effect immediately regardless of prior exam status
- DB migrations must be run against live D1 via wrangler — schema.sql updates alone are not enough; always run the wrangler command immediately after updating schema.sql
- Approval inbox banner should not appear on Student dashboard — students are never approvers

---

*Last updated: 2026-03-09. Phase 9 complete (app.js split + School Admin dashboard restructured into 6 pages). Next: Phase 9.5 (Grading gate approver review page).*
