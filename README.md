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
  app.js            → User, auth, school, admin routes
  exams.js          → Exam builder routes + teacher results pane + grading screen
  question-bank.js  → Question bank routes
  attempts.js       → Exam taking engine routes (student)
  results.js        → Student results page, review page, sitting results (future)

db/
  schema.sql        → Reference schema — run once in D1 for a fresh clone

wrangler.toml       → Cloudflare config
```

### Why [[path]].js?
The double brackets are **required by Cloudflare Pages** — it's their syntax for a catch-all route handler. Cannot be renamed.

### Routing Logic in [[path]].js
```
/question-bank, /qbank-*                → question-bank.js
/exam-create, /exam-builder,
/exam-save-settings, /exam-*,
/exam-bank-picker, /exam-add-from-bank,
/exam-grade, /exam-results-csv          → exams.js
/attempt-start, /attempt-take,
/attempt-complete                       → attempts.js
/attempt-results, /attempt-review       → results.js
everything else                         → app.js
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
### School Admin (`/school`) — COMPLETE (including Class management)
### Teacher (`/teacher`) — COMPLETE (with exam builder + question bank)
### Student (`/student`) — COMPLETE

---

## 🔑 Join Code System — COMPLETE

---

## 📐 Exam Builder — COMPLETE

### Settings Pane — COMPLETE
All fields: title, description, duration, max attempts, schedule, late policy, password, shuffle, navigation mode, results release, score display, pass mark, grade bands, custom fields.

### Questions Pane — COMPLETE
- 5 question types: MCQ, Multiple Select, True/False, Short Answer, Essay
- Add, edit, delete, reorder (↑↓)
- Option-level and question-level feedback
- Partial marking for Multiple Select
- **📚 Add from bank** button → goes to bank picker
- Questions added inline are auto-saved to bank as PERSONAL
- Badge shows "📚 From bank" on questions linked to the bank

### Publish Pane — COMPLETE
- Three always-visible blocks: Publish, Close, Release Results
- Full settings summary before publishing
- Padlock icons and faded disabled buttons with clear explanatory messages
- Date stamps on Close and Release Results blocks
- IMMEDIATE policy sets `results_published_at` on publish
- AFTER_CLOSE policy sets `results_published_at` on close

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

- Shows all exams the student has access to via `exam_access`
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

## ⏳ What Comes Next (In Order)

### Phase 8 — Sittings (School Admin)
- [ ] Create sittings, assign papers
- [ ] Sitting results page — combined view across papers
- [ ] Drill into individual paper → `/attempt-results?attempt_id=X`

### Phase 9 — Question Bank bulk import (CSV/Excel)

### Future improvements noted
- **Results pane** — summary cards showing total pass/fail counts, filter by grade band
- **Grading view** — currently shows all questions, teacher sees full attempt context
- **exam_access extension** — add `access_source` (CLASS/COURSE/INDIVIDUAL) and `source_id` columns to track how each student was granted access. Enables accurate class display on result slip and clean removal of access by class.
- **Anti-cheat / proctoring** — Page Visibility API to detect tab switching, Fullscreen API enforcement, violation log on `exam_attempts` as `violations_json`, configurable auto-submit after X violations, teacher sees violation summary in results pane
- **question_display setting** — add `ONE_AT_A_TIME | ALL` to exam settings for teacher to override FREE mode display. New column on `exams` table, snapshot onto `exam_attempts`.
- **Printable review page** — student name shown only in `@media print`, hidden on screen
- **Printable marksheet** — teacher prints grading screen as official marksheet, questions in `sort_order`

### Phase 2 — Auth Improvements (Deferred)
- [ ] Forgot password flow
- [ ] Email verification
- [ ] Bulk import students/teachers

---

## 💡 Important Decisions & Preferences

- **Modular file structure** — split into shared.js, app.js, exams.js, question-bank.js, attempts.js, results.js
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
- **Key settings snapshotted on attempt** — `score_display`, `pass_mark_percent`, `grade_bands_json`, `question_order_json` stored on `exam_attempts` so results always reflect settings at time of sitting
- **Publish pane design principle** — always show all blocks, explain why buttons are disabled, never hide
- **Grading screen shows questions in `sort_order`** — original teacher order, not student shuffle order
- **Student review page shows questions in `question_order_json` order** — the order the student actually saw
- **Teacher always sees full scores** — `score_display` setting only affects what students see
- **New columns before new tables** — always consider adding columns to existing tables before creating new ones
- **recalcAttempt lives in shared.js** — used by both auto grading (attempts.js) and manual grading (exams.js)
- **Review page is a learning tool** — no personal details shown on screen; print version with name deferred
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

---

*Last updated: 2026-03-08. Exam taking engine complete. Auto grading complete. Teacher results pane and manual grading screen complete. Student results page complete. Student review page complete (Phase 6). Next: Sittings (Phase 8).*
