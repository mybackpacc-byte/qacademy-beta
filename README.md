

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
- **Environment:** Everything done in the browser — GitHub website for code, Cloudflare dashboard for database

---

## 🛠️ Tech Stack

| Layer | Tool |
|---|---|
| Frontend + Routing | Cloudflare Pages |
| Backend Logic | Cloudflare Workers |
| Database | Cloudflare D1 (SQLite) |
| Authentication | Custom built |
| Code Repository | GitHub |
| Database Management | Cloudflare D1 Query Pane |

### Important Notes On Environment
- User works **entirely in the browser** — no terminal
- All code edited directly on **GitHub website**
- Database tables created using **Cloudflare D1 query pane**
- Keep all instructions **browser-friendly**
- Claude cannot directly read from or push to GitHub repo

---

## 📁 Repository Structure
```
functions/
  [[path]].js       → Entry point router — directs traffic to correct handler
  shared.js         → All shared helpers (auth, DB, crypto, cookies, HTML)
  app.js            → User, auth, school, admin routes
  exams.js          → Exam builder routes
  question-bank.js  → Question bank routes

db/
  schema.sql        → Reference schema (not auto-run)

wrangler.toml       → Cloudflare config
```

### Why [[path]].js?
The double brackets are **required by Cloudflare Pages** — it's their syntax for a catch-all route handler. Cannot be renamed.

### Routing Logic in [[path]].js
```
/question-bank, /qbank-*                → question-bank.js
/exam-create, /exam-builder,
/exam-save-settings, /exam-*,
/exam-bank-picker, /exam-add-from-bank  → exams.js
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
| Student | `/student` — takes exams (shell only) |

---

## 🗄️ Database Tables — ALL CREATED IN D1

### Core tables
1. `tenants` — schools
2. `users` — all people
3. `sessions` — login sessions
4. `memberships` — user ↔ school ↔ role
5. `courses` — subjects within a school
6. `course_teachers` — teacher ↔ course
7. `enrollments` — student ↔ course
8. `join_codes` — invite codes
9. `join_requests` — pending approvals

### Exam tables
10. `exams` — exam metadata + all settings
11. `exam_grade_bands` — grade band rows per exam
12. `exam_custom_fields` — custom fields per exam
13. `exam_questions` — questions per exam
14. `exam_question_options` — options per question (column: `question_id`)

### Question bank tables
15. `question_bank` — master question library
16. `question_bank_options` — options for bank questions (column: `bank_question_id` ⚠️ NOT question_id)

### ALTER TABLE run
```sql
ALTER TABLE exam_questions ADD COLUMN bank_question_id TEXT;
```

### ⚠️ Important column name difference
`exam_question_options` uses `question_id` to link to its question.
`question_bank_options` uses `bank_question_id` to link to its question.
These are DIFFERENT — all SQL must use the correct column name for each table.

---

## 🏗️ Dashboards Built

### System Admin (`/sys`) — COMPLETE
### School Admin (`/school`) — COMPLETE
### Teacher (`/teacher`) — COMPLETE (with exam builder + question bank link)
### Student (`/student`) — SHELL ONLY

---

## 🔑 Join Code System — COMPLETE

---

## 📐 Exam Builder — COMPLETE (Settings + Questions panes)

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

### Publish / Access / Results panes — STUB (coming soon)

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

### Visibility Rules
- **PERSONAL** — only the creating teacher can see and use it. Default for all new questions.
- **SCHOOL** — all teachers in the same school can see and add it to their exams
- Only the question owner can edit, delete, or toggle visibility
- Other teachers can use SCHOOL questions read-only

### Bank Sync Rules
- Every question added inline in the exam builder is **auto-saved to the bank as PERSONAL**
- `bank_question_id` on `exam_questions` links back to the bank source
- While exam is **DRAFT**: editing an exam question syncs the changes back to the bank
- Once exam is **PUBLISHED**: exam copy is frozen — bank evolves independently
- Deleting from bank sets `bank_question_id=NULL` on linked exam questions (does not delete them)

### Filters
- Filter by question type
- Filter by visibility (All / My questions / School questions)

---

## ⏳ What Comes Next (In Order)

### Remaining Exam Builder panes
- [ ] Publish pane — publish exam, close exam, release results
- [ ] Access pane — assign classes/students to exam
- [ ] Results pane — view submissions, grades, release to students

### Phase 4 — Exam Taking Engine
- [ ] Student sees available exams on dashboard
- [ ] Timed exam with countdown timer
- [ ] Auto-save answers every 30 seconds
- [ ] Auto-submit on time expiry
- [ ] One attempt at a time enforcement
- [ ] Custom fields collected before exam starts
- [ ] Exam password check before starting

### Phase 5 — Grading & Results
- [ ] Auto-grade MCQ and True/False
- [ ] Teacher manually grades Short Answer and Essay
- [ ] Publish results to students
- [ ] Student review mode (if allow_review enabled)

### Phase 6 — Question Bank bulk import (CSV/Excel)

### Phase 2 — Auth Improvements (Deferred)
- [ ] Forgot password flow
- [ ] Email verification
- [ ] Bulk import students/teachers

---

## 💡 Important Decisions & Preferences

- **Modular file structure** — split into shared.js, app.js, exams.js, question-bank.js
- **No third party auth** — custom built
- **Browser only workflow** — no terminal
- **SQLite via D1** — TEXT for IDs and timestamps
- **PBKDF2** passwords, 40,000 iterations, pepper from `env.APP_SECRET`
- **Tenant isolation** — every query includes `tenant_id`
- **Status fields** uppercase: `DRAFT`, `PUBLISHED`, `ACTIVE` etc.
- **Delete-and-reinsert** pattern for repeating rows (grade bands, custom fields, options)
- **Question bank sync rule**: DRAFT exam = sync to bank; PUBLISHED exam = frozen copy
- **Visibility**: PERSONAL (teacher only) or SCHOOL (all teachers in tenant)
- When doing a full rewrite of all files, always verify actual D1 column names match code before deploying

---

## 🔧 Environment Variables
```
APP_SECRET   → pepper for password hashing (set in Cloudflare Pages settings)
```

---

## 🐛 Bugs Fixed & Lessons Learned

- `question_bank_options` table uses `bank_question_id` (not `question_id`) — always check actual D1 column names with `PRAGMA table_info(table_name)` before writing SQL
- When rewriting files, the safest approach is to rewrite ALL five files at once to guarantee they are in sync
- Cloudflare D1 does not support `pragma_table_info` in a JOIN or `WHERE m.type = 'table'` — use `PRAGMA table_info(table_name)` directly, one table at a time

---
*Last updated: Question bank fully working. All five files in sync. Next session: Publish pane, then exam taking engine.*

Changes to make:
1. Update "Important Notes On Environment" — add:

Claude Code Desktop now installed and connected to GitHub repo
git pull before each Claude Code session if GitHub was edited directly

2. Update Dashboards Built section:

School Admin (/school) → add "including Class management"
Publish pane → change from STUB to COMPLETE

3. Update Database Tables — add:

17. classes — class groups within a school
18. class_students — student ↔ class link
ALTER TABLE exams ADD COLUMN closed_at TEXT;

4. Update What Comes Next:

Publish pane → ✅ COMPLETE
Access pane → still next
Add Classes → ✅ COMPLETE (move out of next steps)

5. Add to Important Decisions:

System Admin stays in /sys only — no access to school content unless given a membership
Two exam access modes: Structured (course/class based) and Open (password only)
Questions and settings locked once exam is PUBLISHED
System Admin can edit published questions in future (deferred — teachers contact support)

6. Update Bugs Fixed & Lessons Learned — add:

Duplicate add-from-bank bug fixed — check for existing bank_question_id before inserting
ends_at past date edge case fixed in Publish pane
IMMEDIATE policy sets results_published_at on publish; AFTER_CLOSE sets it on close

7. Update last line:
*Last updated: Publish pane complete. Classes built. Next: Access pane, then exam taking engine.*
