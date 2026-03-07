-- ============================================================
-- QAcademy Beta — schema.sql
-- Cloudflare D1 (SQLite)
--
-- PURPOSE: This file is the single source of truth for the
-- database schema. It is written so that a fresh clone of the
-- repo can run this file once in the D1 query pane and get a
-- fully working, empty database — with no manual ALTER TABLEs
-- needed afterwards.
--
-- HOW TO USE FOR A FRESH CLONE:
--   1. Create a new D1 database in Cloudflare.
--   2. Open the D1 Query Pane.
--   3. Paste this entire file and click Run.
--   4. All tables will be created. Done.
--
-- HOW TO UPDATE THIS FILE WHEN THE SCHEMA CHANGES:
--   - If you ADD a column, add it here inside the CREATE TABLE.
--   - If you ADD a table, add a new CREATE TABLE block here.
--   - Never use ALTER TABLE in this file. ALTER TABLE is only
--     needed on an already-running database (see MIGRATIONS
--     section at the bottom).
-- ============================================================


-- ============================================================
-- CORE TABLES
-- ============================================================

-- 1. tenants — one row per school
CREATE TABLE IF NOT EXISTS tenants (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | SUSPENDED
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

-- 2. users — every person across all schools
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  password_salt   TEXT NOT NULL,
  password_iter   INTEGER NOT NULL,
  is_system_admin INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | SUSPENDED
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- 3. sessions — login sessions (token stored hashed)
CREATE TABLE IF NOT EXISTS sessions (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL,
  token_hash        TEXT NOT NULL UNIQUE,
  active_tenant_id  TEXT,
  expires_at        TEXT NOT NULL,
  created_at        TEXT NOT NULL
);

-- 4. memberships — user <-> school <-> role
CREATE TABLE IF NOT EXISTS memberships (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  tenant_id   TEXT NOT NULL,
  role        TEXT NOT NULL, -- STUDENT | TEACHER | SCHOOL_ADMIN
  status      TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | SUSPENDED
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

-- 5. courses — subjects within a school
CREATE TABLE IF NOT EXISTS courses (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL,
  title       TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | ARCHIVED
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

-- 6. course_teachers — teacher <-> course link
CREATE TABLE IF NOT EXISTS course_teachers (
  course_id   TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (course_id, user_id)
);

-- 7. enrollments — student <-> course link
CREATE TABLE IF NOT EXISTS enrollments (
  course_id   TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (course_id, user_id)
);

-- 8. join_codes — invite codes for joining a school or course
CREATE TABLE IF NOT EXISTS join_codes (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL,
  code_hash           TEXT NOT NULL UNIQUE,
  scope               TEXT NOT NULL, -- TENANT_ROLE | COURSE_ENROLL | COURSE_TEACHER
  role                TEXT,          -- STUDENT | TEACHER | SCHOOL_ADMIN (for TENANT_ROLE)
  course_id           TEXT,          -- set when scope is COURSE_*
  auto_approve        INTEGER NOT NULL DEFAULT 1,
  max_uses            INTEGER,
  uses_approved       INTEGER NOT NULL DEFAULT 0,
  revoked             INTEGER NOT NULL DEFAULT 0,
  expires_at          TEXT,
  status              TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | DISABLED
  created_by_user_id  TEXT NOT NULL,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

-- 9. join_requests — pending approvals from join codes
CREATE TABLE IF NOT EXISTS join_requests (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL,
  user_id             TEXT NOT NULL,
  join_code_id        TEXT NOT NULL,
  type                TEXT NOT NULL, -- MEMBERSHIP | COURSE_ENROLL | COURSE_TEACHER
  requested_role      TEXT,
  course_id           TEXT,
  status              TEXT NOT NULL DEFAULT 'PENDING', -- PENDING | APPROVED | REJECTED
  reviewed_by_user_id TEXT,
  reviewed_at         TEXT,
  created_at          TEXT NOT NULL
);

-- 17. classes — class groups within a school
CREATE TABLE IF NOT EXISTS classes (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  name          TEXT NOT NULL,
  year_group    TEXT,
  academic_year TEXT,
  description   TEXT,
  status        TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | ARCHIVED
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

-- 18. class_students — student <-> class link
CREATE TABLE IF NOT EXISTS class_students (
  id          TEXT PRIMARY KEY,
  class_id    TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);


-- ============================================================
-- EXAM TABLES
-- ============================================================

-- 10. exams — one row per exam, holds all settings
CREATE TABLE IF NOT EXISTS exams (
  id                      TEXT PRIMARY KEY,
  tenant_id               TEXT NOT NULL,
  course_id               TEXT NOT NULL,
  created_by              TEXT NOT NULL,
  title                   TEXT NOT NULL,
  description             TEXT,

  -- Scheduling
  duration_mins           INTEGER NOT NULL DEFAULT 60,
  max_attempts            INTEGER NOT NULL DEFAULT 1,
  starts_at               TEXT,
  ends_at                 TEXT,
  late_submission_policy  TEXT,  -- HARD_CUT | ALLOW_LATE | null

  -- Access
  exam_password           TEXT,

  -- Question behaviour
  shuffle_questions       INTEGER NOT NULL DEFAULT 0,
  shuffle_options         INTEGER NOT NULL DEFAULT 0,
  show_marks_during       INTEGER NOT NULL DEFAULT 0,
  allow_review            INTEGER NOT NULL DEFAULT 0,
  navigation_mode         TEXT NOT NULL DEFAULT 'FREE', -- FREE | SEQUENTIAL

  -- Results
  results_release_policy  TEXT NOT NULL DEFAULT 'MANUAL', -- MANUAL | IMMEDIATE | AFTER_CLOSE
  score_display           TEXT NOT NULL DEFAULT 'BOTH',   -- BOTH | PERCENT | MARKS | NONE
  pass_mark_percent       REAL,

  -- Lifecycle
  status                  TEXT NOT NULL DEFAULT 'DRAFT',  -- DRAFT | PUBLISHED | CLOSED
  published_at            TEXT,
  published_by            TEXT,
  closed_at               TEXT,
  results_published_at    TEXT,

  created_at              TEXT NOT NULL,
  updated_at              TEXT NOT NULL
);

-- 11. exam_grade_bands — grade band rows per exam
CREATE TABLE IF NOT EXISTS exam_grade_bands (
  id          TEXT PRIMARY KEY,
  exam_id     TEXT NOT NULL,
  label       TEXT NOT NULL,
  min_percent REAL NOT NULL,
  created_at  TEXT NOT NULL
);

-- 12. exam_custom_fields — custom fields collected before exam starts
CREATE TABLE IF NOT EXISTS exam_custom_fields (
  id            TEXT PRIMARY KEY,
  exam_id       TEXT NOT NULL,
  field_label   TEXT NOT NULL,
  field_type    TEXT NOT NULL DEFAULT 'TEXT', -- TEXT | DROPDOWN | NUMBER
  field_options TEXT,   -- comma-separated options for DROPDOWN type
  is_required   INTEGER NOT NULL DEFAULT 0,
  sort_order    INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);

-- 13. exam_questions — questions belonging to an exam
CREATE TABLE IF NOT EXISTS exam_questions (
  id                TEXT PRIMARY KEY,
  exam_id           TEXT NOT NULL,
  tenant_id         TEXT NOT NULL,
  question_type     TEXT NOT NULL, -- MCQ | MULTIPLE_SELECT | TRUE_FALSE | SHORT_ANSWER | ESSAY
  question_text     TEXT NOT NULL,
  marks             REAL NOT NULL DEFAULT 1,
  sort_order        INTEGER NOT NULL DEFAULT 0,
  partial_marking   INTEGER NOT NULL DEFAULT 0,
  model_answer      TEXT,
  feedback          TEXT,
  bank_question_id  TEXT,  -- link back to question_bank; NULL if not from bank
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

-- 14. exam_question_options — answer options per exam question
--  ⚠️  Foreign key column is called question_id (NOT bank_question_id)
CREATE TABLE IF NOT EXISTS exam_question_options (
  id          TEXT PRIMARY KEY,
  question_id TEXT NOT NULL,  -- references exam_questions.id
  option_text TEXT NOT NULL,
  is_correct  INTEGER NOT NULL DEFAULT 0,
  feedback    TEXT,
  sort_order  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

-- 19. exam_access — students/users explicitly granted access to an exam
CREATE TABLE IF NOT EXISTS exam_access (
  id          TEXT PRIMARY KEY,
  exam_id     TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  added_by    TEXT NOT NULL,
  created_at  TEXT NOT NULL
);


-- ============================================================
-- QUESTION BANK TABLES
-- ============================================================

-- 15. question_bank — master question library (shared across exams)
CREATE TABLE IF NOT EXISTS question_bank (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  created_by      TEXT NOT NULL,
  question_type   TEXT NOT NULL, -- MCQ | MULTIPLE_SELECT | TRUE_FALSE | SHORT_ANSWER | ESSAY
  question_text   TEXT NOT NULL,
  marks           REAL NOT NULL DEFAULT 1,
  partial_marking INTEGER NOT NULL DEFAULT 0,
  model_answer    TEXT,
  feedback        TEXT,
  visibility      TEXT NOT NULL DEFAULT 'PERSONAL', -- PERSONAL | SCHOOL
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- 16. question_bank_options — answer options for bank questions
--  ⚠️  Foreign key column is called bank_question_id (NOT question_id)
--      This is DIFFERENT from exam_question_options which uses question_id.
CREATE TABLE IF NOT EXISTS question_bank_options (
  id               TEXT PRIMARY KEY,
  bank_question_id TEXT NOT NULL,  -- references question_bank.id
  option_text      TEXT NOT NULL,
  is_correct       INTEGER NOT NULL DEFAULT 0,
  feedback         TEXT,
  sort_order       INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL
);


-- ============================================================
-- PROGRESS LOG TABLE
-- ============================================================

-- 20. progress_log — internal dev/project progress tracking
CREATE TABLE IF NOT EXISTS progress_log (
  id              TEXT PRIMARY KEY,
  log_date        TEXT NOT NULL,
  category        TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  estimated_mins  INTEGER,
  created_at      TEXT NOT NULL
);


-- ============================================================
-- EXAM TAKING ENGINE TABLES
-- ============================================================

-- 21. exam_attempts — one row per student attempt at an exam
CREATE TABLE IF NOT EXISTS exam_attempts (
  id                      TEXT PRIMARY KEY,
  tenant_id               TEXT NOT NULL,        -- isolation
  exam_id                 TEXT NOT NULL,        -- which exam
  user_id                 TEXT NOT NULL,        -- references users.id
  sitting_id              TEXT,                 -- nullable — set if exam belongs to a sitting
  attempt_no              INTEGER NOT NULL DEFAULT 1, -- 1, 2, 3 based on max_attempts

  -- Lifecycle
  status                  TEXT NOT NULL DEFAULT 'IN_PROGRESS', -- IN_PROGRESS | SUBMITTED | ABANDONED

  -- Timing
  started_at              TEXT NOT NULL,        -- when student clicked Start
  submitted_at            TEXT,                 -- null if still in progress
  effective_duration_secs INTEGER NOT NULL,     -- actual time allocated — may be less than full duration if exam closes soon
  time_taken_secs         INTEGER,              -- calculated on submit — actual time spent
  auto_submitted          INTEGER NOT NULL DEFAULT 0, -- 1 if timer or server force-submitted
  is_late                 INTEGER NOT NULL DEFAULT 0, -- 1 if submitted after ends_at

  -- Pre-exam data
  question_order_json     TEXT NOT NULL,        -- actual order questions were presented (critical when shuffle is on)
  custom_fields_json      TEXT,                 -- student responses to custom fields collected before starting

  -- Grading & scores (filled after grading)
  score_raw               REAL,                 -- total marks awarded
  score_total             REAL,                 -- total possible marks at time of sitting
  score_pct               REAL,                 -- score_raw / score_total * 100
  grade                   TEXT,                 -- computed band label e.g. Distinction, Pass, Fail
  grading_status          TEXT NOT NULL DEFAULT 'PENDING', -- PENDING | AUTO_GRADED | FULLY_GRADED

  -- Snapshotted settings (so results always reflect what was set when student sat the exam)
  score_display           TEXT NOT NULL,        -- snapshotted from exams.score_display
  pass_mark_percent       REAL,                 -- snapshotted from exams.pass_mark_percent
  grade_bands_json        TEXT,                 -- snapshotted from exams.grade_bands at time of sitting

  created_at              TEXT NOT NULL,
  updated_at              TEXT NOT NULL
);

-- 22. exam_answers — one row per question per attempt
CREATE TABLE IF NOT EXISTS exam_answers (
  id              TEXT PRIMARY KEY,
  attempt_id      TEXT NOT NULL,            -- references exam_attempts.id
  question_id     TEXT NOT NULL,            -- references exam_questions.id
  question_type   TEXT NOT NULL,            -- snapshotted — grading always knows the type

  -- Student response
  answer_json     TEXT,                     -- flexible: selected option ID for MCQ, text for essay, etc. null if skipped
  is_flagged      INTEGER NOT NULL DEFAULT 0, -- 1 if student flagged for review during exam
  time_spent_secs INTEGER,                  -- how long student spent on this question

  -- Grading (filled after submission)
  score_awarded   REAL,                     -- marks given for this answer
  teacher_note    TEXT,                     -- teacher comment when manually grading
  graded_by       TEXT,                     -- user_id of teacher who graded
  graded_at       TEXT,                     -- when this answer was graded

  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- 23. exam_sittings — groups multiple exam papers into one sitting (School Admin controlled)
CREATE TABLE IF NOT EXISTS exam_sittings (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,              -- isolation
  title         TEXT NOT NULL,              -- e.g. "Year 1 Semester 2 Finals 2026"
  description   TEXT,                       -- optional details
  academic_year TEXT,                       -- e.g. "2025/26" for filtering and reporting
  status        TEXT NOT NULL DEFAULT 'DRAFT', -- DRAFT | ACTIVE | CLOSED
  created_by    TEXT NOT NULL,              -- School Admin who created it
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

-- 24. exam_sitting_papers — which exams belong to which sitting
CREATE TABLE IF NOT EXISTS exam_sitting_papers (
  id          TEXT PRIMARY KEY,
  sitting_id  TEXT NOT NULL,                -- references exam_sittings.id
  exam_id     TEXT NOT NULL,                -- references exams.id
  sort_order  INTEGER NOT NULL DEFAULT 0,   -- display order of papers within the sitting
  created_at  TEXT NOT NULL
);


-- ============================================================
-- INDEXES
-- Critical for performance at scale — without these, queries
-- slow down significantly as data grows.
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_exam_attempts_exam_id    ON exam_attempts(exam_id);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_user_id    ON exam_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_sitting_id ON exam_attempts(sitting_id);
CREATE INDEX IF NOT EXISTS idx_exam_answers_attempt_id  ON exam_answers(attempt_id);
CREATE INDEX IF NOT EXISTS idx_exam_answers_question_id ON exam_answers(question_id);


-- ============================================================
-- MIGRATIONS LOG
-- (for reference only — these were run on the live database
--  as ALTER TABLE statements. They are already baked into the
--  CREATE TABLEs above for any new clone.)
-- ============================================================

-- ALTER TABLE exam_questions ADD COLUMN bank_question_id TEXT;
-- ALTER TABLE exams ADD COLUMN closed_at TEXT;
