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
-- MIGRATIONS LOG
-- (for reference only — these were run on the live database
--  as ALTER TABLE statements. They are already baked into the
--  CREATE TABLEs above for any new clone.)
-- ============================================================

-- ALTER TABLE exam_questions ADD COLUMN bank_question_id TEXT;
-- ALTER TABLE exams ADD COLUMN closed_at TEXT;
