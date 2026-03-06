-- =============================================================
-- SCHEMA.SQL
-- Multi-Tenant Exam Platform
-- Cloudflare D1 (SQLite)
-- =============================================================
-- HOW TO USE THIS FILE:
--   Option 1: Paste each CREATE TABLE into the Cloudflare D1 query pane
--   Option 2: Run from terminal using Wrangler:
--             npx wrangler d1 execute beta_db --file=schema.sql
--
-- NOTE: Tables marked [EXISTING] are already in your D1 database.
--       DO NOT run those again unless rebuilding from scratch.
--       Tables marked [NEW] need to be created - run those now.
-- =============================================================


-- -------------------------------------------------------------
-- [EXISTING] 1. TENANTS (Schools)
-- Each row = one school on the platform
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id          TEXT PRIMARY KEY,       -- unique ID for the school
  name        TEXT NOT NULL,          -- school display name
  status      TEXT NOT NULL           -- ACTIVE | INACTIVE
                DEFAULT 'ACTIVE',
  created_at  TEXT NOT NULL,          -- ISO timestamp
  updated_at  TEXT NOT NULL           -- ISO timestamp
);


-- -------------------------------------------------------------
-- [EXISTING] 2. USERS
-- Everyone on the platform lives here (all schools, all roles)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                TEXT PRIMARY KEY,
  email             TEXT NOT NULL UNIQUE,
  name              TEXT NOT NULL,
  password_salt     TEXT NOT NULL,     -- random salt for hashing
  password_hash     TEXT NOT NULL,     -- PBKDF2 hashed password
  password_iter     INTEGER NOT NULL   -- hash iterations (40000)
                    DEFAULT 40000,
  is_system_admin   INTEGER NOT NULL   -- 1 = system admin, 0 = normal user
                    DEFAULT 0,
  status            TEXT NOT NULL      -- ACTIVE | INACTIVE
                    DEFAULT 'ACTIVE',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);


-- -------------------------------------------------------------
-- [EXISTING] 3. SESSIONS
-- Tracks active login sessions (one per login)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  token_hash        TEXT PRIMARY KEY,  -- hashed session token stored in cookie
  user_id           TEXT NOT NULL,     -- which user this session belongs to
  active_tenant_id  TEXT,              -- which school is currently active
  expires_at        TEXT NOT NULL,     -- when this session expires (7 days)
  created_at        TEXT NOT NULL,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (active_tenant_id) REFERENCES tenants(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 4. MEMBERSHIPS
-- Links users to schools with a role (one user can be in many schools)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memberships (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,           -- the user
  tenant_id   TEXT NOT NULL,           -- the school
  role        TEXT NOT NULL,           -- SCHOOL_ADMIN | TEACHER | STUDENT
  status      TEXT NOT NULL            -- ACTIVE | REMOVED
              DEFAULT 'ACTIVE',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 5. COURSES
-- Subjects or classes within a school (e.g. "Maths Grade 10")
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS courses (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL,           -- which school owns this course
  title       TEXT NOT NULL,           -- course name
  status      TEXT NOT NULL            -- ACTIVE | ARCHIVED
              DEFAULT 'ACTIVE',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,

  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 6. COURSE_TEACHERS
-- Links teachers to the courses they teach
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS course_teachers (
  course_id   TEXT NOT NULL,           -- which course
  user_id     TEXT NOT NULL,           -- which teacher
  created_at  TEXT NOT NULL,

  PRIMARY KEY (course_id, user_id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 7. ENROLLMENTS
-- Links students to the courses they are enrolled in
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrollments (
  course_id   TEXT NOT NULL,           -- which course
  user_id     TEXT NOT NULL,           -- which student
  created_at  TEXT NOT NULL,

  PRIMARY KEY (course_id, user_id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 8. JOIN_CODES
-- Invite codes teachers/admins share to let users join a school or course
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS join_codes (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL,       -- which school this code belongs to
  scope               TEXT NOT NULL,       -- TENANT_ROLE | COURSE_ENROLL | COURSE_TEACHER
  role                TEXT NOT NULL,       -- STUDENT | TEACHER | SCHOOL_ADMIN
  course_id           TEXT,                -- only set for course-scoped codes
  code_hash           TEXT NOT NULL UNIQUE,-- hashed version of the code (never store plain)
  auto_approve        INTEGER NOT NULL     -- 1 = instant access, 0 = needs admin approval
                      DEFAULT 0,
  expires_at          TEXT NOT NULL,       -- when the code stops working
  max_uses            INTEGER NOT NULL     -- max number of times code can be used
                      DEFAULT 300,
  uses_approved       INTEGER NOT NULL     -- how many times it has been used so far
                      DEFAULT 0,
  revoked             INTEGER NOT NULL     -- 1 = manually disabled by admin
                      DEFAULT 0,
  created_by_user_id  TEXT NOT NULL,       -- which admin created this code
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,

  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);


-- -------------------------------------------------------------
-- [EXISTING] 9. JOIN_REQUESTS
-- When auto_approve=0, a request is created and waits for admin approval
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS join_requests (
  id                    TEXT PRIMARY KEY,
  join_code_id          TEXT NOT NULL,     -- which code was used
  tenant_id             TEXT NOT NULL,     -- which school
  course_id             TEXT,              -- which course (if course-scoped)
  user_id               TEXT NOT NULL,     -- who is requesting access
  type                  TEXT NOT NULL,     -- MEMBERSHIP | COURSE_ENROLL | COURSE_TEACHER
  requested_role        TEXT NOT NULL,     -- the role they are requesting
  status                TEXT NOT NULL      -- PENDING | APPROVED | REJECTED
                        DEFAULT 'PENDING',
  reviewed_by_user_id   TEXT,              -- which admin approved/rejected
  reviewed_at           TEXT,              -- when it was reviewed
  created_at            TEXT NOT NULL,

  FOREIGN KEY (join_code_id) REFERENCES join_codes(id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
);


-- =============================================================
-- STEP 2: Recreate exams table with all settings columns
-- Run this after Step 1
-- =============================================================
CREATE TABLE IF NOT EXISTS exams (
  -- Core identity (referenced by all other exam tables)
  id                      TEXT PRIMARY KEY,
  tenant_id               TEXT NOT NULL,       -- which school
  course_id               TEXT NOT NULL,       -- which course
  created_by              TEXT NOT NULL,       -- which teacher created it
  status                  TEXT NOT NULL        -- DRAFT | PUBLISHED | CLOSED | ARCHIVED
                          DEFAULT 'DRAFT',

  -- Basic info
  title                   TEXT NOT NULL,
  description             TEXT,                -- instructions shown before exam starts

  -- Timing
  duration_mins           INTEGER NOT NULL     -- personal timer per student (minutes)
                          DEFAULT 60,
  starts_at               TEXT,                -- when students can open the exam (optional)
  ends_at                 TEXT,                -- hard deadline for starting (optional)
  late_submission_policy  TEXT,                -- HARD_CUT | ALLOW_DURATION (only relevant if ends_at set)

  -- Attempts
  max_attempts            INTEGER NOT NULL     -- how many times student can attempt
                          DEFAULT 1,

  -- Security
  exam_password           TEXT,                -- optional room password students must enter

  -- Behaviour toggles
  shuffle_questions       INTEGER NOT NULL DEFAULT 0,   -- 1 = randomise question order per student
  shuffle_options         INTEGER NOT NULL DEFAULT 0,   -- 1 = randomise MCQ option order per student
  show_marks_during       INTEGER NOT NULL DEFAULT 0,   -- 1 = student can see marks per question
  allow_review            INTEGER NOT NULL DEFAULT 0,   -- 1 = student can review after submission
  navigation_mode         TEXT NOT NULL                 -- FREE | LINEAR
                          DEFAULT 'FREE',

  -- Results & grading
  results_release_policy  TEXT NOT NULL                 -- IMMEDIATE | AFTER_CLOSE | MANUAL
                          DEFAULT 'MANUAL',
  score_display           TEXT NOT NULL                 -- BOTH | RAW | PERCENT | PASS_FAIL | HIDDEN
                          DEFAULT 'BOTH',
  pass_mark_percent       REAL,                         -- e.g. 50.0 means 50% needed to pass (optional)

  -- Publish tracking (used by Publish pane later)
  published_at            TEXT,
  published_by            TEXT,
  results_published_at    TEXT,

  -- Timestamps
  created_at              TEXT NOT NULL,
  updated_at              TEXT NOT NULL,

  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);


-- =============================================================
-- STEP 3: Supporting tables for repeating data
-- Run both of these after Step 2
-- =============================================================

-- Grade bands (e.g. Distinction = 75%+, Credit = 65%+)
CREATE TABLE IF NOT EXISTS exam_grade_bands (
  id            TEXT PRIMARY KEY,
  exam_id       TEXT NOT NULL,
  label         TEXT NOT NULL,        -- e.g. "Distinction", "A", "Pass"
  min_percent   REAL NOT NULL,        -- minimum % to achieve this grade
  created_at    TEXT NOT NULL,

  FOREIGN KEY (exam_id) REFERENCES exams(id)
);

-- Custom fields (collected from student before exam starts)
CREATE TABLE IF NOT EXISTS exam_custom_fields (
  id              TEXT PRIMARY KEY,
  exam_id         TEXT NOT NULL,
  field_label     TEXT NOT NULL,      -- e.g. "Index Number", "Seat Number"
  field_type      TEXT NOT NULL,      -- TEXT | YESNO | DROPDOWN
  field_options   TEXT,               -- comma-separated options (only for DROPDOWN type)
  is_required     INTEGER NOT NULL    -- 1 = student must fill this in
                  DEFAULT 1,
  sort_order      INTEGER NOT NULL    -- display order
                  DEFAULT 0,
  created_at      TEXT NOT NULL,

  FOREIGN KEY (exam_id) REFERENCES exams(id)
);


-- =============================================================
-- INDEXES
-- =============================================================
CREATE INDEX IF NOT EXISTS idx_exams_course_id        ON exams(course_id);
CREATE INDEX IF NOT EXISTS idx_exams_tenant_id        ON exams(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exams_status           ON exams(status);
CREATE INDEX IF NOT EXISTS idx_exam_grade_bands_exam  ON exam_grade_bands(exam_id);
CREATE INDEX IF NOT EXISTS idx_exam_custom_fields_exam ON exam_custom_fields(exam_id);


-- =============================================================
-- QUESTIONS TABLES
-- Run both of these in your Cloudflare D1 query pane
-- =============================================================

-- Questions (one row per question)
CREATE TABLE IF NOT EXISTS exam_questions (
  id              TEXT PRIMARY KEY,
  exam_id         TEXT NOT NULL,
  tenant_id       TEXT NOT NULL,
  question_type   TEXT NOT NULL,      -- MCQ | MULTIPLE_SELECT | TRUE_FALSE | SHORT_ANSWER | ESSAY
  question_text   TEXT NOT NULL,
  marks           REAL NOT NULL DEFAULT 1,
  sort_order      INTEGER NOT NULL DEFAULT 1,
  partial_marking INTEGER NOT NULL DEFAULT 1,  -- 1=partial (MULTIPLE_SELECT only)
  model_answer    TEXT,               -- optional, SHORT_ANSWER only
  feedback        TEXT,               -- optional, shown during review
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,

  FOREIGN KEY (exam_id) REFERENCES exams(id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- Answer options (one row per option, MCQ/MULTIPLE_SELECT/TRUE_FALSE only)
CREATE TABLE IF NOT EXISTS exam_question_options (
  id            TEXT PRIMARY KEY,
  question_id   TEXT NOT NULL,
  option_text   TEXT NOT NULL,
  is_correct    INTEGER NOT NULL DEFAULT 0,   -- 1 = correct answer
  feedback      TEXT,                          -- optional, shown during review
  sort_order    INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,

  FOREIGN KEY (question_id) REFERENCES exam_questions(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_exam_questions_exam_id     ON exam_questions(exam_id);
CREATE INDEX IF NOT EXISTS idx_exam_question_opts_qid     ON exam_question_options(question_id);

CREATE TABLE classes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  year_group TEXT,
  academic_year TEXT,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE class_students (
  id TEXT PRIMARY KEY,
  class_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE exam_access (
  id TEXT PRIMARY KEY,
  exam_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  added_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
