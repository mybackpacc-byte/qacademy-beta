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
-- [NEW] 10. EXAMS
-- An exam created by a teacher for a specific course
-- This is the first building block of the exam engine
-- =============================================================
CREATE TABLE IF NOT EXISTS exams (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,       -- which school owns this exam
  course_id       TEXT NOT NULL,       -- which course this exam belongs to
  created_by      TEXT NOT NULL,       -- which teacher created it
  title           TEXT NOT NULL,       -- exam name e.g. "Term 1 Maths Exam"
  description     TEXT,                -- optional instructions for students
  duration_mins   INTEGER NOT NULL     -- time limit in minutes e.g. 60
                  DEFAULT 60,
  total_marks     INTEGER NOT NULL     -- total marks available e.g. 100
                  DEFAULT 100,
  status          TEXT NOT NULL        -- DRAFT | PUBLISHED | CLOSED | ARCHIVED
                  DEFAULT 'DRAFT',
  starts_at       TEXT,                -- when students can start (optional schedule)
  ends_at         TEXT,                -- deadline to submit (optional schedule)
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,

  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);


-- =============================================================
-- INDEXES
-- These speed up common lookups (optional but good practice)
-- =============================================================
CREATE INDEX IF NOT EXISTS idx_sessions_user_id       ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user_id    ON memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant_id  ON memberships(tenant_id);
CREATE INDEX IF NOT EXISTS idx_courses_tenant_id      ON courses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exams_course_id        ON exams(course_id);
CREATE INDEX IF NOT EXISTS idx_exams_tenant_id        ON exams(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exams_status           ON exams(status);
