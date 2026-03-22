# QAcademy Beta — Admin Restructure Plan
*Prepared: March 2026 — Execute on Claude Desktop*

---

## Background

The current School Admin structure is functionally correct at the data level
but has workflow problems that would make it painful for real schools to use.
This plan addresses those problems without changing the database schema.

The core issues are:
1. Classes and Courses have no relationship — no way to enrol a whole class
   into a course in one action
2. Course management is one overwhelming page with no drill-down
3. People page mixes adding users and managing members confusingly
4. Join code form exposes technical type names instead of plain English questions

---

## What Does NOT Change

- Database schema — courses, enrollments, classes, class_students,
  memberships, join_codes are all correct as they are
- Join code logic and scopes — correct, just needs better UI
- All exam-related pages — untouched
- Sittings pages — untouched
- Overview page — untouched
- Teacher and Student dashboards — untouched

---

## The Mental Model We Are Building Towards

A school admin thinks in this order:
1. Set up courses — what subjects does the school offer
2. Set up classes — what groups of students exist
3. Add people — teachers and students
4. Connect everything — which teachers teach which courses,
   which classes take which courses
5. Manage access — join codes for self-service, manual overrides

The restructure makes the UI match this natural workflow.

---

## Page-by-Page Plan

---

### 1. Courses — `/school-courses`

**Current problem:**
Course list, teacher assignment, student enrolment, and course rosters
are all on one page. It grows unbounded and is overwhelming.

**Change:**
The courses page becomes a clean list with a Create Course button.
Each course gets its own detail page: `/school-course?course_id=X`

**Course detail page — 4 tabs:**

| Tab | Content |
|---|---|
| Details | Title, status, edit form |
| Teachers | List of assigned teachers, assign new teacher, remove |
| Students | List of enrolled students, enrol student, remove |
| Classes | List of classes enrolled in this course, enrol class, remove |

The Classes tab is the critical new addition — see Class-to-Course
Enrolment section below.

**Route changes:**
- `/school-courses` — list only, Create button
- `/school-course` — new detail page (GET + POST actions)
- `/school-assign-teacher` — moves to course detail
- `/school-unassign-teacher` — moves to course detail
- `/school-enrol-student` — moves to course detail
- `/school-unenrol-student` — moves to course detail
- New: `/school-enrol-class` — enrols all students in a class into
  a course (see below)

---

### 2. Classes — `/school-classes`

**Current problem:**
Classes are just bags of students with no academic context.
No relationship to courses exists.

**Change:**
The existing class detail page `/school-class?class_id=X` gets one
new tab added:

**New Courses tab on class detail page:**
- Lists which courses this class is currently enrolled in
- Button: "Enrol this class in a course" — dropdown of active courses,
  submit runs bulk enrolment
- Remove button per course row — unenrols all class students from
  that course

No changes to the classes list page itself.

---

### 3. Class-to-Course Enrolment — New Operation

**The missing workflow:**
Currently there is no way to enrol an entire class into a course.
Every student must be enrolled individually — completely unworkable
for a school with 200 students.

**Chosen approach: Option A — Bulk action (no new table)**

When admin clicks "Enrol class into course":
- System fetches all students currently in the class
- Creates individual enrollment rows in the `enrollments` table
  for each student who is not already enrolled
- Skips students already enrolled (idempotent — safe to run twice)
- Shows a confirmation: "47 students enrolled. 3 were already enrolled
  and were skipped."

**Important limitation to communicate to admin:**
If a new student is added to the class after this action, they are NOT
automatically enrolled in the course. The admin must re-run the
enrolment action or enrol the student manually.

This is Option A. Option B (persistent class-course link table with
automatic sync) is the right long-term answer but adds complexity
around edge cases. Upgrade to Option B in a future phase.

**New route:** `POST /school-enrol-class`
- Params: `class_id`, `course_id`
- Action: bulk insert into `enrollments` for all students in class,
  skip existing, return count

---

### 4. People — `/school-people`

**Current problem:**
Adding new users and managing existing members are mixed on one page.
The add form does not handle the case where the email already exists
in the system.

**Change:**
Split the page into two clear tabs:

**Tab 1 — Members**
- Table: Name, Email, Role badge, Change Role dropdown + Update button,
  Remove button
- Clean, no clutter

**Tab 2 — Add Person**
- Step 1: Enter email, click Check
- System checks if email already exists in `users` table
- If email EXISTS: show their name, confirm role to assign,
  no password needed — just adds membership to this school
- If email NEW: show full form — name, role, temporary password —
  creates user account and adds to school
- Optional after adding: "Also enrol in a course" or
  "Also add to a class" — quick assignment without navigating away

This makes the existing-user flow explicit and prevents confusion
or silent failures.

**Route changes:**
- `GET /school-people` — tabbed page
- `POST /school-add-user` — unchanged logic, improved flow
- New: `GET /school-check-email?email=X` — returns JSON:
  `{ exists: true, name: "..." }` or `{ exists: false }`
  Used by Tab 2 to check before showing the form

---

### 5. Join Codes — `/school-join-codes`

**Current problem:**
The create form exposes four technical type names (TENANT_STUDENT,
TENANT_TEACHER, COURSE_ENROLL, COURSE_TEACHER) as a dropdown.
Pending requests, active codes, and history are mixed together.

**Change:**
Restructure the page into three clear sections:

**Section 1 — Active Codes**
Table of currently valid, non-revoked codes:
- Plain English description of what the code does
  e.g. "Students joining with this code will be enrolled in Maths"
  e.g. "Anyone joining with this code becomes a school member (Teacher)"
- Expiry date, uses remaining
- Copy Code button
- Revoke button

**Section 2 — Create Code**
Replace the technical dropdown with two plain English questions:

Question 1: Who is this code for?
- Student
- Teacher

Question 2: What should happen when they join?
- Join the school (no specific course)
- Join the school AND enrol in a specific course → show course dropdown

These two questions map cleanly to the four existing scopes:
- Student + School only = TENANT_STUDENT
- Student + Course = COURSE_ENROLL
- Teacher + School only = TENANT_TEACHER
- Teacher + Course = COURSE_TEACHER

No change to the underlying logic — purely a UI improvement.

**Section 3 — Pending Requests**
Approve/Reject table, clearly separated from the codes section.
Shows requester name, email, which code they used, date requested.

---

## Implementation Order

Do these in order — each builds on the previous:

| Step | Task | Reason |
|---|---|---|
| 1 | Course detail page with Details + Teachers + Students tabs | Foundation for everything else |
| 2 | Class-to-Course enrolment (bulk action) | Most impactful single change |
| 3 | Courses tab on class detail page | Completes the class ↔ course connection |
| 4 | Join Codes UI redesign | Self-contained, no dependencies |
| 5 | People page split + email check | Self-contained, improves onboarding |

---

## Summary Table

| Page | Status | Change Type |
|---|---|---|
| `/school` Overview | No change | — |
| `/school-sittings` | No change | — |
| `/school-courses` | Restructure | List only + drill to detail page |
| `/school-course` (new) | Build new | Course detail with 4 tabs |
| `/school-classes` | Minor | No change to list page |
| `/school-class` (existing) | Extend | Add Courses tab |
| `/school-people` | Restructure | Two tabs + email check |
| `/school-join-codes` | Restructure | Three sections + plain English form |

---

*Save this file as `docs/beta-admin-restructure-plan.md` in the repo.*
*Execute on Claude Desktop with MCP filesystem access.*
