# QAcademy Beta — Exam Platform Roadmap

## What's Already Built (Strong Foundation)

- Timer with color warnings + auto-submit
- Free & linear navigation modes
- Question shuffling + option shuffling
- 5 question types (MCQ, True/False, Multi-select, Short Answer, Essay)
- Manual grading interface for subjective questions
- Flexible result release (immediate / after close / manual)
- Grade bands + pass/fail
- Approval gates (questions, grading, results)
- Exam sittings system
- Question bank with personal/school visibility
- Custom fields collection before exam
- Auto-save every 30 seconds
- CSV export of results
- Multi-tenant architecture with role-based access
- Join codes and membership management

---

## What's Missing to Be a Proper Exam Platform

### 1. Anti-Cheating / Proctoring (Priority: HIGH)

Right now only password protection exists. A real exam platform needs:

- **Tab-switch detection** — detect when student leaves the tab, log it, optionally auto-submit
- **Fullscreen enforcement** — force fullscreen mode, warn on exit
- **Copy/paste blocking** — disable right-click, copy, paste in exam area
- **Browser lockdown warning** — "X tab switches detected" shown to admin
- **IP logging** — record student's IP per attempt for audit
- **Optional webcam proctoring** (advanced) — periodic snapshots, AI flag review

Even just tab-switch detection + fullscreen + copy-paste blocking gets you 80% of the way.

### 2. Question Bank / Pooling (Priority: HIGH)

Board exams don't show every student the same 50 questions. You need:

- **Question bank** per subject/topic with tagging (difficulty, topic, Bloom's level)
- **Question pooling** — "pick 10 random questions from this pool of 30"
- **Blueprint/specification** — "5 easy, 3 medium, 2 hard from Topic A"
- This makes exams harder to cheat on and enables exam reuse

### 3. Certificate Generation (Priority: HIGH)

After passing, students expect a downloadable certificate:

- PDF certificate with student name, exam title, score/grade, date
- QR code or unique verification URL for authenticity
- Customizable template per institution

### 4. Analytics & Item Analysis (Priority: HIGH)

Exam bodies need to evaluate question quality:

- **Item difficulty index** — what % of students got each question right
- **Discrimination index** — do high-scoring students get this question right more often?
- **Distractor analysis** — which wrong MCQ options are students picking?
- **Score distribution** charts (histogram, bell curve)
- **Comparative analytics** — this sitting vs last sitting

### 5. Audit Trail (Priority: HIGH)

Board exams are legally scrutinized. You need:

- Every action logged: who did what, when (login, start, answer change, submit, grade, appeal)
- Immutable logs (not editable by admin)
- Export audit logs per student for dispute resolution

### 6. Rubric System for Essay Grading (Priority: MEDIUM)

Current grading is just score + note. Professional marking needs:

- **Rubric templates** — criteria with levels (e.g., Content: 1-5, Grammar: 1-3)
- **Per-criteria scoring** — grader scores each criterion independently
- **Inter-rater reliability** — two graders mark the same essay, system flags discrepancies
- **Moderation** — senior examiner reviews a sample of graded papers

### 7. Student Appeals (Priority: MEDIUM)

Students should be able to formally dispute a grade:

- Submit appeal with reason → teacher reviews → approves/rejects with note
- Audit trail of the original grade vs revised grade

### 8. Accessibility (Priority: MEDIUM)

If this is for board exams, you need:

- Screen reader support (proper ARIA labels)
- Keyboard-only navigation through questions
- High contrast mode
- Extra time accommodations (per-student time extensions)
- Font size adjustment

### 9. Offline Resilience (Priority: MEDIUM)

Many exam environments have unreliable internet:

- Auto-save answers to localStorage as backup
- Reconnection handling — queue answer submissions, sync when back online
- "Connection lost" indicator with graceful recovery

### 10. Exam Scheduling & Communication (Priority: LOW)

- Exam calendar visible to students
- Email/SMS notifications (registration confirmed, exam reminder, results released)
- Countdown to exam start on student dashboard

### 11. Registration & Payment (Priority: LOW)

Many board exams require students to register and pay fees:

- Registration table tracking student → exam → payment status
- Fee configuration on exams or sittings
- Manual payment verification (student enters payment ref, admin confirms)
- Optional payment gateway integration (Paystack, Flutterwave, M-Pesa, Stripe)
- Admin bulk approval screen with CSV export for bank reconciliation

---

## Additional Features Worth Considering

### Advanced Question Types
- Image/media-based questions
- Drag-and-drop matching
- Gap-fill/cloze questions
- Formula/mathematical expression input
- Code submission with automated testing

### Exam Administration
- Bulk import of students/questions (CSV upload)
- Exam cloning/templating for repeated use
- Candidate number / anonymous submission support
- Exam paper print-to-PDF
- Practice exam mode vs graded mode

### Marking & Feedback
- Blind marking (grader doesn't see student name)
- Marker allocation (assign graders to specific students)
- Feedback templates for common comments
- Annotation/highlighting on student work

### Integration & Interoperability
- LMS integration (Moodle, Canvas, Blackboard)
- SSO/OAuth for institutional login
- API for third-party integrations
- Webhook support for external systems

### Real-Time Monitoring
- Live dashboard during exam: who's online, progress, time remaining
- Flag students with suspicious activity in real-time
- System status page for large-scale exam events

---

## Priority Summary

| Priority | Feature | Impact |
|----------|---------|--------|
| 1 | Anti-cheating (tab detect, fullscreen, copy block) | Without this, no one trusts online exams |
| 2 | Question bank + pooling | Core differentiator from a quiz app |
| 3 | Certificate generation | Students expect it, institutions need it |
| 4 | Analytics + item analysis | Exam bodies need this to improve exams |
| 5 | Audit trail | Legal requirement for any serious exam |
| 6 | Rubric system | Makes subjective grading credible |
| 7 | Student appeals | Fairness and accountability |
| 8 | Accessibility | Compliance and inclusivity |
| 9 | Offline resilience | Practical for unreliable network environments |
| 10 | Notifications | Nice to have, not blocking |
| 11 | Registration + payment | Needed for board exam workflows |
