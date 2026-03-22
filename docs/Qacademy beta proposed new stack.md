
QAcademy Beta
Proposed New Stack — Version 2
Prepared: March 2026
Internal Planning Document



This document describes the proposed technology stack for QAcademy Beta Version 2. It covers why the current stack is being reconsidered, what the new stack involves, how the two compare, and what the migration would mean in practice.

This is a planning document. No code changes should be made until the current Beta admin restructure is complete and the platform has real users.


Background — Why Reconsider the Stack
The current Beta stack was the right choice at the time it was built. Server-rendered HTML via Cloudflare Workers is fast to build, easy to deploy, and naturally enforces tenant isolation. It served the purpose of proving the platform concept.

However as the platform grows towards institutional clients — schools, exam bodies, professional certification organisations — the user experience demands are increasing. Specifically:

•	Admin users need to view complete context about a teacher or student without navigating between pages
•	Teachers need a fluid exam building experience with real-time feedback, not page reloads
•	Students need an app-like exam taking experience that feels fast and responsive
•	The platform needs to feel like a serious institutional tool, not a collection of separate web pages

These requirements point towards a Single Page Application architecture — which the current server-rendered approach cannot deliver cleanly.


Key Concepts to Understand
React
React is a JavaScript library for building user interfaces. Instead of separate HTML pages, you build reusable components — self-contained pieces of UI that update automatically when their data changes.

The core idea: build a component once, use it anywhere. Pass it different data and it displays accordingly. A StudentDrawer component built once can be called from the results page, the marksheet, the classes page, or anywhere else — same component, different context.
Single Page Application (SPA)
A SPA loads once in the browser. After that, everything — navigation, drawers, panels, tabs — happens by swapping React components in and out without ever reloading the page. The user experience feels instant and app-like.

For Beta this means: one URL per role. Everything the admin, teacher, or student needs renders within their single page. Clicking a teacher opens a drawer. Clicking their exams opens a panel. All without a single page reload.
Next.js
Next.js is React with a server layer added on top. Pure React runs entirely in the browser — which means slow first loads and poor search engine visibility. Next.js solves this by generating pages on the server when needed, then handing control to React in the browser.

Next.js gives you three rendering modes per page:

•	Static Generation — built once at deploy time. For landing pages and content that rarely changes.
•	Server Side Rendering — built on the server on every request. For dashboards and pages needing fresh data.
•	Client Side — pure React in the browser. For highly interactive pages like the exam builder and quiz runner.

You mix all three in the same application. Each page chooses the right approach for its needs.

Next.js also adds automatic file-based routing — a file at app/school/page.js automatically becomes the route /school. No manual routing configuration needed.


Current Stack vs Proposed Stack

Layer	Current Stack	Proposed Stack
Frontend	Server-rendered HTML	Next.js + React components
Backend	Cloudflare Workers (handler files)	Next.js API Routes
Database	Cloudflare D1 (SQLite)	Cloudflare D1 (unchanged)
Auth	Custom built (PBKDF2, cookies)	Custom or NextAuth.js
Routing	Manual in [[path]].js	Automatic via file structure
Hosting	Cloudflare Pages	Cloudflare Pages (with Next.js adapter)
Version Control	GitHub	GitHub (unchanged)
UI Pattern	Full page reloads	Mixed — SSR for data pages, client side React for interactive features
Admin Experience	Separate pages per section	Server rendered pages with client side drawers and panels


What Changes
functions/ folder becomes API Routes
Your current handler files — admin.js, teacher.js, exams.js, sittings.js etc — become Next.js API routes. The logic stays the same. Only the structure changes.

Current:
functions/admin.js  →  handles all /school-* routes

Proposed:
app/api/school/route.js  →  handles /api/school requests
app/api/exams/route.js   →  handles /api/exams requests
Server-rendered HTML becomes React Components
Your current pages return HTML strings built in JavaScript. In Next.js each page is a React component that returns JSX — a cleaner, more maintainable way of describing UI.

Current:
return page(`<div class='card'><h2>Teachers</h2>...</div>`)

Proposed:
export default function TeachersPage() {   return <div className='card'><h2>Teachers</h2>...</div> }
[[path]].js Router Disappears
Your entire routing file is replaced by Next.js's automatic file-based routing. The folder structure becomes the routes. No manual routing configuration needed.
Reusable Drawers and Panels
The most powerful change. Components like StudentDrawer, TeacherDrawer, and ExamPanel are built once and used across every page that needs them.

// On results page <StudentDrawer studentId={alice.id} activeTab='results' />

// On classes page <StudentDrawer studentId={alice.id} activeTab='classes' />

// On marksheet <StudentDrawer studentId={alice.id} activeTab='attempts' />

Same component. Different data. Different context. Built once, used everywhere.


What Stays the Same
•	Cloudflare D1 database — all tables, all data, completely untouched
•	All business logic — exam engine, approval gates, sittings, tenant isolation — moves into API routes unchanged
•	Cloudflare Pages hosting — same platform, Next.js has a Cloudflare adapter
•	GitHub workflow — same repo, same commit to main approach
•	Multi-tenant architecture — tenant isolation enforced in API routes exactly as it is now in Workers
•	All the hard thinking already done — approval gates, grading flows, sittings — none of that changes


Proposed Folder Structure

app/   (admin)/     school/       page.js          ← School Admin (SSR + client drawers)   (teacher)/     teacher/       page.js          ← Teacher (SSR + client exam builder)   (student)/     student/       page.js          ← Student (SSR + client quiz runner)   (auth)/     login/       page.js          ← Login page (static)     setup/       page.js          ← First time setup (static)  api/   school/     route.js           ← Admin API endpoints   exams/     route.js           ← Exam endpoints   auth/     route.js           ← Auth endpoints   sittings/     route.js           ← Sittings endpoints  components/   StudentDrawer.js     ← Reusable student context panel (client side)   TeacherDrawer.js     ← Reusable teacher context panel (client side)   ExamBuilder.js       ← Interactive exam builder (client side)   QuizRunner.js        ← Interactive quiz runner (client side)   ExamCard.js          ← Reusable exam card   Sidebar.js           ← Reusable sidebar   ApprovalGate.js      ← Reusable approval gate component  lib/   db.js               ← D1 database connection helper   auth.js             ← Auth helpers   tenant.js           ← Tenant isolation helpers


Rendering Approach Per Feature
React does not always mean a Single Page Application. React is a component system — how those components are delivered is a separate decision. Next.js lets you mix all three rendering approaches in the same project. Each page and feature chooses the right approach for its needs.

Feature	Rendering Approach	Reason
Landing page	Static Generation	Never changes — build once, serve forever, fastest possible load
Login and Setup pages	Static Generation	No dynamic data needed
Admin dashboard	Server Side Rendering	Always needs fresh stats and live data
Results pages	Server Side Rendering	Current submission data must always be accurate
Marksheet	Server Side Rendering	Live attempt data and grading status
Sitting management	Server Side Rendering	Real time sitting status and gate state
Exam builder	Client Side React	Highly interactive, real time feedback, no reloads needed
Quiz runner	Client Side React	Live timer, answer tracking, question grid — must be instant
Student drawers	Client Side React	Slides in without leaving the current page
Teacher drawers	Client Side React	Context panel called from anywhere on any page
Question bank browser	Client Side React	Live filtering, search, add to exam — fully interactive


The Experience Per Role
Each role gets a focused, intelligent experience. Pages that need fresh data are server rendered — fast first load, always accurate. Interactive features within those pages use client side React components — no reloads, instant feedback. The two approaches work together seamlessly within the same application.
School Admin — /school
Server rendered dashboard with live stats and pending banners. Navigation between sections — Courses, Classes, People, Join Codes — loads fresh server rendered data each time. Clicking a teacher or student anywhere opens a client side TeacherDrawer or StudentDrawer that slides in without leaving the current page. Tabs within the drawer — Profile, Courses, Exams, Approvals — swap client side instantly. Complete context on every person from anywhere.
Teacher — /teacher
Server rendered teacher home showing exam list and pending approvals — always current data. Clicking into the exam builder switches to a fully client side experience — interactive questions, real time validation, drag to reorder, no reloads. Results and marksheet are server rendered for accuracy. Clicking a student in results opens a client side StudentDrawer inline.
Student — /student
Server rendered dashboard showing available exams, results, and sittings — always fresh. Launching an exam switches to a fully client side quiz runner — live timer, answer tracking, question grid, auto-save. Completing the exam returns to the server rendered dashboard with updated results.
System Admin — /sys
Server rendered tenant management and platform oversight. Clean, accurate, data-driven. No need for complex interactivity at this level.


When to Migrate
This migration should not happen until the following conditions are met:

•	Current Beta admin restructure is complete and working
•	Beta has real school users — at least 2 to 3 schools actively using it
•	Revenue is flowing — either from Gamma or Beta
•	The current version has been validated with real usage so we know exactly what needs to exist in v2

Migrating before real users exist means rebuilding something that has not been validated. Real usage always reveals things that need to change. Build on the current version first, learn from real schools, then rebuild v2 properly in Next.js with confidence.


Summary

Question	Answer
What is React?	A library for building reusable UI components
What is Next.js?	React with a server layer — faster, smarter, production-ready
What is a SPA?	One page that swaps components without reloading — React supports this but is not limited to it
What are drawers?	Reusable panels built once, called from anywhere with different data
What changes in v2?	Frontend becomes React components, backend becomes API routes
What stays the same?	D1 database, all business logic, Cloudflare hosting, GitHub
When to migrate?	After real users, after validation, after revenue
Why Next.js over pure React?	Server rendering, automatic routing, better for serious platforms
Will it look better?	Design makes it look better — React makes complex interactions smoother
Is it more secure?	No — security lives in the database and API, not the frontend framework

QAcademy Beta — Internal Planning Document — March 2026
