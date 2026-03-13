// functions/[[path]].js
// Entry point — routes requests to the correct handler file
// Do not put any logic here

import { handleAuthRequest } from "./auth.js";
import { handleSysRequest } from "./sys.js";
import { handleAdminRequest } from "./admin.js";
import { handleTeacherRequest } from "./teacher.js";
import { handleStudentRequest } from "./student.js";
import { handleExamRequest } from "./exams.js";
import { handleQuestionBankRequest } from "./question-bank.js";
import { handleAttemptRequest } from "./attempts.js";
import { handleResultsRequest } from "./results.js";
import { handleSittingRequest } from "./sittings.js";

export async function onRequest(ctx) {
  const url = new URL(ctx.request.url);
  const path = url.pathname;

  // Attempt (exam taking engine) routes
  if (
    path === "/attempt-start" ||
    path === "/attempt-take" ||
    path === "/attempt-complete"
  ) {
    return handleAttemptRequest(ctx);
  }

  // Results routes
  if (
    path === "/attempt-results" ||
    path === "/attempt-review" ||
    path === "/sitting-results"
  ) {
    return handleResultsRequest(ctx);
  }

  // Sittings routes (School Admin tool) + Approval Inbox
  if (
    path === "/sittings" ||
    path === "/sitting-builder" ||
    path === "/sitting-create" ||
    path === "/sitting-save-settings" ||
    path === "/sitting-add-paper" ||
    path === "/sitting-remove-paper" ||
    path === "/sitting-gate-save" ||
    path === "/sitting-gate-remove-approver" ||
    path === "/sitting-gate-settings" ||
    path === "/approvals" ||
    path === "/approval-respond" ||
    path === "/exam-preview" ||
    path === "/approval-respond-with-comments"
  ) {
    return handleSittingRequest(ctx);
  }

  // Question bank routes
  if (
    path === "/question-bank" ||
    path.startsWith("/qbank-")
  ) {
    return handleQuestionBankRequest(ctx);
  }

  // All exam builder routes go to exams.js
  if (
    path === "/exam-create" ||
    path === "/exam-builder" ||
    path === "/exam-save-settings" ||
    path === "/exam-add-question" ||
    path === "/exam-update-question" ||
    path === "/exam-delete-question" ||
    path === "/exam-reorder-question" ||
    path === "/exam-bank-picker" ||
    path === "/exam-add-from-bank" ||
    path === "/exam-publish" ||
    path === "/exam-close" ||
    path === "/exam-release-results" ||
    path === "/exam-access-add-class" ||
    path === "/exam-access-add-course" ||
    path === "/exam-access-add-student" ||
    path === "/exam-access-remove" ||
    path === "/exam-grade" ||
    path === "/grading-review-respond" ||
    path === "/exam-results-csv" ||
    path === "/exam-gate-submit"
  ) {
    return handleExamRequest(ctx);
  }

  // System Admin routes
  if (
    path === "/sys" ||
    path.startsWith("/sys-")
  ) {
    return handleSysRequest(ctx);
  }

  // School Admin routes
  if (
    path === "/school" ||
    path === "/school-sittings" ||
    path === "/school-courses" ||
    path === "/school-classes" ||
    path === "/school-people" ||
    path === "/school-join-codes" ||
    path.startsWith("/school-")
  ) {
    return handleAdminRequest(ctx);
  }

  // Teacher dashboard
  if (path === "/teacher") {
    return handleTeacherRequest(ctx);
  }

  // Student dashboard
  if (path === "/student") {
    return handleStudentRequest(ctx);
  }

  // Auth routes: /, /login, /logout, /setup, /profile, /no-access,
  // /choose-school, /switch-school, /join, /join-login, /join-create-account, /health
  return handleAuthRequest(ctx);
}
