// functions/[[path]].js
// Entry point — routes requests to the correct handler file
// Do not put any logic here

import { handleAppRequest } from "./app.js";
import { handleExamRequest } from "./exams.js";
import { handleQuestionBankRequest } from "./question-bank.js";
import { handleAttemptRequest } from "./attempts.js";

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
    path === "/exam-results-csv"
  ) {
    return handleExamRequest(ctx);
  }

  // School class management routes
  if (
    path === "/school-create-class" ||
    path === "/school-class" ||
    path === "/school-class-add-student" ||
    path === "/school-class-remove-student" ||
    path === "/school-class-enrol-course" ||
    path === "/school-class-archive"
  ) {
    return handleAppRequest(ctx);
  }

  // Everything else goes to app.js
  return handleAppRequest(ctx);
}
