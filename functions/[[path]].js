// functions/[[path]].js
// Entry point — routes requests to the correct handler file
// Do not put any logic here

import { handleAppRequest } from "./app.js";
import { handleExamRequest } from "./exams.js";
import { handleBankRequest } from "./question-bank.js";

export async function onRequest(ctx) {
  const url = new URL(ctx.request.url);
  const path = url.pathname;

  // Question bank routes
  if (
    path === "/question-bank" ||
    path === "/qbank-add" ||
    path === "/qbank-update" ||
    path === "/qbank-delete" ||
    path === "/qbank-toggle-visibility"
  ) {
    return handleBankRequest(ctx);
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
    path === "/exam-add-from-bank" ||
    path === "/exam-bank-picker"
  ) {
    return handleExamRequest(ctx);
  }

  // Everything else goes to app.js
  return handleAppRequest(ctx);
}
