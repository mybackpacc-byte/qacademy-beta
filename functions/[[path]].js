import { handleRequest } from "/.app.js";

export async function onRequest(ctx) {
  return handleRequest(ctx);
}
