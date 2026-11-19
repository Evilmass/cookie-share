import crypto from "node:crypto";
import type { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from "express";
import express from "express";
import { renderAdminPage } from "./admin-page";
import { ENCRYPTION_VERSION, decryptPayloadAsync } from "./crypto";
import { HttpError } from "./errors";
import { sendCorsPreflight, sendEncryptedJson, sendHtml, sendJson } from "./http";
import { CookieStore } from "./store";
import type { ErrorPayload, RuntimeConfig } from "./types";
import {
  normalizeHostParameter,
  normalizeImportBody,
  normalizeSendCookiesBody,
  normalizeUpdateBody,
  validateId,
} from "./validation";

const API_REQUESTS_PER_MINUTE = 600;
const ADMIN_AUTH_FAILURES_PER_MINUTE = 30;
const RATE_WINDOW_MS = 60_000;
const MAX_RATE_ENTRIES = 4096;

function plainError(status: number, message: string): HttpError {
  return new HttpError(status, message, { success: false, message }, { plain: true });
}

// Fixed one-minute windows per key, bounded in size. In-memory and per
// process: enough to slow guessing and floods against a single instance.
class RateWindows {
  private readonly windows = new Map<string, { count: number; until: number }>();

  public count(key: string): number {
    const entry = this.windows.get(key);
    return entry && Date.now() < entry.until ? entry.count : 0;
  }

  public hit(key: string): number {
    const now = Date.now();
    let entry = this.windows.get(key);
    if (!entry || now >= entry.until) {
      this.windows.delete(key);
      if (this.windows.size >= MAX_RATE_ENTRIES) {
        const oldest = this.windows.keys().next().value;
        if (oldest !== undefined) this.windows.delete(oldest);
      }
      entry = { count: 0, until: now + RATE_WINDOW_MS };
      this.windows.set(key, entry);
    }
    entry.count += 1;
    return entry.count;
  }
}

function clientKey(request: Request): string {
  return request.ip || request.socket.remoteAddress || "unknown";
}

function timingSafeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function resolveRouteSecret(pathname: string, config: RuntimeConfig): string {
  if (pathname.startsWith(`${config.basePath}/admin/`)) {
    return config.adminPassword;
  }

  return config.transportSecret;
}

function isEncryptedRoute(request: Request, config: RuntimeConfig): boolean {
  return !(request.method === "GET" && request.path === `${config.basePath}/admin`) && request.method !== "OPTIONS";
}

async function readEncryptedRequestBody(request: Request, secret: string): Promise<unknown> {
  const bodyText = typeof request.body === "string" ? request.body : "";
  if (!bodyText) {
    throw new HttpError(400, "Invalid encrypted payload", {
      success: false,
      message: "Invalid encrypted payload",
    });
  }

  let envelope: unknown;
  try {
    envelope = JSON.parse(bodyText) as unknown;
  } catch {
    throw new HttpError(400, "Invalid encrypted payload", {
      success: false,
      message: "Invalid encrypted payload",
    });
  }

  return decryptPayloadAsync(secret, envelope);
}

function ensureAdminPassword(request: Request, config: RuntimeConfig): void {
  const providedPassword = request.header("X-Admin-Password");
  if (!providedPassword || !timingSafeEqual(providedPassword, config.adminPassword)) {
    // Plain on purpose: an error encrypted with the real admin password would
    // hand an unauthenticated caller material for offline password guessing.
    throw plainError(401, "Unauthorized");
  }
}

function handleRoute(handler: (request: Request, response: Response, next: NextFunction) => Promise<void> | void): RequestHandler {
  return (request: Request, response: Response, next: NextFunction) => {
    Promise.resolve(handler(request, response, next)).catch(next);
  };
}

function buildError(error: unknown): HttpError {
  if (error instanceof HttpError) {
    return error;
  }

  if (error && typeof error === "object") {
    const candidate = error as { status?: unknown; message?: unknown };
    if (typeof candidate.status === "number" && typeof candidate.message === "string") {
      // A malformed :host parameter is rejected by the router; answer like the
      // Worker's own host validation does.
      if (candidate.status === 400 && candidate.message.includes("Failed to decode param")) {
        return new HttpError(400, "Invalid host", { success: false, message: "Invalid host" });
      }
      // Raised before any handler ran (body parser, router): plain.
      return candidate.status >= 500
        ? plainError(500, "Internal Server Error")
        : plainError(candidate.status, candidate.message);
    }
  }

  console.error("Unhandled server error", error);
  // Details stay in the server log.
  return plainError(500, "Internal Server Error");
}

export function createApp(config: RuntimeConfig, store: CookieStore): express.Express {
  store.ensureSchema();

  const app = express();
  app.disable("x-powered-by");
  if (config.trustProxy) {
    app.set("trust proxy", 1);
  }
  const rateWindows = new RateWindows();

  app.use((request, response, next) => {
    if (request.method === "OPTIONS") {
      sendCorsPreflight(response);
      return;
    }
    if (rateWindows.hit(`api:${clientKey(request)}`) > API_REQUESTS_PER_MINUTE) {
      throw plainError(429, "Too many requests; retry later");
    }
    // Outside the path secret nothing is parsed, derived or encrypted.
    if (request.path !== config.basePath && !request.path.startsWith(`${config.basePath}/`)) {
      throw plainError(404, "Not Found");
    }
    next();
  });

  app.use(express.text({ type: "*/*", limit: "2mb" }));

  app.get(`${config.basePath}/capabilities`, (_request, response) => {
    sendJson(response, 200, { success: true, protocolVersions: [1], cookieAttributes: true, metadata: true });
  });

  app.get(`${config.basePath}/admin`, (_request, response) => {
    sendHtml(response, renderAdminPage(config.basePath));
  });

  app.use(`${config.basePath}/admin`, (request, _response, next) => {
    if (request.path === "/" || request.path === "") {
      next();
      return;
    }

    // Checked before comparing, so a throttled caller cannot tell a correct
    // guess from a wrong one.
    const failureKey = `adminfail:${clientKey(request)}`;
    if (rateWindows.count(failureKey) >= ADMIN_AUTH_FAILURES_PER_MINUTE) {
      throw plainError(429, "Too many requests; retry later");
    }
    try {
      ensureAdminPassword(request, config);
    } catch (error) {
      rateWindows.hit(failureKey);
      throw error;
    }
    next();
  });

  app.post(`${config.basePath}/send-cookies`, handleRoute(async (request, response) => {
    const body = normalizeSendCookiesBody(await readEncryptedRequestBody(request, config.transportSecret));
    store.upsertCookieRecord({
      id: body.id,
      url: body.url,
      host: new URL(body.url).hostname.toLowerCase(),
      cookies: body.cookies,
    });
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Cookies saved successfully",
    }, config.transportSecret);
  }));

  app.get(`${config.basePath}/receive-cookies/:id`, handleRoute(async (request, response) => {
    const id = validateId(request.params.id, "Invalid cookie ID");
    const record = store.getCookieRecord(id);
    if (!record) {
      await sendEncryptedJson(response, 404, {
        success: false,
        message: "Cookies not found",
      }, config.transportSecret);
      return;
    }

    await sendEncryptedJson(response, 200, {
      success: true,
      cookies: record.cookies,
      url: record.url, host: record.host,
    }, config.transportSecret);
  }));

  app.get(`${config.basePath}/list-cookies-by-host/:host`, handleRoute(async (request, response) => {
    const host = normalizeHostParameter(request.params.host);
    await sendEncryptedJson(response, 200, {
      success: true,
      cookies: store.listCookieRecordsByHost(host),
    }, config.transportSecret);
  }));

  app.delete(`${config.basePath}/delete`, handleRoute(async (request, response) => {
    // Reading the key from an encrypted body forces the caller to prove
    // knowledge of the transport secret, not just the URL path secret.
    const body = (await readEncryptedRequestBody(request, config.transportSecret)) as { key?: unknown };
    const key = validateId(body?.key, "Invalid key. Only letters and numbers are allowed.");
    store.deleteCookieRecord(key);
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Data deleted successfully",
    }, config.transportSecret);
  }));

  app.get(`${config.basePath}/admin/list-cookies`, handleRoute(async (_request, response) => {
    await sendEncryptedJson(response, 200, {
      success: true,
      cookies: store.listCookieRecordsWithPayload(),
    }, config.adminPassword);
  }));

  app.get(`${config.basePath}/admin/list-cookies-by-host/:host`, handleRoute(async (request, response) => {
    const host = normalizeHostParameter(request.params.host);
    await sendEncryptedJson(response, 200, {
      success: true,
      cookies: store.listCookieRecordsByHost(host),
    }, config.adminPassword);
  }));

  app.post(`${config.basePath}/admin/create`, handleRoute(async (request, response) => {
    const body = normalizeSendCookiesBody(await readEncryptedRequestBody(request, config.adminPassword));
    store.upsertCookieRecord({
      id: body.id,
      url: body.url,
      host: new URL(body.url).hostname.toLowerCase(),
      cookies: body.cookies,
    });
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Cookies saved successfully",
    }, config.adminPassword);
  }));

  app.put(`${config.basePath}/admin/update`, handleRoute(async (request, response) => {
    const body = normalizeUpdateBody(await readEncryptedRequestBody(request, config.adminPassword));
    const existingRecord = store.getCookieRecord(body.key);
    if (!existingRecord) {
      await sendEncryptedJson(response, 404, {
        success: false,
        message: "Cookie not found",
      }, config.adminPassword);
      return;
    }

    const nextUrl = body.url ?? existingRecord.url;
    store.upsertCookieRecord({
      id: body.key,
      url: nextUrl,
      host: new URL(nextUrl).hostname.toLowerCase(),
      cookies: body.value,
    });
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Cookies and URL updated successfully",
    }, config.adminPassword);
  }));

  app.delete(`${config.basePath}/admin/delete`, handleRoute(async (request, response) => {
    const key = validateId(request.query.key, "Invalid key. Only letters and numbers are allowed.");
    store.deleteCookieRecord(key);
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Data deleted successfully",
    }, config.adminPassword);
  }));

  app.get(`${config.basePath}/admin/export-all`, handleRoute(async (_request, response) => {
    await sendEncryptedJson(response, 200, {
      version: ENCRYPTION_VERSION,
      exportedAt: new Date().toISOString(),
      records: store.listCookieRecordsWithPayload().map((record) => ({
        id: record.id,
        url: record.url,
        host: record.host,
        cookies: record.cookies,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      })),
    }, config.adminPassword);
  }));

  app.post(`${config.basePath}/admin/import-all`, handleRoute(async (request, response) => {
    const body = normalizeImportBody(await readEncryptedRequestBody(request, config.adminPassword));
    store.upsertCookieRecords(body.records);
    await sendEncryptedJson(response, 200, {
      success: true,
      message: "Import completed",
      total: body.records.length,
      imported: body.records.length,
    }, config.adminPassword);
  }));

  app.use((_request, _response, next) => {
    next(plainError(404, "Not Found"));
  });

  const errorHandler: ErrorRequestHandler = (error, request, response, next) => {
    if (response.headersSent) {
      next(error);
      return;
    }

    const httpError = buildError(error);
    const payload: ErrorPayload = httpError.payload ?? { success: false, message: httpError.message };

    if (!isEncryptedRoute(request, config) || httpError.plain) {
      sendJson(response, httpError.status, payload);
      return;
    }

    sendEncryptedJson(response, httpError.status, payload, resolveRouteSecret(request.path, config)).catch(next);
  };

  app.use(errorHandler);

  return app;
}
