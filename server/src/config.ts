import path from "node:path";
import dotenv from "dotenv";
import { HttpError } from "./errors";
import type { RuntimeConfig } from "./types";

const SERVER_ROOT = path.resolve(__dirname, "..");

dotenv.config({ path: path.join(SERVER_ROOT, ".env") });

function requireString(name: string): string {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new HttpError(500, `Missing required environment variable: ${name}`, {
      success: false,
      error: `Missing required environment variable: ${name}`,
    }, { plain: true });
  }

  return value.trim();
}

function resolvePort(): number {
  const rawPort = process.env.PORT?.trim() ?? "3000";
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new HttpError(500, "Invalid PORT", {
      success: false,
      error: "Invalid PORT",
    }, { plain: true });
  }

  return port;
}

function resolveDbPath(rawPath: string): string {
  if (rawPath === ":memory:") {
    return rawPath;
  }

  return path.isAbsolute(rawPath) ? rawPath : path.resolve(SERVER_ROOT, rawPath);
}

function configError(message: string): HttpError {
  return new HttpError(500, message, { success: false, error: message }, { plain: true });
}

function isTrue(name: string): boolean {
  return process.env[name]?.trim().toLowerCase() === "true";
}

const PLACEHOLDER_SECRETS = new Set(["change-me", "changeme", "dev", "dev-password", "dev-transport-secret"]);
export const MIN_SECRET_LENGTH = 16;

// Every response of the v1 protocol is ciphertext under one of these secrets,
// so a guessable value can be brute-forced offline. Refuse to start with one.
export function validateSecrets(
  secrets: { pathSecret: string; adminPassword: string; transportSecret: string },
  allowWeak = false,
): void {
  // Also the characters Express treats as route pattern syntax.
  if (/[\x00-\x20\x7f<>;?#\\:*{}()[\]!+]/.test(secrets.pathSecret)) {
    throw configError("PATH_SECRET contains unsupported characters");
  }
  if (allowWeak) {
    return;
  }

  const named: Array<[string, string]> = [
    ["PATH_SECRET", secrets.pathSecret],
    ["ADMIN_PASSWORD", secrets.adminPassword],
    ["TRANSPORT_SECRET", secrets.transportSecret],
  ];
  for (const [name, value] of named) {
    if (PLACEHOLDER_SECRETS.has(value.toLowerCase())) {
      throw configError(`${name} is still a placeholder value; generate a random one`);
    }
  }
  if (new Set(named.map(([, value]) => value)).size !== named.length) {
    throw configError("PATH_SECRET, ADMIN_PASSWORD and TRANSPORT_SECRET must be three different values");
  }
  for (const [name, value] of named.slice(1)) {
    if (value.length < MIN_SECRET_LENGTH) {
      throw configError(
        `${name} must be at least ${MIN_SECRET_LENGTH} characters of random data ` +
        "(set ALLOW_WEAK_SECRETS=true to start anyway)",
      );
    }
  }
}

export function loadRuntimeConfig(): RuntimeConfig {
  const pathSecret = requireString("PATH_SECRET");
  const dbPath = resolveDbPath(process.env.DB_PATH?.trim() ?? "./data/cookie_share.db");
  const adminPassword = requireString("ADMIN_PASSWORD");
  const transportSecret = requireString("TRANSPORT_SECRET");
  validateSecrets({ pathSecret, adminPassword, transportSecret }, isTrue("ALLOW_WEAK_SECRETS"));

  return {
    trustProxy: isTrue("TRUST_PROXY"),
    host: process.env.HOST?.trim() || "0.0.0.0",
    port: resolvePort(),
    serverRoot: SERVER_ROOT,
    dbPath,
    pathSecret,
    basePath: `/${pathSecret}`,
    adminPassword,
    transportSecret,
  };
}
