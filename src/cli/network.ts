import { CliError } from "./shared.ts";

export type Sleeper = (milliseconds: number) => Promise<void>;

async function isRateLimited(response: Response): Promise<boolean> {
  if (response.status !== 429) return false;
  try {
    const body: unknown = await response.clone().json();
    if (body && typeof body === "object" && !Array.isArray(body) && (Object.hasOwn(body, "grund") || Object.hasOwn(body, "reason"))) return false;
  } catch {
    // Non-JSON gateway responses are retriable.
  }
  return true;
}

export function retryDelay(response: Response, attempt: number): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter !== null) {
    const seconds = /^\d+$/.test(retryAfter.trim()) ? Number(retryAfter.trim()) : Number.NaN;
    if (Number.isSafeInteger(seconds)) return Math.min(10_000, seconds * 1000);
    const date = Date.parse(retryAfter.trim());
    if (Number.isFinite(date)) return Math.min(10_000, Math.max(0, date - Date.now()));
  }
  return attempt === 0 ? 2000 : 4000;
}

export async function retryOnRateLimit(
  request: () => Promise<Response>,
  sleeper: Sleeper = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
): Promise<Response> {
  for (let attempt = 0; attempt <= 2; attempt += 1) {
    const response = await request();
    if (!await isRateLimited(response)) return response;
    if (attempt === 2) {
      throw new CliError(2, "The Subspace server is currently throttling requests from this address. Please try again in one minute.");
    }
    await sleeper(retryDelay(response, attempt));
  }
  throw new CliError(2, "The Subspace server is currently throttling requests from this address. Please try again in one minute.");
}
