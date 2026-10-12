import { CliFehler } from "./gemeinsam.ts";

export type Schlaefer = (milliseconds: number) => Promise<void>;

async function drosselt(response: Response): Promise<boolean> {
  if (response.status !== 429) return false;
  try {
    const body: unknown = await response.clone().json();
    if (body && typeof body === "object" && !Array.isArray(body) && (Object.hasOwn(body, "grund") || Object.hasOwn(body, "reason"))) return false;
  } catch {
    // Non-JSON gateway responses are retriable.
  }
  return true;
}

function wartezeit(response: Response, versuch: number): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter !== null) {
    const seconds = /^\d+$/.test(retryAfter.trim()) ? Number(retryAfter.trim()) : Number.NaN;
    if (Number.isSafeInteger(seconds)) return Math.min(10_000, seconds * 1000);
    const date = Date.parse(retryAfter.trim());
    if (Number.isFinite(date)) return Math.min(10_000, Math.max(0, date - Date.now()));
  }
  return versuch === 0 ? 2000 : 4000;
}

export async function wiederholeBeiDrosselung(
  request: () => Promise<Response>,
  schlaefer: Schlaefer = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
): Promise<Response> {
  for (let versuch = 0; versuch <= 2; versuch += 1) {
    const response = await request();
    if (!await drosselt(response)) return response;
    if (versuch === 2) {
      throw new CliFehler(2, "The post office is currently throttling requests from this address. Please try again in one minute.");
    }
    await schlaefer(wartezeit(response, versuch));
  }
  throw new CliFehler(2, "The post office is currently throttling requests from this address. Please try again in one minute.");
}
