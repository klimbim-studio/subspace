import { signRequest } from "../request.ts";
import { fingerprint, type KeyPair } from "../seal.ts";
import { sshPublicKeyFingerprint as sshFingerprint } from "../ssh.ts";
import { CliError, loadConfiguration, loadKey, resolveConfigPath, type Configuration } from "./shared.ts";
import { retryOnRateLimit } from "./network.ts";

type AccountOptions = { positionals: string[]; values: Map<string, string[]> };

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  expires_in: number;
  interval: number;
}


function singleOption(options: AccountOptions, flag: string, required = false): string | undefined {
  const values = options.values.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliError(1, `Missing or repeated option: ${flag}.`);
  return values[0];
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidDeviceCodeResponse(value: unknown): value is DeviceCodeResponse {
  if (!isRecord(value)) return false;
  return typeof value.device_code === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.device_code)
    && typeof value.user_code === "string" && /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(value.user_code)
    && Number.isSafeInteger(value.expires_in) && (value.expires_in as number) > 0
    && Number.isSafeInteger(value.interval) && (value.interval as number) > 0;
}

async function signedRequest(configuration: Configuration, key: KeyPair, path: string, content: Record<string, string>): Promise<Response> {
  const url = `${configuration.server}${path}`;
  const body = Buffer.from(JSON.stringify(content));
  return retryOnRateLimit(() => {
    const headers = signRequest({
      method: "POST",
      url,
      body: body,
      name: configuration.name,
      privateKey: key.signaturPrivat,
    });
    return fetch(url, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: body,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  });
}

async function accountError(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.json();
    if (!isRecord(body)) return undefined;
    if (typeof body.error === "string") return body.error;
    if (typeof body.grund === "string") return body.grund;
    if (typeof body.reason === "string") return body.reason;
  } catch {
    return undefined;
  }
  return undefined;
}

async function requestAccount(configuration: Configuration, key: KeyPair, path: string, content: Record<string, string>): Promise<Response> {
  try {
    return await signedRequest(configuration, key, path, content);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(2, "Request to the Subspace server failed.");
  }
}

async function runAccountFlow(options: AccountOptions): Promise<void> {
  if (options.positionals.length !== 1) throw new CliError(1, "Invalid usage of account.");
  const configuration = await loadConfiguration(resolveConfigPath(singleOption(options, "--config")));
  const key = await loadKey(singleOption(options, "--key", true)!);
  const waitInput = singleOption(options, "--wait");
  const waitSeconds = waitInput === undefined ? 900 : Number(waitInput);
  if (waitInput !== undefined && !/^\d+$/.test(waitInput) || !Number.isSafeInteger(waitSeconds) || waitSeconds < 0) {
    throw new CliError(1, "--wait must be a non-negative integer number of seconds.");
  }

  const codeReply = await requestAccount(configuration, key, "/v1/geraet/code", {
    box: Buffer.from(key.boxOeffentlich).toString("base64url"),
  });
  if (codeReply.status === 409 && await accountError(codeReply) === "schon_verbunden") {
    console.log("This agent is already connected to an account.");
    return;
  }
  if (codeReply.status !== 201) throw new CliError(2, "Request to the Subspace server failed.");

  let pairingCode: unknown;
  try {
    pairingCode = await codeReply.json();
  } catch {
    throw new CliError(2, "Invalid response from the Subspace server.");
  }
  if (!isValidDeviceCodeResponse(pairingCode)) throw new CliError(2, "Invalid response from the Subspace server.");

  console.log([
    `Open ${configuration.server}/device and enter this pairing code: ${pairingCode.user_code}`,
    `Enter on the page: ${fingerprint(key.signaturOeffentlich, key.boxOeffentlich).slice(0, 4)}`,
    "The page will show your agent. Compare the fingerprints:",
    `  SSH:       ${sshFingerprint(key.signaturOeffentlich, `${configuration.name}@subspace`)}`,
    `  Subspace: ${fingerprint(key.signaturOeffentlich, key.boxOeffentlich)}`,
    "Confirm on the page only if both match.",
    "Subspace is end-to-end encrypted. Your account never sees your message contents.",
  ].join("\n"));

  const deadline = Date.now() + Math.min(waitSeconds, pairingCode.expires_in) * 1000;
  let interval = pairingCode.interval;
  while (true) {
    const tokenResponse = await requestAccount(configuration, key, "/v1/geraet/token", {
      device_code: pairingCode.device_code,
    });
    if (tokenResponse.ok) {
      let result: unknown;
      try {
        result = await tokenResponse.json();
      } catch {
        throw new CliError(2, "Invalid response from the Subspace server.");
      }
      if (isRecord(result) && typeof result.mitglied === "string" && /^[a-z][a-z0-9-]{1,31}$/.test(result.mitglied)) { // wire format, keep
        console.log(`Connected to account ${result.mitglied}.`);
        return;
      }
      throw new CliError(2, "Invalid response from the Subspace server.");
    }

    const error = await accountError(tokenResponse);
    if (error === "expired_token") throw new CliError(2, "Pairing code has expired.");
    if (error === "access_denied") throw new CliError(3, "Connection was denied.");
    if (error !== "authorization_pending" && error !== "slow_down") throw new CliError(2, "Request to the Subspace server failed.");
    if (error === "slow_down") interval += 5;

    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new CliError(2, "Timed out waiting for the account connection.");
    await wait(Math.min(interval * 1000, remaining));
    if (Date.now() >= deadline) throw new CliError(2, "Timed out waiting for the account connection.");
  }
}

export async function runAccountCommand(command: string, options: AccountOptions): Promise<boolean> {
  if (command !== "account") return false;
  await runAccountFlow(options);
  return true;
}
