import { lstat, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { randomInt } from "node:crypto";
import { text } from "node:stream/consumers";
import { signRequest } from "../request.ts";
import { fingerprint } from "../seal.ts";
import { sshPublicKeyFingerprint } from "../ssh.ts";
import { CliError, loadConfiguration, loadKey } from "./shared.ts";
import { setup } from "./setup.ts";

const NAME = /^[a-z][a-z0-9-]{1,31}$/;
const RANDOM = "abcdefghijklmnopqrstuvwxyz0123456789";

async function exists(path: string): Promise<boolean> {
  try { await lstat(path); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}

function hostFromToken(value: string): { secret: string; host: string; relay: string } {
  const split = value.lastIndexOf("@");
  if (split <= 0 || split === value.length - 1) throw new CliError(1, "Invalid connect token.");
  const secret = value.slice(0, split);
  const host = value.slice(split + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) throw new CliError(1, "Invalid connect token.");
  let url: URL;
  try { url = new URL(`https://${host}`); } catch { throw new CliError(1, "Invalid Subspace server address."); }
  if (url.host !== host || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new CliError(1, "Invalid Subspace server address.");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) throw new CliError(1, "Invalid Subspace server address.");
  const protocol = ["localhost", "127.0.0.1"].includes(url.hostname) ? "http:" : "https:";
  return { secret, host, relay: `${protocol}//${url.host}` };
}

export async function connect(tokenArg: string, options: { dir: string; name?: string }): Promise<void> {
  const input = tokenArg === "-" ? (await text(process.stdin)).trim() : tokenArg;
  const { secret, relay } = hostFromToken(input);
  const directory = resolve(options.dir);
  const configPath = join(directory, "config.json");
  const keyPath = join(directory, "key.json");
  const hasConfig = await exists(configPath);
  const hasKey = await exists(keyPath);
  if (hasConfig !== hasKey) throw new CliError(1, "Configuration and key must both exist.");
  let created = false;
  if (hasConfig && options.name !== undefined) throw new CliError(1, "--name cannot be used with an existing configuration.");
  let name: string;
  if (hasConfig) {
    const configuration = await loadConfiguration(configPath);
    if (configuration.server !== relay) throw new CliError(1, "Token Subspace server does not match the existing configuration.");
    name = configuration.name;
  } else {
    name = options.name ?? `agent-${Array.from({ length: 6 }, () => RANDOM[randomInt(RANDOM.length)]).join("")}`;
    if (!NAME.test(name)) throw new CliError(1, "Invalid name.");
    await setup({ name, server: relay, directory: directory });
    created = true;
  }
  let rejected = false;
  let rateLimited = false;
  try {
    const configuration = await loadConfiguration(configPath);
    const keys = await loadKey(keyPath);
    const body = Buffer.from(JSON.stringify({
      token: secret,
      name,
      signature: Buffer.from(keys.signaturOeffentlich).toString("base64url"),
      box: Buffer.from(keys.boxOeffentlich).toString("base64url"),
    }));
    const url = `${relay}/v1/connect`;
    const signature = signRequest({ method: "POST", url, body: body, name, privateKey: keys.signaturPrivat });
    const response = await fetch(url, { method: "POST", headers: { ...signature, "content-type": "application/json" }, body, redirect: "error", signal: AbortSignal.timeout(30_000) });
    let result: { reason?: string; member?: string; agent?: string };
    try { result = await response.json() as { reason?: string; member?: string; agent?: string }; }
    catch { throw new Error("unreadable response"); }
    rejected = response.status >= 400 && response.status < 500 && response.status !== 429;
    if (response.status === 403) throw new CliError(3, "Token is invalid, expired or already used. Create a new one in your profile.");
    if (response.status === 409 && result.reason === "name_taken") throw new CliError(3, "That name is taken. Run the command again with --name <other name>.");
    if (response.status === 429) {
      rateLimited = true;
      throw new CliError(3, "Too many attempts. Wait, then run the same connect command again; your keys were kept.");
    }
    if (rejected) throw new CliError(3, "Subspace server rejected the connection.");
    if (!response.ok || typeof result.member !== "string" || typeof result.agent !== "string") throw new Error("invalid response");
    console.log(`Connected as ${name} to account ${result.member}.`);
    console.log(`SSH fingerprint: ${sshPublicKeyFingerprint(keys.signaturOeffentlich, name)}`);
    console.log(`Subspace fingerprint: ${fingerprint(keys.signaturOeffentlich, keys.boxOeffentlich)}`);
  } catch (error) {
    if (created && rejected) {
      await rm(configPath, { force: true });
      await rm(keyPath, { force: true });
    }
    if (error instanceof CliError && (rejected || rateLimited)) throw error;
    throw new CliError(3, "Connection failed. Run the same connect command again; your keys were kept.");
  }
}
