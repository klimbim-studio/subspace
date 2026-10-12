import { lstat, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { randomInt } from "node:crypto";
import { signiereAnfrage } from "../anfrage.ts";
import { fingerabdruck } from "../siegel.ts";
import { sshFingerabdruck } from "../ssh.ts";
import { CliFehler, ladeKonfiguration, ladeSchluessel } from "./gemeinsam.ts";
import { setup } from "./setup.ts";

const NAME = /^[a-z][a-z0-9-]{1,31}$/;
const RANDOM = "abcdefghijklmnopqrstuvwxyz0123456789";

async function exists(path: string): Promise<boolean> {
  try { await lstat(path); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}

function hostFromToken(value: string): { secret: string; host: string; postOffice: string } {
  const split = value.lastIndexOf("@");
  if (split <= 0 || split === value.length - 1) throw new CliFehler(1, "Invalid connect token.");
  const secret = value.slice(0, split);
  const host = value.slice(split + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) throw new CliFehler(1, "Invalid connect token.");
  let url: URL;
  try { url = new URL(`https://${host}`); } catch { throw new CliFehler(1, "Invalid post office address."); }
  if (url.host !== host || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new CliFehler(1, "Invalid post office address.");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) throw new CliFehler(1, "Invalid post office address.");
  const protocol = ["localhost", "127.0.0.1"].includes(url.hostname) ? "http:" : "https:";
  return { secret, host, postOffice: `${protocol}//${url.host}` };
}

export async function connect(tokenArg: string, options: { dir: string; name?: string }): Promise<void> {
  const input = tokenArg === "-" ? (await new Response(Bun.stdin.stream()).text()).trim() : tokenArg;
  const { secret, postOffice } = hostFromToken(input);
  const directory = resolve(options.dir);
  const configPath = join(directory, "config.json");
  const keyPath = join(directory, "key.json");
  const hasConfig = await exists(configPath);
  const hasKey = await exists(keyPath);
  if (hasConfig !== hasKey) throw new CliFehler(1, "Configuration and key must both exist.");
  let created = false;
  if (hasConfig && options.name !== undefined) throw new CliFehler(1, "--name cannot be used with an existing configuration.");
  let name: string;
  if (hasConfig) {
    const configuration = await ladeKonfiguration(configPath);
    if (configuration.postamt !== postOffice) throw new CliFehler(1, "Token post office does not match the existing configuration.");
    name = configuration.name;
  } else {
    name = options.name ?? `agent-${Array.from({ length: 6 }, () => RANDOM[randomInt(RANDOM.length)]).join("")}`;
    if (!NAME.test(name)) throw new CliFehler(1, "Invalid name.");
    await setup({ name, postamt: postOffice, ordner: directory });
    created = true;
  }
  let rejected = false;
  try {
    const configuration = await ladeKonfiguration(configPath);
    const keys = await ladeSchluessel(keyPath);
    const body = Buffer.from(JSON.stringify({
      token: secret,
      name,
      signature: Buffer.from(keys.signaturOeffentlich).toString("base64url"),
      box: Buffer.from(keys.boxOeffentlich).toString("base64url"),
    }));
    const url = `${postOffice}/v1/connect`;
    const signature = signiereAnfrage({ methode: "POST", url, koerper: body, name, signaturPrivat: keys.signaturPrivat });
    const response = await fetch(url, { method: "POST", headers: { ...signature, "content-type": "application/json" }, body, redirect: "error", signal: AbortSignal.timeout(30_000) });
    let result: { reason?: string; member?: string; agent?: string };
    try { result = await response.json() as { reason?: string; member?: string; agent?: string }; }
    catch { throw new Error("unreadable response"); }
    rejected = response.status >= 400 && response.status < 500;
    if (response.status === 403) throw new CliFehler(3, "Token is invalid, expired or already used. Create a new one in your profile.");
    if (response.status === 409 && result.reason === "name_taken") throw new CliFehler(3, "That name is taken. Run the command again with --name <other name>.");
    if (rejected) throw new CliFehler(3, "Post office rejected the connection.");
    if (!response.ok || typeof result.member !== "string" || typeof result.agent !== "string") throw new Error("invalid response");
    console.log(`Connected as ${name} to account ${result.member}.`);
    console.log(`SSH fingerprint: ${sshFingerabdruck(keys.signaturOeffentlich, name)}`);
    console.log(`Subspace fingerprint: ${fingerabdruck(keys.signaturOeffentlich, keys.boxOeffentlich)}`);
  } catch (error) {
    if (created && rejected) {
      await rm(configPath, { force: true });
      await rm(keyPath, { force: true });
    }
    if (error instanceof CliFehler && rejected) throw error;
    throw new CliFehler(3, "Connection failed. Run the same connect command again; your keys were kept.");
  }
}
