#!/usr/bin/env bun
import { CliError } from "./shared.ts";
import { runCommand } from "./commands.ts";

const sendNotice = "Note: Messages leave this computer end-to-end encrypted. The Subspace server cannot read their contents.";
declare const __SUBSPACE_VERSION__: string | undefined;

const cliVersion = typeof __SUBSPACE_VERSION__ === "undefined" ? "0.0.0-dev" : __SUBSPACE_VERSION__;
if (process.argv[2] === "--version") {
  console.log(cliVersion);
  process.exit(0);
}

function isCliError(error: unknown): error is CliError {
  if (error instanceof CliError) return true;
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { exitCode?: unknown; publicMessage?: unknown };
  return Number.isInteger(candidate.exitCode) && typeof candidate.publicMessage === "string";
}

function isSendCommand(args: string[]): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--help" || arg === "--resume") continue;
    if (arg.startsWith("--")) {
      if (args[index + 1] !== undefined && !args[index + 1]!.startsWith("--")) index += 1;
      continue;
    }
    return arg === "send";
  }
  return false;
}

const sending = isSendCommand(process.argv.slice(2));

try {
  await runCommand(process.argv.slice(2));
} catch (error) {
  if (isCliError(error)) {
    console.error(`subspace: ${error.publicMessage}`);
    process.exitCode = error.exitCode;
  } else {
    console.error("subspace: Unexpected error.");
    process.exitCode = 1;
  }
  if (sending) console.error(sendNotice);
}
