import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  buildPs2Fixture,
  PS2_CALLEE,
  PS2_ELF_FLAGS,
  PS2_ENTRY,
} from "../tests/conformance/ghidra/ps2-fixture.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// PS2 / Emotion Engine console profile against a real Ghidra with the
// caller-installed ghidra-emotionengine-reloaded extension. No tool acquisition
// and no target execution; the fixture is generated, not commercial data.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-ps2.mjs");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation with ghidra-emotionengine-reloaded.",
  );
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-ps2-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const entrypoint = join(root, "scripts", "rea.mjs");
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const hex = (value) => `0x${value.toString(16)}`;
const fixture = buildPs2Fixture();
const path = join(workspace, "ee.elf");
await writeFile(path, fixture.bytes);
const refusedPath = join(workspace, "ee-other-flags.elf");
await writeFile(refusedPath, buildPs2Fixture(PS2_ELF_FLAGS | 1).bytes);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-ps2-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await client.connect(transport);
  const opened = await call("open_binary", { path, provider_id: "ghidra" });
  assert.equal(opened.architecture, "mips");
  const image = evidence(await call("inspect_native_load_image"));
  // Independent load-image verification covers DOS and raw images; for ELF the
  // observations report what Ghidra loaded, which must be the pinned EE import.
  const loaded = image.normalized_result.observations;
  assert.equal(loaded.executable_format, "Executable and Linking Format (ELF)");
  assert.equal(loaded.language_id, "r5900:LE:32:default");
  assert.equal(loaded.compiler_spec_id, "default");
  assert.equal(loaded.image_base, hex(PS2_ENTRY));
  assert.ok(
    loaded.mappings.some(
      (mapping) =>
        mapping.start === hex(PS2_ENTRY) &&
        mapping.length === fixture.codeSize &&
        mapping.initialized,
    ),
    JSON.stringify(loaded.mappings),
  );
  const parameters = image.analysis_profile.parameters;
  assert.equal(parameters.mips_support_lane, "ps2-elf32-exec-eabi64-r5900-v1");
  assert.equal(parameters.loader, "ElfLoader");
  assert.equal(parameters.language_id, "r5900:LE:32:default");
  assert.equal(parameters.ps2_extension.id, "ghidra-emotionengine-reloaded");
  assert.match(parameters.ps2_extension.sha256, /^[a-f0-9]{64}$/u);
  assert.ok(
    image.limitations.some((limitation) =>
      limitation.includes("ghidra-emotionengine-reloaded"),
    ),
  );
  const entryWords = fixture.instructions.filter(
    (instruction) => instruction.address < PS2_CALLEE,
  );
  const memory = evidence(
    await call("read_bytes", {
      address: hex(PS2_ENTRY),
      length: entryWords.length * 4,
    }),
  );
  assert.equal(
    memory.normalized_result.bytes_hex,
    fixture.bytes
      .subarray(fixture.codeOffset, fixture.codeOffset + entryWords.length * 4)
      .toString("hex"),
  );
  // R5900-only encodings decode as EE instructions, which proves the pinned
  // extension language, not a generic MIPS fallback, served the session.
  const decoded = [];
  for (const { address, mnemonic } of fixture.instructions.filter(
    ({ mnemonic }) => ["lq", "paddw", "sq", "jal"].includes(mnemonic),
  )) {
    const instruction = evidence(
      await call("inspect_native_instruction", { address: hex(address) }),
    );
    assert.equal(
      instruction.normalized_result.mnemonic.toLowerCase().replace(/^_/u, ""),
      mnemonic,
      JSON.stringify(instruction.normalized_result),
    );
    decoded.push(mnemonic);
    if (mnemonic === "jal")
      assert.ok(
        instruction.normalized_result.references.some(
          (reference) =>
            reference.call && reference.target_address === hex(PS2_CALLEE),
        ),
        JSON.stringify(instruction.normalized_result.references),
      );
  }
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: hex(PS2_CALLEE) }),
  );
  assert.match(pseudo.normalized_result, /0x1234/u);
  await call("close_binary");
  await client.ping();
  const cli = async (args) => {
    const { stdout } = await exec(process.execPath, [entrypoint, ...args], {
      env,
      timeout: 600000,
      maxBuffer: 16 * 1024 * 1024,
    });
    return JSON.parse(stdout);
  };
  const cliImage = evidence(
    await cli([
      "inspect-native-load-image",
      path,
      "--provider",
      "ghidra",
      "--json",
    ]),
  );
  assert.deepEqual(cliImage.normalized_result, image.normalized_result);
  assert.equal(cliImage.analysis_profile.digest, image.analysis_profile.digest);
  const snapshotPath = join(workspace, "ee-snapshot.json");
  await cli([
    "analyze",
    path,
    "--provider",
    "ghidra",
    "--snapshot",
    snapshotPath,
    "--json",
  ]);
  const snapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
  assert.equal(
    snapshot.binding.analysis_profile.parameters.ps2_extension.sha256,
    parameters.ps2_extension.sha256,
  );
  const replayed = evidence(
    await cli([
      "decompile",
      path,
      hex(PS2_CALLEE),
      "--provider",
      "ghidra",
      "--snapshot",
      snapshotPath,
      "--json",
    ]),
  );
  assert.equal(replayed.normalized_result, pseudo.normalized_result);
  await assert.rejects(
    cli(["analyze", refusedPath, "--provider", "ghidra", "--json"]),
    (cause) => {
      assert.match(cause.stdout + cause.stderr, /0x20924000/u);
      return true;
    },
  );
  assert.deepEqual(await readFile(path), fixture.bytes);
  assert.deepEqual(await readdir(runtime), []);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-ps2",
    host: `${process.platform}/${process.arch}`,
    provider: image.provider,
    extension: parameters.ps2_extension,
    target: {
      sha256: fixture.sha256,
      bytes: fixture.bytes.length,
      flags: hex(PS2_ELF_FLAGS),
      entry: hex(PS2_ENTRY),
    },
    r5900_instructions_decoded: decoded,
    call_reference: true,
    decompilation: true,
    cli_mcp_load_image_parity: true,
    snapshot_replay: true,
    other_declaration_refused: true,
    source_unchanged: true,
    runtime_cleanup: "complete",
  };
} catch (cause) {
  if (stderr) process.stderr.write(stderr);
  throw cause;
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
  }
}
const verifierRun = await completeVerifierRun(run);
if (process.platform !== "win32") {
  assert.equal(verifierRun.process_lineage.status, "verified");
  assert.deepEqual(verifierRun.process_lineage.descendants, []);
}
// Keep the workspace for diagnosis unless verification and cleanup both pass.
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 600000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  if (["open_binary", "binary_session", "close_binary"].includes(name))
    return requireMcpOperationResult(result, name);
  return result.structuredContent;
}

function evidence(value) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, fixture.sha256);
  assert.equal(result.subject.architecture, "mips");
  assert.equal(result.subject.format, "elf");
  return result;
}
