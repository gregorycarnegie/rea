import { createHash } from "node:crypto";
import { lstat, opendir, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import {
  openRegularFile,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import { parseGhidraJavaProperties } from "./GhidraJavaProperties.js";

/**
 * A caller-installed Ghidra processor extension a console profile depends on:
 * its directory under `Ghidra/Extensions`, which is also the `name` its
 * extension.properties must declare, and the installed components it needs.
 */
export interface GhidraConsoleExtensionRequirement {
  readonly id: string;
  /** Short component name used in refusal text, for example "Allegrex". */
  readonly displayName: string;
  /** Paths relative to the extension root, in addition to a `lib/*.jar`. */
  readonly requiredFiles: readonly string[];
}

/** Installed processor code and data, distinct from REA's analysis-extension ABI. */
export const ghidraConsoleExtensionSchema = z.strictObject({
  id: z.string().min(1),
  root: z.string().refine(isAbsolute),
  ghidra_version: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type GhidraConsoleExtension = z.infer<
  typeof ghidraConsoleExtensionSchema
>;

// Resource bounds for scanning a caller-installed extension, not target limits.
const MAX_ENTRIES = 1024;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_DEPTH = 16;

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraConsoleExtension = async (
  requirement: GhidraConsoleExtensionRequirement,
  root: string,
  ghidraVersion: string,
  signal?: AbortSignal,
): Promise<GhidraConsoleExtension> => {
  const name = requirement.displayName;
  signal?.throwIfAborted();
  if (!isAbsolute(root) || (await realpath(root)) !== root)
    throw new Error(
      `The installed ${name} directory must be a canonical non-symlink path.`,
    );
  const files: string[] = [];
  let entries = 1; // The root itself consumes one inventory entry.
  const visit = async (relative: string, depth: number): Promise<void> => {
    signal?.throwIfAborted();
    if (depth > MAX_DEPTH)
      throw new Error(
        `${name} extension directory nesting exceeds the inspection limit.`,
      );
    const path = join(root, relative);
    const metadata = await lstat(path);
    if (metadata.isDirectory()) {
      const children: string[] = [];
      for await (const child of await opendir(path)) {
        signal?.throwIfAborted();
        if (++entries > MAX_ENTRIES)
          throw new Error(
            `${name} extension inventory exceeds the inspection limit.`,
          );
        children.push(child.name);
      }
      children.sort();
      for (const child of children)
        await visit(
          relative === "" ? child : `${relative}/${child}`,
          depth + 1,
        );
    } else if (metadata.isFile()) {
      files.push(relative);
    } else
      throw new Error(
        `${name} extension entries must be regular files or directories: ${relative}`,
      );
  };
  await visit("", 0);
  for (const required of requirement.requiredFiles)
    if (!files.includes(required))
      throw new Error(`Missing installed ${name} component: ${required}`);
  if (!files.some((path) => path.startsWith("lib/") && path.endsWith(".jar")))
    throw new Error(`The installed ${name} extension has no loader JAR.`);
  const hash = createHash("sha256");
  let bytesRead = 0;
  let properties = Buffer.alloc(0);
  for (const relative of files) {
    signal?.throwIfAborted();
    const path = join(root, relative);
    const handle = await openRegularFile(path, { symlinks: "reject", signal });
    try {
      const before = await handle.stat();
      if (
        !Number.isSafeInteger(before.size) ||
        before.size > MAX_BYTES - bytesRead
      )
        throw new Error(`${name} extension bytes exceed the inspection limit.`);
      if (relative === "extension.properties" && before.size > 65536)
        throw new Error(
          `${name} extension properties exceed the inspection limit.`,
        );
      hash.update(JSON.stringify([relative, before.size]));
      const buffer = Buffer.alloc(Math.min(65536, before.size + 1));
      let offset = 0;
      const chunks: Buffer[] = [];
      while (offset < before.size) {
        signal?.throwIfAborted();
        const read = await handle.read(
          buffer,
          0,
          Math.min(buffer.length, before.size - offset),
          offset,
        );
        if (read.bytesRead === 0)
          throw new Error(`Truncated ${name} component: ${relative}`);
        const chunk = buffer.subarray(0, read.bytesRead);
        hash.update(chunk);
        if (relative === "extension.properties")
          chunks.push(Buffer.from(chunk));
        offset += read.bytesRead;
      }
      if (
        !sameRegularFileState(before, await handle.stat()) ||
        !sameRegularFileState(before, await lstat(path))
      )
        throw new Error(
          `${name} component changed during inspection: ${relative}`,
        );
      bytesRead += before.size;
      if (relative === "extension.properties")
        properties = Buffer.concat(chunks);
    } finally {
      await handle.close();
    }
  }
  // Ghidra's extension.properties version is the compatible Ghidra version,
  // not the extension release (e.g. v21.4); content identity supplies the latter.
  const parsedProperties = parseGhidraJavaProperties(
    properties.toString("latin1"),
  );
  if (!parsedProperties.ok)
    throw new Error(
      `Invalid ${name} extension properties: ${parsedProperties.error}`,
    );
  const property = (key: string): string | undefined =>
    parsedProperties.value.get(key);
  if (
    property("name") !== requirement.id ||
    property("version") !== ghidraVersion
  )
    throw new Error(
      `${name} extension metadata does not match the selected Ghidra ${ghidraVersion}; install or rebuild a compatible extension.`,
    );
  signal?.throwIfAborted();
  return {
    id: requirement.id,
    root,
    ghidra_version: ghidraVersion,
    sha256: hash.digest("hex"),
  };
};

/** The extension a profile needs, and where its refusals point the caller. */
export interface GhidraConsoleExtensionResolution {
  readonly extension: GhidraConsoleExtensionRequirement;
  /** Prefix of the refusal reason, for example "PSP_EXTENSION_UNAVAILABLE". */
  readonly unavailableCode: string;
  /** Null when the installation is available on a host verified for this profile. */
  readonly hostRefusal: (
    installation: GhidraInstallationInspection,
  ) => string | null;
}

/** Resolve prerequisites before opening or admitting cached console analysis. */
export const resolveGhidraConsoleExtension = async (
  resolution: GhidraConsoleExtensionResolution,
  installation: GhidraInstallationInspection,
  signal?: AbortSignal,
): Promise<Result<GhidraConsoleExtension, AnalysisError>> => {
  if (signal?.aborted)
    return err(new AnalysisCancelledError("resolve_analysis_profile"));
  const { extension } = resolution;
  try {
    const hostRefusal = resolution.hostRefusal(installation);
    if (hostRefusal !== null || installation.status !== "available")
      throw new Error(
        hostRefusal ?? "The selected Ghidra installation is unavailable.",
      );
    const root = join(
      await realpath(installation.installDir),
      "Ghidra",
      "Extensions",
      extension.id,
    );
    return ok(
      await inspectGhidraConsoleExtension(
        extension,
        root,
        installation.providerVersion,
        signal,
      ),
    );
  } catch (cause: unknown) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("resolve_analysis_profile"));
    const reason = `${resolution.unavailableCode}: ${cause instanceof Error ? cause.message : String(cause)} Use a compatible caller-installed ${extension.id} under GHIDRA_INSTALL_DIR/Ghidra/Extensions; REA does not install it.`;
    return err(
      new AnalysisCapabilityUnavailableError(
        "ghidra",
        "resolve_analysis_profile",
        reason,
        { cause, userMessage: reason },
      ),
    );
  }
};
