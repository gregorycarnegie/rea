import type {
  BinaryTarget,
  MipsElfMetadata,
} from "../domain/binaryTargetTypes.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import type { GhidraConsoleExtensionResolution } from "./GhidraConsoleExtension.js";
import {
  ghidraMipsGnuAttributesUnsupportedReason,
  ghidraMipsIncompleteDeclarationsReason,
  ghidraMipsUnsupportedReason,
} from "./GhidraMipsProfile.js";
import { ghidraPowerPcUnsupportedReason } from "./GhidraPowerPcProfile.js";
import { ghidraRiscvUnsupportedReason } from "./GhidraRiscvProfile.js";

/** A host REA has verified a console profile on, as Ghidra reports it. */
interface GhidraConsoleHost {
  readonly platform: NodeJS.Platform;
  readonly architecture: NodeJS.Architecture;
}

/**
 * A game-console executable interpretation owned by a caller-installed Ghidra
 * processor extension. Each profile is admitted from header declarations only,
 * pins its loader, language and compiler, fingerprints its extension, and is
 * served only on hosts where it has been verified with a real Ghidra.
 */
export interface GhidraConsoleProfile extends GhidraConsoleExtensionResolution {
  readonly id: "psp" | "ps2";
  /** Display name used in refusal text, for example "PSP Allegrex". */
  readonly displayName: string;
  /** Committed profile parameter naming the support lane and its revision. */
  readonly lane: string;
  /** Committed profile parameter holding the extension identity. */
  readonly extensionParameter: "psp_extension" | "ps2_extension";
  /** Ghidra loader class the import must use. */
  readonly loader: string;
  readonly languageId: string;
  readonly compilerSpecId: string;
  readonly hosts: readonly GhidraConsoleHost[];
  /** The verified hosts as refusal text, for example "Linux x64". */
  readonly hostDescription: string;
  /** Whether this profile owns the target's interpretation. */
  readonly matches: (target: BinaryTarget) => boolean;
  /** Bounded admission of the owned target's declarations. */
  readonly unsupportedReason: (target: BinaryTarget) => string | null;
  /** Propagated with every observation the profile serves. */
  readonly limitations: readonly string[];
}

const mipsElf = (target: BinaryTarget): MipsElfMetadata | undefined =>
  target.kind === "executable" &&
  target.format === "elf" &&
  target.architecture === "mips"
    ? target.mips
    : undefined;

/** EF_MIPS_MACH declares the machine variant; filenames never select a profile. */
const mipsMachine = (target: BinaryTarget, machine: number): boolean =>
  ((mipsElf(target)?.flags ?? 0) & 0x00ff0000) === machine << 16;

const onHost = (
  hosts: readonly GhidraConsoleHost[],
  platform: NodeJS.Platform,
  architecture: NodeJS.Architecture,
): boolean =>
  hosts.some(
    (host) => host.platform === platform && host.architecture === architecture,
  );

const hostRefusal =
  (hosts: readonly GhidraConsoleHost[], refusal: string) =>
  (installation: GhidraInstallationInspection): string | null =>
    installation.status === "available" &&
    onHost(hosts, installation.platform, installation.architecture)
      ? null
      : refusal;

const PSP_HOSTS = [{ platform: "linux", architecture: "x64" }] as const;
const PS2_HOSTS = [{ platform: "win32", architecture: "x64" }] as const;

const PSP: GhidraConsoleProfile = {
  id: "psp",
  displayName: "PSP Allegrex",
  lane: "psp-elf32-exec-eabi32-allegrex-v2",
  extensionParameter: "psp_extension",
  loader: "PspElfLoader",
  languageId: "Allegrex:LE:32:default",
  compilerSpecId: "default",
  hosts: PSP_HOSTS,
  hostDescription: "Linux x64",
  hostRefusal: hostRefusal(
    PSP_HOSTS,
    "The initial PSP profile requires a supported Linux x64 Ghidra installation.",
  ),
  unavailableCode: "PSP_EXTENSION_UNAVAILABLE",
  extension: {
    id: "ghidra-allegrex",
    displayName: "Allegrex",
    requiredFiles: [
      "Module.manifest",
      "extension.properties",
      "data/languages/allegrex.ldefs",
      "data/languages/allegrex.sla",
      "data/languages/allegrex.pspec",
      "data/languages/allegrex.cspec",
    ],
  },
  /** Allegrex's ELF machine declaration, not a filename or inferred instruction. */
  matches: (target) => mipsMachine(target, 0xa2),
  unsupportedReason: (target) => {
    const metadata = mipsElf(target);
    if (metadata === undefined) return "PSP analysis requires ELF metadata.";
    const gnuAttributesReason =
      ghidraMipsGnuAttributesUnsupportedReason(metadata);
    if (gnuAttributesReason !== null) return gnuAttributesReason;
    const incomplete = ghidraMipsIncompleteDeclarationsReason(metadata);
    if (incomplete !== null) return incomplete;
    if (metadata.elfClass !== 32 || metadata.byteOrder !== "little")
      return "The PSP Allegrex profile requires little-endian ELF32.";
    if (metadata.type !== 2)
      return "The PSP Allegrex profile supports static ET_EXEC only; PRX, shared and relocatable images require separate verification.";
    // PSPSDK emits MIPS-II / Allegrex / EABI32 with NOREORDER. Do not accept
    // unknown producer flags or treat this as proof of instruction semantics.
    if (metadata.flags !== 0x10a23001)
      return "The PSP Allegrex profile requires the verified PSPSDK ELF declaration 0x10a23001; other ISA/ABI/ASE flags are not inferred.";
    const abi = metadata.abiFlags;
    if (abi === undefined || abi === null)
      return "The PSP Allegrex profile requires an inspected separate MIPS ABI flags record; missing declarations are not inferred.";
    // PSPDEV v20261001: GNU readelf 2.44 and the 24-byte record agree on
    // MIPS II, 32-bit registers, single-precision hard float and flags1=1.
    // This is a bounded producer declaration, not a claim about VFPU semantics.
    if (
      abi.version !== 0 ||
      abi.isaLevel !== 2 ||
      abi.isaRevision !== 0 ||
      abi.gprSize !== 1 ||
      abi.cpr1Size !== 1 ||
      abi.cpr2Size !== 0 ||
      abi.fpAbi !== 2 ||
      abi.isaExtension !== 0 ||
      abi.ases !== 0 ||
      abi.flags1 !== 1 ||
      abi.flags2 !== 0
    )
      return "The separate MIPS ABI flags record does not match the verified PSP MIPS-II/32-bit/single-float declaration; other versions, register modes and extension flags require separate verification.";
    return null;
  },
  limitations: [
    "PSP/Allegrex analysis uses the caller-installed ghidra-allegrex extension. ELF declarations and selected instruction checks are not proof of runtime semantics.",
    "ghidra-allegrex does not model VFPU prefix effects completely in decompiled output. Verify vector behavior independently; pseudocode is not an execution oracle.",
    "This PSP profile covers static ELF32 ET_EXEC only. PRX relocations, PBP/ISO containers, live overlays and PSP emulation are outside this verified lane.",
  ],
};

const PS2: GhidraConsoleProfile = {
  id: "ps2",
  displayName: "PS2 Emotion Engine",
  lane: "ps2-elf32-exec-eabi64-r5900-v1",
  extensionParameter: "ps2_extension",
  loader: "ElfLoader",
  languageId: "r5900:LE:32:default",
  compilerSpecId: "default",
  hosts: PS2_HOSTS,
  hostDescription: "Windows x64",
  hostRefusal: hostRefusal(
    PS2_HOSTS,
    "The initial PS2 profile requires a supported Windows x64 Ghidra installation.",
  ),
  unavailableCode: "PS2_EXTENSION_UNAVAILABLE",
  extension: {
    id: "ghidra-emotionengine-reloaded",
    displayName: "Emotion Engine",
    requiredFiles: [
      "Module.manifest",
      "extension.properties",
      "data/languages/emotionengine.ldefs",
      "data/languages/r5900.sla",
      "data/languages/r5900.pspec",
      "data/languages/r5900.cspec",
    ],
  },
  /** EF_MIPS_MACH 0x92 is the R5900 (Emotion Engine) declaration. */
  matches: (target) => mipsMachine(target, 0x92),
  unsupportedReason: (target) => {
    const metadata = mipsElf(target);
    if (metadata === undefined) return "PS2 analysis requires ELF metadata.";
    const gnuAttributesReason =
      ghidraMipsGnuAttributesUnsupportedReason(metadata);
    if (gnuAttributesReason !== null) return gnuAttributesReason;
    const incomplete = ghidraMipsIncompleteDeclarationsReason(metadata);
    if (incomplete !== null) return incomplete;
    if (metadata.elfClass !== 32 || metadata.byteOrder !== "little")
      return "The PS2 Emotion Engine profile requires little-endian ELF32.";
    if (metadata.type !== 2)
      return "The PS2 Emotion Engine profile supports static ET_EXEC only; IRX modules, relocatable and shared images require separate verification.";
    // MIPS III, R5900 and EABI64 without ASE, FP64 or NaN2008 bits: the Sony EE
    // linker's declaration, which the extension's own ELF opinion also claims.
    if (metadata.flags !== 0x20924000)
      return "The PS2 Emotion Engine profile requires the verified EE ELF declaration 0x20924000; other ISA/ABI/ASE flags are not inferred.";
    if (metadata.abiFlags === undefined)
      return "The PS2 Emotion Engine profile requires an inspected MIPS ABI flags declaration source; an uninspected record is not inferred absent.";
    if (metadata.abiFlags !== null)
      return "The PS2 Emotion Engine profile requires the verified EE declaration without a separate MIPS ABI flags record; a record's semantics are not inferred.";
    return null;
  },
  limitations: [
    "PS2/Emotion Engine analysis uses the caller-installed ghidra-emotionengine-reloaded extension. ELF declarations and selected instruction checks are not proof of runtime semantics.",
    "Only Emotion Engine code in the executable is modelled. Vector-unit microcode, IOP (IRX) modules, VIF/DMA packets and memory-mapped hardware behavior are outside this lane; decompiled COP2/MMI code is not an execution oracle.",
    "This PS2 profile covers static ELF32 ET_EXEC only. IRX modules, ISO/CDVD containers, overlays loaded at runtime and PS2 emulation are outside this verified lane.",
  ],
};

/** Registered console profiles, matched by their header declarations. */
export const GHIDRA_CONSOLE_PROFILES: readonly GhidraConsoleProfile[] = [
  PSP,
  PS2,
];

/** The console profile that owns this target's interpretation, if any. */
export const ghidraConsoleProfile = (
  target: BinaryTarget,
): GhidraConsoleProfile | undefined =>
  GHIDRA_CONSOLE_PROFILES.find((profile) => profile.matches(target));

/** Whether a host is one this console profile has been verified on. */
export const ghidraConsoleHostSupported = (
  profile: GhidraConsoleProfile,
  platform: NodeJS.Platform,
  architecture: NodeJS.Architecture,
): boolean => onHost(profile.hosts, platform, architecture);

/** Console profiles own their interpretation; generic family rules stay unchanged. */
export const ghidraProcessorUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind === "executable" && target.architecture === "powerpc")
    return ghidraPowerPcUnsupportedReason(target);
  if (target.kind === "executable" && target.architecture === "riscv")
    return ghidraRiscvUnsupportedReason(target);
  const profile = ghidraConsoleProfile(target);
  return profile === undefined
    ? ghidraMipsUnsupportedReason(target)
    : profile.unsupportedReason(target);
};
