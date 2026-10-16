# PS2 static ELF analysis through Ghidra

This console profile builds on [generic MIPS support](ghidra-mips.md) and shares
the [PSP profile](ghidra-psp.md)'s console-profile mechanism
(`src/ghidra/GhidraConsoleProfile.ts`). It reuses REA's existing CLI/MCP, Ghidra
bridge, Evidence and snapshot workflows. Emotion Engine (R5900) instructions,
including 128-bit MMI and COP2 macro-mode encodings, remain owned by
[ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded).

## Initial boundary

The initial profile is limited to Windows x64, little-endian ELF32 `ET_EXEC`,
`EM_MIPS` and the EE linker declaration `e_flags=0x20924000`. Those bits declare
MIPS III, machine `EF_MIPS_MACH=0x92` (R5900) and EABI64; they are not proof of
every instruction's semantics. The extension's own ELF opinion claims the same
shape. The profile also requires an inspected absence of a separate MIPS ABI
flags record, which this producer does not emit; an uninspected or present record
is refused rather than inferred. Other flag combinations, including NOREORDER or
PIC variants from other toolchains, are refused until verified separately.
The PS2 profile is not an exception to the generic MIPS32r2/o32 policy; that
separate gate is unchanged.

IOP modules (IRX), relocatable/shared images, ISO/CDVD containers, overlays loaded
at runtime, vector-unit microcode, VIF/DMA packets and PS2 emulation are outside
this first profile. Linux and macOS hosts are refused until verified separately.
File names do not identify a PS2 target.

## Bring your own compatible extension

Install the extension in the selected Ghidra distribution at
`GHIDRA_INSTALL_DIR\Ghidra\Extensions\ghidra-emotionengine-reloaded`, with its
`Module.manifest`, `extension.properties`, `emotionengine.ldefs`, compiled
`r5900` language files and loader JAR. User-home installations are not searched.
REA never downloads, installs, rebuilds or vendors the extension. Its
`extension.properties` `version` must match the selected Ghidra version.

REA fingerprints installed extension files before resolving the analysis profile
and checks that identity again immediately before launch, with the same bounds
and refusals as the [PSP extension](ghidra-psp.md#bring-your-own-compatible-extension).
Content changes yield a different profile; an old snapshot is not silently reused.

## Ordinary public interfaces

```powershell
rea analyze C:\absolute\path\to\game.elf --provider ghidra --json
rea decompile C:\absolute\path\to\game.elf 0x00100040 --provider ghidra --json
```

MCP uses `open_binary` with an absolute path and `provider_id: "ghidra"`, then
ordinary inventory and function operations. The import is explicitly `ElfLoader`,
language `r5900:LE:32:default`, compiler `default`; the bridge handshake must
confirm the language and compiler before serving observations. A configured
`REA_GHIDRA_LANGUAGE_ID` is refused for this profile. Missing prerequisites return
`PS2_EXTENSION_UNAVAILABLE` with an installation remedy; no provider fallback or
automatic installation occurs.

Evidence retains the `mips` architecture family, the `ps2-elf32-exec-eabi64-r5900-v1`
support lane and the extension's content identity, with the EE-only, static-only
limitations. Decompiled MMI/COP2 code is not an execution oracle.

## Verification

```powershell
npm run build:cached
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_12.1.4_PUBLIC"
$env:JAVA_HOME = "C:\path\to\jdk"
node scripts/verify-real-ghidra-ps2.mjs
```

Set `JAVA_HOME` explicitly: Oracle's `javapath` redirector otherwise writes a
`JavaLauncher.log` into the verifier's private temporary directory, which fails
its cleanup check.

The fixture (`tests/conformance/ghidra/ps2-fixture.mjs`) is generated and
non-commercial: one `PT_LOAD` at `0x00100000` holding hand-assembled R5900 words
whose fields are listed beside each word and decoded independently by
`ps2-fixture.test.ts`. It is not produced by a PS2 toolchain. The verifier
requires that `lq`, `paddw` and `sq`, which do not decode as those instructions in
generic MIPS languages, decode through the pinned language; that `jal` records a
call to the callee; that the callee decompiles its `0x1234` immediate; CLI/MCP
load-image parity; snapshot replay with the same extension identity; refusal of
`0x20924001`; unchanged source bytes; and complete runtime cleanup. ELF load-image
inspection reports Ghidra's observed loader, language and mappings; independent
load-image attestation remains limited to DOS and raw images.

Verified with Ghidra 12.1.4, ghidra-emotionengine-reloaded for 12.1.4, Temurin/
Oracle JDK 26 and Node.js 26 on Windows 11 x64. These are selected static facts,
not full behavioral equivalence or arbitrary PS2 compatibility.
