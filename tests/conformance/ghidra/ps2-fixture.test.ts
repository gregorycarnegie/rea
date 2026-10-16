import assert from "node:assert/strict";
import { it } from "vitest";
import { parseExecutableHeader } from "../../../src/domain/binaryTarget.js";
import {
  ghidraConsoleProfile,
  ghidraProcessorUnsupportedReason,
} from "../../../src/ghidra/GhidraConsoleProfile.js";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import {
  buildPs2Fixture,
  PS2_CALLEE,
  PS2_ELF_FLAGS,
  PS2_ENTRY,
} from "./ps2-fixture.mjs";

// Field-level decoding of the hand-assembled words, independent of Ghidra and
// of the fixture's own comments: opcode, registers and immediates.
const opcode = (word: number) => word >>> 26;
const rs = (word: number) => (word >>> 21) & 0x1f;
const rt = (word: number) => (word >>> 16) & 0x1f;
const rd = (word: number) => (word >>> 11) & 0x1f;
const immediate = (word: number) => word & 0xffff;

it("encodes the documented R5900 instructions", () => {
  const { instructions } = buildPs2Fixture();
  const at = (address: number) => {
    const found = instructions.find((value) => value.address === address);
    assert.ok(found, `no instruction at 0x${address.toString(16)}`);
    return found.word;
  };
  const lq = at(PS2_ENTRY);
  assert.deepEqual(
    [opcode(lq), rs(lq), rt(lq), immediate(lq)],
    [0x1e, 4, 8, 0x10],
  );
  const paddw = at(PS2_ENTRY + 4);
  assert.deepEqual(
    [
      opcode(paddw),
      rs(paddw),
      rt(paddw),
      rd(paddw),
      (paddw >>> 6) & 0x1f,
      paddw & 0x3f,
    ],
    [0x1c, 8, 8, 9, 0, 0x08],
  );
  const sq = at(PS2_ENTRY + 8);
  assert.deepEqual(
    [opcode(sq), rs(sq), rt(sq), immediate(sq)],
    [0x1f, 4, 9, 0x20],
  );
  const jal = at(PS2_ENTRY + 12);
  assert.equal(opcode(jal), 0x03);
  assert.equal(
    ((jal & 0x03ffffff) << 2) | (PS2_ENTRY & 0xf0000000),
    PS2_CALLEE,
  );
  const addiu = at(PS2_CALLEE);
  assert.deepEqual(
    [opcode(addiu), rs(addiu), rt(addiu), immediate(addiu)],
    [0x09, 0, 2, 0x1234],
  );
});

it("is owned and admitted by the PS2 profile from its header alone", () => {
  const { bytes, sha256 } = buildPs2Fixture();
  const parsed = parseExecutableHeader(bytes, "x64");
  if (!parsed.ok) throw new Error(parsed.error);
  assert.equal(parsed.value.architecture, "mips");
  if (parsed.value.architecture !== "mips") return;
  assert.equal(parsed.value.mips.flags, PS2_ELF_FLAGS);
  // The real target reader inspects ABI declarations; this header has none.
  const target: BinaryTarget = {
    kind: "executable",
    path: "/fixture/ps2.elf",
    sha256,
    ...parsed.value,
    mips: { ...parsed.value.mips, abiFlags: null, gnuAttributes: null },
  };
  assert.equal(ghidraConsoleProfile(target)?.id, "ps2");
  assert.equal(ghidraProcessorUnsupportedReason(target), null);
  const refused = buildPs2Fixture(PS2_ELF_FLAGS | 1).bytes;
  const other = parseExecutableHeader(refused, "x64");
  if (!other.ok || other.value.architecture !== "mips")
    throw new Error("refusal fixture was not MIPS");
  assert.match(
    ghidraProcessorUnsupportedReason({
      ...target,
      mips: { ...other.value.mips, abiFlags: null, gnuAttributes: null },
    }) ?? "",
    /0x20924000/u,
  );
});
