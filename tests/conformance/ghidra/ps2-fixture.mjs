import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** EE linker declaration: MIPS III, EF_MIPS_MACH 0x92 (R5900), EABI64. */
export const PS2_ELF_FLAGS = 0x20924000;
export const PS2_ENTRY = 0x00100000;
export const PS2_CALLEE = 0x00100040;

// Hand-assembled from the R5900 encodings; each word lists its fields so a
// reviewer can check it without a PS2 toolchain. lq, paddw and sq do not
// decode as these instructions in generic MIPS32/MIPS64 languages.
const ENTRY_CODE = [
  // lq $t0, 0x10($a0): LQ opcode 0x1e, base 4, rt 8, offset 0x10
  [0x78880010, "lq"],
  // paddw $t1, $t0, $t0: MMI opcode 0x1c, rs 8, rt 8, rd 9, MMI0 0x00, funct 0x08
  [0x71084808, "paddw"],
  // sq $t1, 0x20($a0): SQ opcode 0x1f, base 4, rt 9, offset 0x20
  [0x7c890020, "sq"],
  // jal 0x00100040: J-type opcode 0x03, target 0x00100040 >> 2
  [0x0c040010, "jal"],
  [0x00000000, "nop"],
  // jr $ra: SPECIAL, rs 31, funct 0x08
  [0x03e00008, "jr"],
  [0x00000000, "nop"],
];
const CALLEE_CODE = [
  // addiu $v0, $zero, 0x1234
  [0x24021234, "addiu"],
  [0x03e00008, "jr"],
  [0x00000000, "nop"],
];

/**
 * A deterministic, non-commercial ELF32 shaped like the EE linker's output: one
 * PT_LOAD at 0x00100000, no section headers and no MIPS ABI flags record. The
 * flags argument lets verifiers prove that other declarations are refused.
 */
export function buildPs2Fixture(flags = PS2_ELF_FLAGS) {
  const codeOffset = 0x1000;
  const codeSize = 0x100;
  const bytes = Buffer.alloc(codeOffset + codeSize);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]); // ELF32, little-endian, v1
  bytes.writeUInt16LE(2, 16); // ET_EXEC
  bytes.writeUInt16LE(8, 18); // EM_MIPS
  bytes.writeUInt32LE(1, 20); // EV_CURRENT
  bytes.writeUInt32LE(PS2_ENTRY, 24); // e_entry
  bytes.writeUInt32LE(52, 28); // e_phoff
  bytes.writeUInt32LE(flags, 36); // e_flags
  bytes.writeUInt16LE(52, 40); // e_ehsize
  bytes.writeUInt16LE(32, 42); // e_phentsize
  bytes.writeUInt16LE(1, 44); // e_phnum
  bytes.writeUInt32LE(1, 52); // PT_LOAD
  bytes.writeUInt32LE(codeOffset, 56); // p_offset
  bytes.writeUInt32LE(PS2_ENTRY, 60); // p_vaddr
  bytes.writeUInt32LE(PS2_ENTRY, 64); // p_paddr
  bytes.writeUInt32LE(codeSize, 68); // p_filesz
  bytes.writeUInt32LE(codeSize, 72); // p_memsz
  bytes.writeUInt32LE(5, 76); // PF_R | PF_X
  bytes.writeUInt32LE(0x1000, 80); // p_align
  const write = (address, code) =>
    code.forEach(([word], index) =>
      bytes.writeUInt32LE(word, codeOffset + address - PS2_ENTRY + index * 4),
    );
  write(PS2_ENTRY, ENTRY_CODE);
  write(PS2_CALLEE, CALLEE_CODE);
  assert.equal(bytes.readUInt32LE(36), flags);
  return {
    bytes,
    sha256: sha256(bytes),
    codeOffset,
    codeSize,
    instructions: [
      ...ENTRY_CODE.map(([word, mnemonic], index) => ({
        address: PS2_ENTRY + index * 4,
        word,
        mnemonic,
      })),
      ...CALLEE_CODE.map(([word, mnemonic], index) => ({
        address: PS2_CALLEE + index * 4,
        word,
        mnemonic,
      })),
    ],
  };
}
