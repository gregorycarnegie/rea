export declare const PS2_ELF_FLAGS: number;
export declare const PS2_ENTRY: number;
export declare const PS2_CALLEE: number;

export interface Ps2FixtureInstruction {
  readonly address: number;
  readonly word: number;
  readonly mnemonic: string;
}

export declare function buildPs2Fixture(flags?: number): {
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly codeOffset: number;
  readonly codeSize: number;
  readonly instructions: readonly Ps2FixtureInstruction[];
};
