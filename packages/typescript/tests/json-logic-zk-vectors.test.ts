/**
 * ZK opcode cross-language conformance for the opcodes the TypeScript
 * evaluator implements: `poseidon`, `pmt_verify`, `schnorr_verify`,
 * `bls_verify`, `bls_aggregate_verify`.
 *
 * Runs the matching categories of `shared/zk_opcode_test_vectors.json` (the
 * cross-language oracle also enforced by Scala `ZkVectorConformanceSuite` and
 * Rust `tests/zk_differential.rs`). Categories for opcodes that are not yet
 * ported to TypeScript (smt/mpt/bn254/ecvrf/groth16 and the mixed
 * `known_answer` programs) are skipped explicitly.
 *
 * Case convention: ordinary cases define `expected`; `"error": true` cases
 * pin that evaluation MUST fail.
 */

import * as fs from 'fs';
import * as path from 'path';
import { jsonLogic } from '../src/json-logic';

interface TestCase {
  expr: string;
  data: string;
  expected?: string;
  error?: boolean;
  note?: string;
}

interface TestCategory {
  category: string;
  note?: string;
  cases: TestCase[];
}

interface TestVectors {
  description: string;
  version: string;
  tests: TestCategory[];
}

const IMPLEMENTED = new Set([
  'poseidon',
  'pmt_verify',
  'schnorr_verify',
  'bls_verify',
  'bls_aggregate_verify',
  'sigma_dlog',
  'sigma_dhtuple',
  'sigma',
  'bn254_add',
  'bn254_mul',
  'bn254_pairing',
  'groth16_verify',
]);

const vectorsPath = path.join(__dirname, '../../..', 'shared', 'zk_opcode_test_vectors.json');
const vectors: TestVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));

describe('ZK opcode cross-language conformance (implemented subset)', () => {
  describe(`ZK Opcode Test Vectors v${vectors.version}`, () => {
    for (const category of vectors.tests) {
      if (!IMPLEMENTED.has(category.category)) {
        continue;
      }
      describe(category.category, () => {
        for (const testCase of category.cases) {
          const testName = testCase.note ? `${testCase.expr} (${testCase.note})` : testCase.expr;

          if (testCase.error === true) {
            it(`${testName} [must error]`, () => {
              expect(() => {
                jsonLogic.apply(JSON.parse(testCase.expr), JSON.parse(testCase.data));
              }).toThrow();
            });
            continue;
          }

          it(testName, () => {
            if (testCase.expected === undefined) {
              throw new Error('non-error case must define `expected`');
            }
            const result = jsonLogic.apply(JSON.parse(testCase.expr), JSON.parse(testCase.data));
            expect(result).toEqual(JSON.parse(testCase.expected));
          });
        }
      });
    }
  });
});

/**
 * IMPL-6 (audit 2026-06-17): pin the sigma category case counts and required edge
 * cases so a future vector-file regression cannot silently reduce cross-language
 * coverage (the Rust `zk_differential` harness pins the total; this is the TS twin).
 */
describe('sigma category coverage floors', () => {
  const byCat = (name: string): TestCategory => {
    const c = vectors.tests.find((t) => t.category === name);
    if (!c) {
      throw new Error(`missing sigma category: ${name}`);
    }
    return c;
  };

  it('pins the sigma category case counts', () => {
    expect(byCat('sigma_dlog').cases.length).toBe(9);
    expect(byCat('sigma_dhtuple').cases.length).toBe(11);
    expect(byCat('sigma').cases.length).toBe(27);
  });

  it('keeps the required sigma soundness + hardening edge cases', () => {
    const notes = byCat('sigma').cases.map((c) => c.note ?? '');
    const has = (frag: string): boolean => notes.some((n) => n.includes(frag));
    const required = [
      'simulating ALL branches', // OR: forge-by-simulate-all -> false
      'breaks XOR relation', // OR: XOR-break -> false
      'k-1 real witness', // THRESHOLD: too-few-witness -> false
      'wrong message', // strong-FS message binding -> false
      'tampered response', // tampered z -> false
      'non-canonical leaf response', // canonical z (finding #4) -> error
      'off-curve statement point', // off-curve -> error
      'huge mismatched proof', // DoS structural bound (finding #2) -> error
      'wrong-width challenge', // 31-byte challenge domain (rejects 32B) -> error
      'unknown field on a proposition leaf', // IMPL-2/5
      'unknown field on a proof node', // IMPL-2/5
      "bogus 'children'", // IMPL-2 proof-bound inflation
      'message over the length cap', // IMPL-3 DoS bound
    ];
    for (const frag of required) {
      expect(has(frag)).toBe(true);
    }
  });

  it('keeps the sigma error-case floor', () => {
    const errs = byCat('sigma').cases.filter((c) => c.error === true).length;
    expect(errs).toBeGreaterThanOrEqual(13);
  });
});
