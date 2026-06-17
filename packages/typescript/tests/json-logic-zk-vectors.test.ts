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
