/**
 * JSON Logic Cross-Language Test Vectors
 *
 * These tests validate TypeScript implementation against shared test vectors
 * that are also run by the Scala metakit implementation and the Rust
 * jlvm-core differential harness.
 *
 * Case convention (shared with the Scala `SharedVectorConformanceSuite` and
 * Rust `tests/differential.rs`):
 *   - ordinary cases define `expected` (JSON text) and must evaluate to it;
 *   - `"error": true` cases pin that evaluation MUST fail — a parse/decode
 *     failure also satisfies "evaluation MUST fail".
 */

import * as fs from 'fs';
import * as path from 'path';
import { jsonLogic } from '../src';

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

// Load test vectors
const vectorsPath = path.join(__dirname, '../../..', 'shared', 'json_logic_test_vectors.json');
const vectors: TestVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));

/**
 * Replace bigints (which `encodeValue` emits for integers beyond 2^53 to keep
 * them exact) with JS numbers so `toEqual` against the JSON-parsed `expected`
 * compares numbers BY VALUE — the same leniency as Rust's `json_struct_eq`
 * (numbers compared as f64) and the Scala suite's structEq.
 */
const normalizeBigints = (v: unknown): unknown => {
  if (typeof v === 'bigint') {
    return Number(v);
  }
  if (Array.isArray(v)) {
    return v.map(normalizeBigints);
  }
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, normalizeBigints(x)]));
  }
  return v;
};

describe('JSON Logic Cross-Language Compatibility', () => {
  describe(`Test Vectors v${vectors.version}`, () => {
    for (const category of vectors.tests) {
      describe(category.category, () => {
        for (const testCase of category.cases) {
          const testName = testCase.note ? `${testCase.expr} (${testCase.note})` : testCase.expr;

          if (testCase.error === true) {
            it(`${testName} [must error]`, () => {
              expect(() => {
                const expr = JSON.parse(testCase.expr);
                const data = JSON.parse(testCase.data);
                jsonLogic.apply(expr, data);
              }).toThrow();
            });
            continue;
          }

          it(testName, () => {
            const expr = JSON.parse(testCase.expr);
            const data = JSON.parse(testCase.data);
            if (testCase.expected === undefined) {
              throw new Error('non-error case must define `expected`');
            }
            const expected = JSON.parse(testCase.expected);

            const result = jsonLogic.apply(expr, data);

            // Deep equality check (numbers by value, like the Rust harness)
            expect(normalizeBigints(result)).toEqual(expected);
          });
        }
      });
    }
  });
});
