/**
 * Gas-metering cross-language conformance.
 *
 * Loads `shared/gas_test_vectors.json` (the cross-language gas oracle; every
 * `expected` value was PRODUCED BY RUNNING the Scala reference meter) and runs
 * each case through `evaluateWithGas` under the declared `gasLimit`, asserting
 * EXACT equivalence — the same contract as Rust `tests/gas_differential.rs`:
 *
 *   - integer `expected`: evaluation must succeed and report exactly that
 *     `gasUsed` (the gas-counter delta);
 *   - `"OOG"` `expected`: evaluation must fail with the DISTINCT
 *     `GasExhaustedError` (an ordinary evaluation error is a conformance bug).
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseExpression, parseValue } from '../src/json-logic/codec';
import { evaluateWithGas, GasExhaustedError } from '../src/json-logic/gas-eval';

interface GasCase {
  expr: string;
  data: string;
  gasLimit: number;
  expected: number | 'OOG';
  note?: string;
}

interface GasCategory {
  category: string;
  note?: string;
  cases: GasCase[];
}

interface GasVectors {
  description: string;
  version: string;
  tests: GasCategory[];
}

const vectorsPath = path.join(__dirname, '../../..', 'shared', 'gas_test_vectors.json');
const vectors: GasVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));

describe('Gas metering cross-language conformance', () => {
  describe(`Gas Test Vectors v${vectors.version}`, () => {
    for (const category of vectors.tests) {
      describe(category.category, () => {
        for (const c of category.cases) {
          const testName = c.note ? `${c.expr} (${c.note})` : c.expr;

          it(testName, () => {
            const expr = parseExpression(JSON.parse(c.expr));
            const data = parseValue(JSON.parse(c.data));
            const outcome = evaluateWithGas(expr, data, c.gasLimit);

            if (c.expected === 'OOG') {
              expect(outcome.ok).toBe(false);
              if (!outcome.ok) {
                expect(outcome.error).toBeInstanceOf(GasExhaustedError);
              }
            } else {
              if (!outcome.ok) {
                throw new Error(
                  `expected gasUsed=${c.expected}, got error: ${outcome.error.message}`
                );
              }
              expect(outcome.value.gasUsed).toBe(BigInt(c.expected));
            }
          });
        }
      });
    }
  });
});
