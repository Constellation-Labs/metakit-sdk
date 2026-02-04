/**
 * JSON Logic Cross-Language Test Vectors
 *
 * These tests validate TypeScript implementation against shared test vectors
 * that are also run by the Scala metakit implementation.
 */

import * as fs from 'fs';
import * as path from 'path';
import { jsonLogic } from '../src/json-logic';

interface TestCase {
  expr: string;
  data: string;
  expected: string;
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

describe('JSON Logic Cross-Language Compatibility', () => {
  describe(`Test Vectors v${vectors.version}`, () => {
    for (const category of vectors.tests) {
      describe(category.category, () => {
        for (const testCase of category.cases) {
          const testName = testCase.note
            ? `${testCase.expr} (${testCase.note})`
            : testCase.expr;

          it(testName, () => {
            const expr = JSON.parse(testCase.expr);
            const data = JSON.parse(testCase.data);
            const expected = JSON.parse(testCase.expected);

            const result = jsonLogic.apply(expr, data);

            // Deep equality check
            expect(result).toEqual(expected);
          });
        }
      });
    }
  });
});
