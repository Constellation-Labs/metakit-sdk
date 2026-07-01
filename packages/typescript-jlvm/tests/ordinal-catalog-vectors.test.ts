import fs from 'fs';
import path from 'path';
import {
  verifyOrdinalCatalogProof,
  isOrdinalCatalogError,
  catalogKeys,
  type OrdinalCatalogResult,
} from '../src/ordinal-catalog';

interface CatalogVectors {
  version: string;
  epochSize: number;
  catalogRoot: string;
  cases: Array<{ ordinal: number; note?: string; proof: unknown; expected: Record<string, unknown> }>;
}

const vectorsPath = path.join(__dirname, '../../..', 'shared', 'ordinal_catalog_test_vectors.json');
const vectors: CatalogVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));

/** Map a result to the vector's `expected` JSON shape for comparison. */
function toExpected(r: OrdinalCatalogResult): Record<string, unknown> {
  if (!isOrdinalCatalogError(r)) {
    return r.type === 'CommittedAt'
      ? { type: 'CommittedAt', ordinal: Number(r.ordinal), mptRoot: r.mptRoot }
      : { type: 'NotCommitted', ordinal: Number(r.ordinal) };
  }
  return r.error === 'MalformedOrdinalProof'
    ? { error: 'MalformedOrdinalProof' }
    : { error: r.error, component: r.component };
}

describe('Ordinal-catalog attestation cross-language conformance', () => {
  // Ground-truth catalog key derivation (CommitCatalog): lowercaseHex(sha256(utf8(name))).
  it('derives the fixed catalog keys byte-identically to the Scala reference', () => {
    expect(catalogKeys.hotEpochsKey).toBe('bf219127ab671805b4bc75df3598e2db17eef5fab73facc3757e6baa8c416636');
    expect(catalogKeys.sealedEpochsKey).toBe('19ab634f4720ce035b017e7ffb8e8ca5a4481e62309a5beffaf75da167ee1202');
    expect(catalogKeys.ordinalKey(0n)).toBe('c0020bf0613f2c15579e2e827e436cc0b445b6c2e2ee8f08922016e27c3d7be2');
    expect(catalogKeys.ordinalKey(1n)).toBe('2aeb90f46fe17b9672e4fe5b7f13ae003293a0fefe329e49095d77a727c1e19a');
    expect(catalogKeys.epochKey(0n)).toBe('402a33e021e6fd2d8fb109ce145fef5df03a39a4d5e2f4f993fc812f79ca4692');
  });

  describe(`Ordinal Catalog Vectors v${vectors.version} (epochSize=${vectors.epochSize})`, () => {
    for (const c of vectors.cases) {
      const label = `ordinal ${c.ordinal}${c.note ? ` — ${c.note}` : ''}`;
      it(label, () => {
        const result = verifyOrdinalCatalogProof(vectors.catalogRoot, c.proof, vectors.epochSize);
        expect(toExpected(result)).toEqual(c.expected);
      });
    }
  });
});
