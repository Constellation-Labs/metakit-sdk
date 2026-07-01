import {
  CommitKey,
  CommitKeyError,
  committedRootsCombinedHash,
  encodeCommittedRoots,
  decodeCommittedRoots,
  encodeCommittedBreadcrumb,
  decodeCommittedBreadcrumb,
  type CommittedRoots,
  type CommittedBreadcrumb,
} from '../src/committed-roots';

// Byte-for-byte KATs mirroring the metakit (Scala) `CommittedRootsCodecKatSuite`.
// mptRoot = Hash("aa" * 32), catalogRoot = SparseMerkleRoot(Hash("bb" * 32)).
const MPT_ROOT = 'aa'.repeat(32);
const CATALOG_ROOT = 'bb'.repeat(32);
const roots: CommittedRoots = { mptRoot: MPT_ROOT, catalogRoot: { value: CATALOG_ROOT } };

describe('committed-roots codecs (Scala parity)', () => {
  describe('CommitKey', () => {
    it('encodes as a bare validated string and round-trips', () => {
      const k = CommitKey.from('fiber/abc-1');
      expect(JSON.stringify(k.value)).toBe('"fiber/abc-1"');
      expect(k.value).toBe('fiber/abc-1');
    });

    it('derives the MPT path as lowercase hex of the UTF-8 bytes', () => {
      // hex("fiber/abc-1") — '/' is 0x2f
      expect(CommitKey.from('fiber/abc-1').toHex()).toBe('66696265722f6162632d31');
      expect(CommitKey.from('fiber').namespace).toBe('fiber');
    });

    it('rejects malformed keys with the right error code', () => {
      expect(() => CommitKey.from('')).toThrow(CommitKeyError);
      expect(() => CommitKey.from('/fiber')).toThrow(/empty segment/i);
      expect(() => CommitKey.from('fiber/')).toThrow(/empty segment/i);
      expect(() => CommitKey.from('fiber//abc')).toThrow(/empty segment/i);
      expect(() => CommitKey.from('Fiber')).toThrow(/must match/i); // uppercase rejected
      expect(() => CommitKey.from('a'.repeat(65))).toThrow(/segment exceeds/i);
      expect(() => CommitKey.from(Array(17).fill('a').join('/'))).toThrow(/segments/i);
      expect(CommitKey.isValid('fiber/abc-1')).toBe(true);
      expect(CommitKey.isValid('Fiber')).toBe(false);
    });
  });

  describe('CommittedRoots', () => {
    it('wire keys = [mptRoot, catalogRoot] and round-trips', () => {
      const json = encodeCommittedRoots(roots);
      expect(Object.keys(JSON.parse(json))).toEqual(['mptRoot', 'catalogRoot']);
      expect(json).toBe(`{"mptRoot":"${MPT_ROOT}","catalogRoot":{"value":"${CATALOG_ROOT}"}}`);
      expect(decodeCommittedRoots(json)).toEqual(roots);
    });

    it('combinedHash = sha256(rawBytes(mptRoot) ++ rawBytes(catalogRoot))', () => {
      // Known-answer: sha256(0xaa*32 ++ 0xbb*32)
      expect(committedRootsCombinedHash(roots)).toBe(
        'e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6'
      );
    });
  });

  describe('CommittedBreadcrumb', () => {
    it('wire keys = [ordinal, roots], ordinal is a bare integer, round-trips', () => {
      const b: CommittedBreadcrumb = { ordinal: 0, roots };
      const json = encodeCommittedBreadcrumb(b);
      expect(Object.keys(JSON.parse(json))).toEqual(['ordinal', 'roots']);
      expect(json).toBe(
        `{"ordinal":0,"roots":{"mptRoot":"${MPT_ROOT}","catalogRoot":{"value":"${CATALOG_ROOT}"}}}`
      );
      expect(decodeCommittedBreadcrumb(json)).toEqual(b);
    });

    it('rejects a negative or non-integer ordinal', () => {
      expect(() => decodeCommittedBreadcrumb({ ordinal: -1, roots })).toThrow(/non-negative/i);
      expect(() => decodeCommittedBreadcrumb({ ordinal: 1.5, roots })).toThrow(/non-negative/i);
    });
  });
});
