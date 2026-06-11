package io.constellationnetwork.metagraph.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CanonicalizeTest {

    @Nested
    @DisplayName("dropNullFields")
    class DropNullFields {

        private JsonElement parse(String json) {
            return JsonParser.parseString(json);
        }

        @Test
        @DisplayName("drops null object-fields recursively")
        void dropsNullsRecursively() {
            JsonElement cleaned = Canonicalize.dropNullFields(
                parse("{\"a\":1,\"b\":null,\"c\":{\"d\":null,\"e\":2}}"));
            assertEquals(parse("{\"a\":1,\"c\":{\"e\":2}}"), cleaned);
        }

        @Test
        @DisplayName("preserves null array elements")
        void preservesArrayNulls() {
            JsonElement cleaned = Canonicalize.dropNullFields(parse("{\"xs\":[1,null,3]}"));
            assertEquals(parse("{\"xs\":[1,null,3]}"), cleaned);
        }

        @Test
        @DisplayName("cleans objects inside arrays")
        void cleansObjectsInsideArrays() {
            JsonElement cleaned = Canonicalize.dropNullFields(parse("[{\"a\":null,\"b\":1},null]"));
            assertEquals(parse("[{\"b\":1},null]"), cleaned);
        }

        @Test
        @DisplayName("primitives and top-level null pass through")
        void primitivesPassThrough() {
            assertEquals(parse("null"), Canonicalize.dropNullFields(parse("null")));
            assertEquals(parse("42"), Canonicalize.dropNullFields(parse("42")));
            assertEquals(parse("\"x\""), Canonicalize.dropNullFields(parse("\"x\"")));
        }
    }

    @Nested
    @DisplayName("canonicalize")
    class CanonicalizeBehavior {

        @Test
        @DisplayName("drops null object-fields (server-aligned)")
        void dropsNullObjectFields() {
            assertEquals("{\"b\":1}", Canonicalize.canonicalizeJson("{\"a\":null,\"b\":1}"));
        }

        @Test
        @DisplayName("preserves null array elements")
        void preservesNullArrayElements() {
            assertEquals("{\"xs\":[1,null,3]}", Canonicalize.canonicalizeJson("{\"xs\":[1,null,3]}"));
        }

        @Test
        @DisplayName("sorts object keys")
        void sortsObjectKeys() {
            assertEquals("{\"a\":1,\"b\":2}", Canonicalize.canonicalizeJson("{\"b\":2,\"a\":1}"));
        }
    }

    /**
     * Pins the normative content-hash rule (metakit docs/content-hash.md):
     * drop null OBJECT fields recursively, PRESERVE array nulls, then RFC 8785.
     */
    @Nested
    @DisplayName("content-hash rule")
    class ContentHashRule {

        @Test
        @DisplayName("explicit-null fields produce identical signing bytes to absent fields")
        void absentEqualsExplicitNullForSigningBytes() {
            JsonElement withNull = JsonParser.parseString(
                "{\"a\":1,\"b\":null,\"c\":{\"d\":null,\"e\":2},\"f\":[1,null,3]}");
            JsonElement absent = JsonParser.parseString(
                "{\"a\":1,\"c\":{\"e\":2},\"f\":[1,null,3]}");
            assertArrayEquals(Binary.toBytes(withNull, true), Binary.toBytes(absent, true));
            assertEquals(Hash.hash(withNull).getValue(), Hash.hash(absent).getValue());
        }

        @Test
        @DisplayName("array nulls are positional and change the hash")
        void arrayNullsChangeTheHash() {
            JsonElement a = JsonParser.parseString("{\"xs\":[1,null,3]}");
            JsonElement b = JsonParser.parseString("{\"xs\":[1,3]}");
            assertNotEquals(Hash.hash(a).getValue(), Hash.hash(b).getValue());
        }

        @Test
        @DisplayName("matches the Scala arrays.json fixture hash (metakit JsonBinaryHasherSuite)")
        void matchesScalaArraysFixtureHash() {
            // metakit src/test/resources/input/arrays.json
            JsonElement data = JsonParser.parseString("[56,{\"d\":true,\"10\":null,\"1\":[]}]");

            // null "10" dropped, keys sorted — identical to metakit's canonical form
            assertEquals("[56,{\"1\":[],\"d\":true}]", Canonicalize.canonicalize(data));

            // sha256 over the canonical bytes — pinned in metakit JsonBinaryHasherSuite:
            // "arrays.json should produce a known hash"
            assertEquals(
                "060ba9d4be65e7b773f67328b6fd6a5360f8f66ef88d57351dbc6e39b46f2ea9",
                Hash.hash(data).getValue());
        }
    }
}
