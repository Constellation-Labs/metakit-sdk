package io.constellationnetwork.metagraph.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.util.Map;

/**
 * JSON canonicalization using RFC 8785, with server-aligned null dropping.
 *
 * <p>Null-valued object fields are recursively dropped (array nulls are
 * preserved) before canonicalizing, so the bytes produced for
 * signing/verification match what the authoritative Scala server (metakit
 * {@code JsonBinaryCodec.dropNulls}), the TypeScript SDK
 * ({@code dropNullFields}) and the Rust SDK ({@code drop_null_fields})
 * re-derive. See metakit {@code docs/content-hash.md}.
 */
public final class Canonicalize {

    private static final Gson GSON = new GsonBuilder()
        .disableHtmlEscaping()
        .create();

    private Canonicalize() {
        // Utility class
    }

    /**
     * Recursively drop null-valued object fields (server-aligned).
     *
     * <p>Behavior — byte-for-byte matched to metakit's
     * {@code JsonBinaryCodec.dropNulls}, the TypeScript SDK's
     * {@code dropNullFields} and the Rust SDK's {@code drop_null_fields}:
     * <ul>
     *   <li>Object fields whose value is null are removed, recursively.</li>
     *   <li>Array elements are NEVER removed — null elements are positional
     *       and preserved; nested objects inside arrays are still cleaned.</li>
     *   <li>Primitives (including a top-level null) pass through unchanged.</li>
     * </ul>
     *
     * @param element JSON element to clean
     * @return The same JSON value with null object-fields recursively removed
     */
    public static JsonElement dropNullFields(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return element;
        }
        if (element.isJsonObject()) {
            JsonObject cleaned = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                if (entry.getValue().isJsonNull()) {
                    continue;
                }
                cleaned.add(entry.getKey(), dropNullFields(entry.getValue()));
            }
            return cleaned;
        }
        if (element.isJsonArray()) {
            JsonArray cleaned = new JsonArray();
            for (JsonElement item : element.getAsJsonArray()) {
                cleaned.add(dropNullFields(item));
            }
            return cleaned;
        }
        return element;
    }

    /**
     * Canonicalize an object to RFC 8785 JSON string.
     *
     * <p>Null-valued object fields are dropped before canonicalization to
     * match the authoritative Scala server (see {@link #dropNullFields}).
     * This makes the bytes produced for signing/verification here agree with
     * what the chain re-derives.
     *
     * @param data Object to canonicalize
     * @return Canonical JSON string
     * @throws Types.SdkException if canonicalization fails
     */
    public static String canonicalize(Object data) {
        return canonicalizeJson(GSON.toJson(data));
    }

    /**
     * Canonicalize a JSON string to RFC 8785 format.
     *
     * <p>Null-valued object fields are dropped before canonicalization
     * (see {@link #dropNullFields}).
     *
     * @param json JSON string to canonicalize
     * @return Canonical JSON string
     * @throws Types.SdkException if canonicalization fails
     */
    public static String canonicalizeJson(String json) {
        try {
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(dropNullsFromJson(json));
            return canonicalizer.getEncodedString();
        } catch (IOException e) {
            throw new Types.SdkException("Failed to canonicalize JSON", e);
        }
    }

    /**
     * Canonicalize an object and return as UTF-8 bytes.
     *
     * <p>Null-valued object fields are dropped before canonicalization
     * (see {@link #dropNullFields}).
     *
     * @param data Object to canonicalize
     * @return Canonical JSON as UTF-8 bytes
     */
    public static byte[] canonicalizeToBytes(Object data) {
        try {
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(dropNullsFromJson(GSON.toJson(data)));
            return canonicalizer.getEncodedUTF8();
        } catch (IOException e) {
            throw new Types.SdkException("Failed to canonicalize JSON", e);
        }
    }

    /**
     * Parse a JSON string, drop null object-fields, and re-serialize.
     *
     * <p>Gson keeps number literals lazily parsed, so this round trip does not
     * degrade number precision before the RFC 8785 canonicalizer runs.
     */
    private static String dropNullsFromJson(String json) {
        return GSON.toJson(dropNullFields(JsonParser.parseString(json)));
    }
}
