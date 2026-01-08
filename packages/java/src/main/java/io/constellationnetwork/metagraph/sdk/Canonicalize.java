package io.constellationnetwork.metagraph.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;

/**
 * JSON canonicalization using RFC 8785.
 */
public final class Canonicalize {

    private static final Gson GSON = new GsonBuilder()
        .disableHtmlEscaping()
        .create();

    private Canonicalize() {
        // Utility class
    }

    /**
     * Canonicalize an object to RFC 8785 JSON string.
     *
     * @param data Object to canonicalize
     * @return Canonical JSON string
     * @throws Types.SdkException if canonicalization fails
     */
    public static String canonicalize(Object data) {
        try {
            String json = GSON.toJson(data);
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
            return canonicalizer.getEncodedString();
        } catch (IOException e) {
            throw new Types.SdkException("Failed to canonicalize JSON", e);
        }
    }

    /**
     * Canonicalize a JSON string to RFC 8785 format.
     *
     * @param json JSON string to canonicalize
     * @return Canonical JSON string
     * @throws Types.SdkException if canonicalization fails
     */
    public static String canonicalizeJson(String json) {
        try {
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
            return canonicalizer.getEncodedString();
        } catch (IOException e) {
            throw new Types.SdkException("Failed to canonicalize JSON", e);
        }
    }

    /**
     * Canonicalize an object and return as UTF-8 bytes.
     *
     * @param data Object to canonicalize
     * @return Canonical JSON as UTF-8 bytes
     */
    public static byte[] canonicalizeToBytes(Object data) {
        try {
            String json = GSON.toJson(data);
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
            return canonicalizer.getEncodedUTF8();
        } catch (IOException e) {
            throw new Types.SdkException("Failed to canonicalize JSON", e);
        }
    }
}
