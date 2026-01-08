package io.constellationnetwork.metagraph.sdk;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Binary encoding utilities for the Constellation signature protocol.
 */
public final class Binary {

    private Binary() {
        // Utility class
    }

    /**
     * Convert data to binary bytes for signing.
     *
     * <p>For regular data: JSON -> RFC 8785 canonicalization -> UTF-8 bytes
     * <p>For DataUpdate: JSON -> RFC 8785 -> UTF-8 -> Base64 -> prepend Constellation prefix -> UTF-8 bytes
     *
     * @param data Object to encode
     * @param isDataUpdate If true, applies DataUpdate encoding with Constellation prefix
     * @return Binary bytes
     */
    public static byte[] toBytes(Object data, boolean isDataUpdate) {
        String canonicalJson = Canonicalize.canonicalize(data);
        byte[] utf8Bytes = canonicalJson.getBytes(StandardCharsets.UTF_8);

        if (isDataUpdate) {
            String base64String = Base64.getEncoder().encodeToString(utf8Bytes);
            String wrappedString = Types.CONSTELLATION_PREFIX + base64String.length() + "\n" + base64String;
            return wrappedString.getBytes(StandardCharsets.UTF_8);
        }

        return utf8Bytes;
    }

    /**
     * Encode data as a DataUpdate with Constellation prefix.
     *
     * @param data Object to encode
     * @return Binary bytes with Constellation prefix
     */
    public static byte[] encodeDataUpdate(Object data) {
        return toBytes(data, true);
    }

    /**
     * Decode a DataUpdate back to original JSON bytes.
     *
     * @param bytes DataUpdate encoded bytes
     * @return Original JSON bytes
     * @throws Types.SdkException if the format is invalid
     */
    public static byte[] decodeDataUpdate(byte[] bytes) {
        String content = new String(bytes, StandardCharsets.UTF_8);

        if (!content.startsWith(Types.CONSTELLATION_PREFIX)) {
            throw new Types.SdkException("Invalid DataUpdate format: missing Constellation prefix");
        }

        String rest = content.substring(Types.CONSTELLATION_PREFIX.length());
        int newlineIndex = rest.indexOf('\n');
        if (newlineIndex == -1) {
            throw new Types.SdkException("Invalid DataUpdate format: missing length separator");
        }

        String base64Content = rest.substring(newlineIndex + 1);
        return Base64.getDecoder().decode(base64Content);
    }
}
