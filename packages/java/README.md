# Constellation Metagraph SDK - Java

Java SDK for signing data transactions on Constellation Network data metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Note:** This SDK is for data transactions only. It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Requirements

- Java 11 or higher
- Maven 3.8+

## Installation

### Maven

```xml
<dependency>
    <groupId>io.constellationnetwork</groupId>
    <artifactId>metagraph-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.constellationnetwork:metagraph-sdk:0.1.0'
```

## Quick Start

```java
import io.constellationnetwork.metagraph.sdk.*;
import java.util.Map;

public class Example {
    public static void main(String[] args) {
        // Generate a key pair
        Types.KeyPair keyPair = Wallet.generateKeyPair();
        System.out.println("Address: " + keyPair.getAddress());

        // Sign data
        Map<String, Object> data = Map.of(
            "action", "UPDATE",
            "payload", Map.of("key", "value")
        );
        Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
            data, keyPair.getPrivateKey(), false
        );

        // Verify
        Types.VerificationResult result = SignedObject.verify(signed, false);
        System.out.println("Valid: " + result.isValid());
    }
}
```

## API Reference

### High-Level API

#### `SignedObject.createSignedObject(value, privateKey, isDataUpdate)`

Create a signed object with a single signature.

```java
Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
    data, privateKey, false
);

// For L1 submission (DataUpdate)
Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
    data, privateKey, true
);
```

#### `SignedObject.addSignature(signed, privateKey, isDataUpdate)`

Add an additional signature to an existing signed object.

```java
var signed = SignedObject.createSignedObject(data, party1Key, false);
signed = SignedObject.addSignature(signed, party2Key, false);
// signed.getProofs().size() == 2
```

#### `SignedObject.batchSign(value, privateKeys, isDataUpdate)`

Create a signed object with multiple signatures at once.

```java
var signed = SignedObject.batchSign(
    data,
    Arrays.asList(key1, key2, key3),
    false
);
// signed.getProofs().size() == 3
```

#### `SignedObject.verify(signed, isDataUpdate)` / `Verify.verify(signed, isDataUpdate)`

Verify all signatures on a signed object.

```java
Types.VerificationResult result = SignedObject.verify(signed, false);
if (result.isValid()) {
    System.out.println("All signatures valid");
} else {
    System.out.println("Invalid proofs: " + result.getInvalidProofs());
}
```

### Low-Level Primitives

#### `Canonicalize.canonicalize(data)`

Canonicalize JSON data according to RFC 8785.

```java
Map<String, Integer> data = Map.of("b", 2, "a", 1);
String canonical = Canonicalize.canonicalize(data);
// "{\"a\":1,\"b\":2}"
```

#### `Binary.toBytes(data, isDataUpdate)`

Convert data to binary bytes for signing.

```java
// Regular encoding
byte[] bytes = Binary.toBytes(data, false);

// DataUpdate encoding (with Constellation prefix)
byte[] bytes = Binary.toBytes(data, true);
```

#### `Hash.hash(data)` / `Hash.hashBytes(bytes)`

Compute SHA-256 hash.

```java
Types.Hash hash = Hash.hash(data);
System.out.println(hash.getValue());  // 64-char hex
System.out.println(hash.getBytes()); // byte[32]
```

#### `Sign.sign(data, privateKey)` / `Sign.signDataUpdate(data, privateKey)`

Sign data and return a proof.

```java
Types.SignatureProof proof = Sign.sign(data, privateKey);
// SignatureProof{id: "...", signature: "..."}
```

#### `Sign.signHash(hashHex, privateKey)`

Sign a pre-computed hash.

```java
Types.Hash hash = Hash.hash(data);
String signature = Sign.signHash(hash.getValue(), privateKey);
```

### Wallet Utilities

#### `Wallet.generateKeyPair()`

Generate a new random key pair.

```java
Types.KeyPair keyPair = Wallet.generateKeyPair();
// KeyPair{privateKey, publicKey, address}
```

#### `Wallet.keyPairFromPrivateKey(privateKey)`

Derive a key pair from an existing private key.

```java
Types.KeyPair keyPair = Wallet.keyPairFromPrivateKey(existingPrivateKey);
```

#### `Wallet.getPublicKeyId(privateKey)`

Get the public key ID (128 chars, no 04 prefix) for use in proofs.

```java
String id = Wallet.getPublicKeyId(privateKey);
```

## Types

```java
// All types are in io.constellationnetwork.metagraph.sdk.Types

public class SignatureProof {
    String getId();        // Public key (128 chars)
    String getSignature(); // DER signature hex
}

public class Signed<T> {
    T getValue();
    List<SignatureProof> getProofs();
}

public class KeyPair {
    String getPrivateKey();
    String getPublicKey();
    String getAddress();
}

public class Hash {
    String getValue();  // 64-char hex
    byte[] getBytes();  // 32 bytes
}

public class VerificationResult {
    boolean isValid();
    List<SignatureProof> getValidProofs();
    List<SignatureProof> getInvalidProofs();
}

// Exception type
public class SdkException extends RuntimeException { }
```

## Usage Examples

### Submit DataUpdate to L1

```java
import io.constellationnetwork.metagraph.sdk.*;
import com.google.gson.Gson;
import java.net.http.*;
import java.util.Map;

public class DataUpdateExample {
    public static void main(String[] args) throws Exception {
        Map<String, Object> dataUpdate = Map.of(
            "action", "TRANSFER",
            "from", "address1",
            "to", "address2",
            "amount", 100
        );

        // Sign as DataUpdate
        var signed = SignedObject.createSignedObject(dataUpdate, privateKey, true);

        // Submit to data-l1
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("http://l1-node:9300/data"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(new Gson().toJson(signed)))
            .build();

        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());
    }
}
```

### Multi-Signature Workflow

```java
import io.constellationnetwork.metagraph.sdk.*;
import java.util.Map;

public class MultiSigExample {
    public static void main(String[] args) {
        Map<String, Object> data = Map.of("action", "multisig-test");

        // Party 1 creates and signs
        var signed = SignedObject.createSignedObject(data, party1Key, false);

        // Party 2 adds signature
        signed = SignedObject.addSignature(signed, party2Key, false);

        // Party 3 adds signature
        signed = SignedObject.addSignature(signed, party3Key, false);

        // Verify all signatures
        var result = SignedObject.verify(signed, false);
        System.out.printf("%d valid signatures%n", result.getValidProofs().size());
    }
}
```

## Development

```bash
# Run tests
mvn test

# Run specific test class
mvn test -Dtest=IntegrationTest

# Build without tests
mvn package -DskipTests

# Clean build
mvn clean package

# Check for dependency updates
mvn versions:display-dependency-updates
```

## Dependencies

- **Bouncy Castle** (1.78.1) - ECDSA secp256k1 cryptography
- **Gson** (2.10.1) - JSON serialization
- **java-json-canonicalization** (1.1) - RFC 8785 canonicalization
- **JUnit 5** (5.10.2) - Testing (dev dependency)

## License

Apache-2.0
