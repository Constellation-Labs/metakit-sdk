# Constellation Metagraph SDK - Java

Java SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

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

### Data Transactions

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

### Currency Transactions

```java
import io.constellationnetwork.metagraph.sdk.*;

public class CurrencyExample {
    public static void main(String[] args) {
        // Generate keys
        Types.KeyPair sender = Wallet.generateKeyPair();
        Types.KeyPair recipient = Wallet.generateKeyPair();

        // Create token transaction
        CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
            new CurrencyTypes.TransferParams(recipient.getAddress(), 100.5, 0),
            sender.getPrivateKey(),
            new CurrencyTypes.TransactionReference("abc123...", 0)
        );

        // Verify
        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
        System.out.println("Valid: " + result.isValid());
    }
}
```

## API Reference

### Data Transactions

#### High-Level API

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

### Currency Transactions

#### `CurrencyTransaction.createCurrencyTransaction(params, privateKey, lastRef)`

Create a metagraph token transaction.

```java
CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
    new CurrencyTypes.TransferParams("DAG...recipient", 100.5, 0),
    privateKey,
    new CurrencyTypes.TransactionReference("abc123...", 5)
);
```

#### `CurrencyTransaction.createCurrencyTransactionBatch(transfers, privateKey, lastRef)`

Create multiple token transactions in a batch.

```java
List<CurrencyTypes.TransferParams> transfers = Arrays.asList(
    new CurrencyTypes.TransferParams("DAG...1", 10, 0),
    new CurrencyTypes.TransferParams("DAG...2", 20, 0),
    new CurrencyTypes.TransferParams("DAG...3", 30, 0)
);

List<CurrencyTypes.CurrencyTransaction> txns = CurrencyTransaction.createCurrencyTransactionBatch(
    transfers,
    privateKey,
    new CurrencyTypes.TransactionReference("abc123...", 5)
);
```

#### `CurrencyTransaction.signCurrencyTransaction(transaction, privateKey)`

Add an additional signature to a currency transaction (for multi-sig).

```java
CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(params, key1, lastRef);
tx = CurrencyTransaction.signCurrencyTransaction(tx, key2);
// tx.getProofs().size() == 2
```

#### `CurrencyTransaction.verifyCurrencyTransaction(transaction)`

Verify all signatures on a currency transaction.

```java
Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
System.out.println("Valid: " + result.isValid());
```

#### `CurrencyTransaction.hashCurrencyTransaction(transaction)`

Hash a currency transaction.

```java
Types.Hash hash = CurrencyTransaction.hashCurrencyTransaction(tx);
System.out.println("Hash: " + hash.getValue());
```

#### `CurrencyTransaction.getTransactionReference(transaction, ordinal)`

Get a transaction reference for chaining transactions.

```java
CurrencyTypes.TransactionReference ref = CurrencyTransaction.getTransactionReference(tx, 6);
// Use ref as lastRef for next transaction
```

#### Utility Functions

```java
// Validate DAG address
CurrencyTransaction.isValidDagAddress("DAG...");  // true/false

// Convert between token units and smallest units
CurrencyTransaction.tokenToUnits(100.5);    // 10050000000L
CurrencyTransaction.unitsToToken(10050000000L);  // 100.5

// Token decimals constant
CurrencyTypes.TOKEN_DECIMALS;  // 1e-8
```

### Network Operations

#### `CurrencyL1Client`

Client for interacting with Currency L1 nodes.

```java
import io.constellationnetwork.metagraph.sdk.*;

NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
    .l1Url("http://localhost:9010")
    .timeout(30)  // optional, defaults to 30s
    .build();

CurrencyL1Client client = new CurrencyL1Client(config);

// Get last transaction reference for an address
CurrencyTypes.TransactionReference lastRef = client.getLastReference("DAG...");

// Submit a signed transaction
NetworkTypes.PostTransactionResponse result = client.postTransaction(signedTx);
System.out.println("Transaction hash: " + result.getHash());

// Check pending transaction status
NetworkTypes.PendingTransaction pending = client.getPendingTransaction(result.getHash());
if (pending != null) {
    System.out.println("Status: " + pending.getStatus());  // Waiting, InProgress, Accepted
}

// Check node health
boolean isHealthy = client.checkHealth();
```

#### `DataL1Client`

Client for interacting with Data L1 nodes (metagraphs).

```java
import io.constellationnetwork.metagraph.sdk.*;

NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
    .dataL1Url("http://localhost:8080")
    .build();

DataL1Client client = new DataL1Client(config);

// Estimate fee for data submission
NetworkTypes.EstimateFeeResponse feeInfo = client.estimateFee(signedData);
System.out.println("Fee: " + feeInfo.getFee() + ", Address: " + feeInfo.getAddress());

// Submit signed data
NetworkTypes.PostDataResponse result = client.postData(signedData);
System.out.println("Data hash: " + result.getHash());

// Check node health
boolean isHealthy = client.checkHealth();
```

#### Combined Configuration

```java
NetworkTypes.NetworkConfig config = new NetworkTypes.NetworkConfig.Builder()
    .l1Url("http://localhost:9010")      // Currency L1
    .dataL1Url("http://localhost:8080")  // Data L1
    .timeout(30)
    .build();

CurrencyL1Client l1Client = new CurrencyL1Client(config);
DataL1Client dataClient = new DataL1Client(config);
```

#### Network Types

```java
// NetworkTypes.NetworkConfig - Builder pattern
NetworkConfig.Builder()
    .l1Url(String)        // Currency L1 endpoint
    .dataL1Url(String)    // Data L1 endpoint
    .timeout(int)         // Request timeout in seconds
    .build()

// NetworkTypes.PostTransactionResponse
String getHash()

// NetworkTypes.PendingTransaction
String getHash()
TransactionStatus getStatus()  // Waiting, InProgress, Accepted
CurrencyTransaction getTransaction()

// NetworkTypes.EstimateFeeResponse
long getFee()
String getAddress()

// NetworkTypes.PostDataResponse
String getHash()

// NetworkTypes.NetworkException extends RuntimeException
int getStatusCode()
String getResponse()
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

// Currency transaction types (io.constellationnetwork.metagraph.sdk.CurrencyTypes)

public class TransactionReference {
    String getHash();      // 64-char hex transaction hash
    long getOrdinal();     // Transaction ordinal number
}

public class CurrencyTransactionValue {
    String getSource();           // Source DAG address
    String getDestination();      // Destination DAG address
    long getAmount();             // Amount in smallest units (1e-8)
    long getFee();                // Fee in smallest units (1e-8)
    TransactionReference getParent();
    String getSalt();             // Random salt for uniqueness
}

public class CurrencyTransaction extends Signed<CurrencyTransactionValue> {
}

public class TransferParams {
    String getDestination();  // Destination DAG address
    double getAmount();       // Amount in token units (e.g., 100.5 tokens)
    double getFee();          // Fee in token units (defaults to 0)
}
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

### Currency Transactions

#### Create and Verify Token Transaction

```java
import io.constellationnetwork.metagraph.sdk.*;

public class CurrencyExample {
    public static void main(String[] args) {
        // Generate keys
        Types.KeyPair senderKey = Wallet.generateKeyPair();
        Types.KeyPair recipientKey = Wallet.generateKeyPair();

        // Get last transaction reference (from network or previous transaction)
        CurrencyTypes.TransactionReference lastRef =
            new CurrencyTypes.TransactionReference("abc123...previous-tx-hash", 5);

        // Create transaction
        CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
            new CurrencyTypes.TransferParams(recipientKey.getAddress(), 100.5, 0),
            senderKey.getPrivateKey(),
            lastRef
        );

        // Verify
        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
        System.out.println("Transaction valid: " + result.isValid());

        // Note: Network submission not yet implemented in this SDK
        // You can submit the transaction using dag4.js or custom network code
    }
}
```

#### Batch Token Transactions

```java
import io.constellationnetwork.metagraph.sdk.*;
import java.util.Arrays;
import java.util.List;

public class BatchExample {
    public static void main(String[] args) {
        Types.KeyPair keyPair = Wallet.generateKeyPair();
        CurrencyTypes.TransactionReference lastRef =
            new CurrencyTypes.TransactionReference("abc123...", 10);

        List<CurrencyTypes.TransferParams> transfers = Arrays.asList(
            new CurrencyTypes.TransferParams("DAG...1", 10, 0),
            new CurrencyTypes.TransferParams("DAG...2", 20, 0),
            new CurrencyTypes.TransferParams("DAG...3", 30, 0)
        );

        // Create batch (transactions are automatically chained)
        List<CurrencyTypes.CurrencyTransaction> txns =
            CurrencyTransaction.createCurrencyTransactionBatch(
                transfers,
                keyPair.getPrivateKey(),
                lastRef
            );

        // txns.get(0).getValue().getParent().getOrdinal() == 10
        // txns.get(1).getValue().getParent().getOrdinal() == 11
        // txns.get(2).getValue().getParent().getOrdinal() == 12
    }
}
```

#### Multi-Signature Token Transaction

```java
import io.constellationnetwork.metagraph.sdk.*;

public class MultiSigExample {
    public static void main(String[] args) {
        Types.KeyPair key1 = Wallet.generateKeyPair();
        Types.KeyPair key2 = Wallet.generateKeyPair();
        Types.KeyPair recipient = Wallet.generateKeyPair();

        CurrencyTypes.TransactionReference lastRef =
            new CurrencyTypes.TransactionReference("abc123...", 0);

        // Create transaction with first signature
        CurrencyTypes.CurrencyTransaction tx = CurrencyTransaction.createCurrencyTransaction(
            new CurrencyTypes.TransferParams(recipient.getAddress(), 100, 0),
            key1.getPrivateKey(),
            lastRef
        );

        // Add second signature
        tx = CurrencyTransaction.signCurrencyTransaction(tx, key2.getPrivateKey());

        // Verify both signatures
        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
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
