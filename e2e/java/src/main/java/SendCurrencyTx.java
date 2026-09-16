import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import io.constellationnetwork.metagraph.sdk.*;
import io.constellationnetwork.metagraph.sdk.core.Types;
import io.constellationnetwork.metagraph.sdk.core.Wallet;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Simple script to send a currency transaction to a local metagraph.
 *
 * Reads configuration from config.json and submits a currency transaction
 * to the Currency L1 endpoint.
 *
 * Usage:
 *   mvn exec:java
 *   mvn exec:java -Dexec.args="--config other_config.json"
 *   mvn exec:java -Dexec.args="--generate-keypair"
 */
public class SendCurrencyTx {

    private static final Gson gson = new Gson();

    static class Config {
        @SerializedName("private_key")
        String privateKey;
        String destination;
        double amount;
        double fee;
        @SerializedName("currency_l1_url")
        String currencyL1Url;
    }

    public static void main(String[] args) {
        String configFile = "../config.json";
        boolean generateKeypair = false;

        // Parse arguments
        for (int i = 0; i < args.length; i++) {
            if ("--generate-keypair".equals(args[i])) {
                generateKeypair = true;
            } else if ("--config".equals(args[i]) && i + 1 < args.length) {
                configFile = args[++i];
            } else if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                printHelp();
                return;
            }
        }

        if (generateKeypair) {
            generateKeypairCommand();
            return;
        }

        // Load config
        Path configPath = Paths.get(configFile);
        if (!Files.exists(configPath)) {
            System.err.println("Error: Config file not found: " + configPath.toAbsolutePath());
            System.exit(1);
        }

        Config config;
        try {
            String content = Files.readString(configPath);
            config = gson.fromJson(content, Config.class);
        } catch (IOException e) {
            System.err.println("Error reading config: " + e.getMessage());
            System.exit(1);
            return;
        }

        sendTransaction(config);
    }

    private static void printHelp() {
        System.out.println("Usage: mvn exec:java -Dexec.args=\"[OPTIONS]\"");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --config <file>     Path to config file (default: ../config.json)");
        System.out.println("  --generate-keypair  Generate a new keypair and exit");
        System.out.println("  --help, -h          Show this help message");
    }

    private static void generateKeypairCommand() {
        Types.KeyPair keypair = Wallet.generateKeyPair();
        System.out.println("Generated new keypair:");
        System.out.println("  Private Key: " + keypair.getPrivateKey());
        System.out.println("  Public Key:  " + keypair.getPublicKey());
        System.out.println("  DAG Address: " + keypair.getAddress());
        System.out.println();
        System.out.println("Save the private key to your config.json to use it for transactions.");
    }

    private static void sendTransaction(Config config) {
        // Validate config
        if (config.privateKey == null || config.privateKey.isEmpty()) {
            System.err.println("Error: Missing required field 'private_key' in config");
            System.exit(1);
        }
        if (config.destination == null || config.destination.isEmpty()) {
            System.err.println("Error: Missing required field 'destination' in config");
            System.exit(1);
        }
        if (config.currencyL1Url == null || config.currencyL1Url.isEmpty()) {
            System.err.println("Error: Missing required field 'currency_l1_url' in config");
            System.exit(1);
        }

        String privateKey = config.privateKey;
        String destination = config.destination;
        double amount = config.amount;
        double fee = config.fee;
        String currencyL1Url = config.currencyL1Url;

        // Validate private key format
        if ("YOUR_64_CHAR_HEX_PRIVATE_KEY_HERE".equals(privateKey)) {
            System.err.println("Error: Please set your private key in config.json");
            System.err.println("Run with --generate-keypair to create a new keypair");
            System.exit(1);
        }

        if (privateKey.length() != 64) {
            System.err.println("Error: Private key must be 64 hex characters, got " + privateKey.length());
            System.exit(1);
        }

        // Derive address from private key
        Types.KeyPair keypair = Wallet.keyPairFromPrivateKey(privateKey);
        String sourceAddress = keypair.getAddress();

        System.out.println("Source Address: " + sourceAddress);
        System.out.println("Destination:    " + destination);
        System.out.println("Amount:         " + amount + " tokens");
        System.out.println("Fee:            " + fee + " tokens");
        System.out.println("Currency L1:    " + currencyL1Url);
        System.out.println();

        // Create client
        MetagraphClient client = new MetagraphClient(currencyL1Url, MetagraphClient.LayerType.CL1);

        // Check health
        System.out.println("Checking node health...");
        if (!client.checkHealth()) {
            System.err.println("Error: Currency L1 node is not responding");
            System.exit(1);
        }
        System.out.println("Node is healthy!");
        System.out.println();

        // Get last reference
        System.out.println("Fetching last reference for " + sourceAddress + "...");
        CurrencyTypes.TransactionReference lastRef;
        try {
            lastRef = client.getLastReference(sourceAddress);
            System.out.println("Last Reference Hash:    " + lastRef.getHash());
            System.out.println("Last Reference Ordinal: " + lastRef.getOrdinal());
        } catch (Exception e) {
            System.err.println("Error getting last reference: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // Create transaction
        System.out.println("Creating transaction...");
        CurrencyTypes.CurrencyTransaction tx;
        try {
            CurrencyTypes.TransferParams transferParams = new CurrencyTypes.TransferParams(
                    destination, amount, fee);
            tx = CurrencyTransaction.createCurrencyTransaction(transferParams, privateKey, lastRef);
            System.out.println("Transaction created successfully!");
        } catch (Exception e) {
            System.err.println("Error creating transaction: " + e.getMessage());
            System.exit(1);
            return;
        }

        // Verify transaction locally
        System.out.println("Verifying transaction signature...");
        Types.VerificationResult result = CurrencyTransaction.verifyCurrencyTransaction(tx);
        if (!result.isValid()) {
            System.err.println("Error: Transaction signature verification failed!");
            System.exit(1);
        }
        System.out.println("Signature verified!");
        System.out.println();

        // Submit transaction
        System.out.println("Submitting transaction to network...");
        NetworkTypes.PostTransactionResponse response;
        try {
            response = client.postTransaction(tx);
            System.out.println("Transaction submitted!");
            System.out.println("Transaction Hash: " + response.getHash());
        } catch (Exception e) {
            System.err.println("Error submitting transaction: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // Poll for status (optional)
        System.out.println("Checking transaction status...");
        try {
            NetworkTypes.PendingTransaction pending = client.getPendingTransaction(response.getHash());
            if (pending != null) {
                System.out.println("Status: " + pending.getStatus());
            } else {
                System.out.println("Transaction not found in pending pool (may already be confirmed)");
            }
        } catch (Exception e) {
            System.out.println("Could not check status: " + e.getMessage());
        }

        System.out.println();
        System.out.println("Done!");
    }
}
