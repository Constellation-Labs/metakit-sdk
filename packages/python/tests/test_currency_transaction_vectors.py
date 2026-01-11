"""
Currency transaction test vector validation

Validates Python implementation against reference test vectors from tessellation
"""

import json
from pathlib import Path

from ecdsa import SECP256k1, SigningKey

from constellation_sdk.currency_transaction import (
    create_currency_transaction,
    encode_currency_transaction,
    hash_currency_transaction,
    verify_currency_transaction,
)
from constellation_sdk.currency_types import (
    CurrencyTransactionValue,
    TransactionReference,
    TransferParams,
)
from constellation_sdk.types import SignatureProof, Signed
from constellation_sdk.wallet import get_address

# Load test vectors
VECTORS_PATH = (
    Path(__file__).parent.parent.parent.parent / "shared" / "currency_transaction_vectors.json"
)
with open(VECTORS_PATH) as f:
    test_vectors = json.load(f)


class TestKeyDerivation:
    """Test key derivation against reference vectors"""

    def test_public_key_derivation(self):
        """Derives correct public key from private key"""
        basic = test_vectors["testVectors"]["basicTransaction"]
        sk = SigningKey.from_string(bytes.fromhex(basic["privateKeyHex"]), curve=SECP256k1)
        vk = sk.verifying_key
        public_key = "04" + vk.to_string().hex()
        assert public_key == basic["publicKeyHex"]

    def test_address_derivation(self):
        """Derives correct address from public key"""
        basic = test_vectors["testVectors"]["basicTransaction"]
        sk = SigningKey.from_string(bytes.fromhex(basic["privateKeyHex"]), curve=SECP256k1)
        vk = sk.verifying_key
        public_key = "04" + vk.to_string().hex()
        address = get_address(public_key)
        assert address == basic["address"]


class TestTransactionEncoding:
    """Test transaction encoding format"""

    def test_encoding_format(self):
        """Encodes transaction correctly"""
        basic = test_vectors["testVectors"]["basicTransaction"]

        # Create transaction with known values
        tx = create_currency_transaction(
            TransferParams(
                destination=basic["transaction"]["destination"],
                amount=basic["transaction"]["amount"] / 1e8,
                fee=basic["transaction"]["fee"] / 1e8,
            ),
            basic["privateKeyHex"],
            TransactionReference(
                hash=basic["transaction"]["parent"]["hash"],
                ordinal=basic["transaction"]["parent"]["ordinal"],
            ),
        )

        # Override salt for deterministic test
        tx.value.salt = str(basic["transaction"]["salt"])
        tx.proofs = []  # Clear proofs for encoding test

        encoded = encode_currency_transaction(tx)
        assert encoded == basic["encodedString"]

    def test_encoding_breakdown(self):
        """Validates encoding format breakdown"""
        breakdown = test_vectors["testVectors"]["encodingBreakdown"]
        components = breakdown["components"]

        # Verify version prefix
        assert components["versionPrefix"] == "2"

        # Verify components are present in full encoding
        full_encoded = breakdown["fullEncoded"]
        assert full_encoded.startswith("2")
        assert components["source"]["value"] in full_encoded
        assert components["destination"]["value"] in full_encoded
        assert components["amountHex"]["value"] in full_encoded
        assert components["parentHash"]["value"] in full_encoded


class TestTransactionHashing:
    """Test transaction hashing"""

    def test_transaction_hash(self):
        """Produces correct transaction hash"""
        basic = test_vectors["testVectors"]["basicTransaction"]

        # Create transaction with deterministic values
        tx = create_currency_transaction(
            TransferParams(
                destination=basic["transaction"]["destination"],
                amount=basic["transaction"]["amount"] / 1e8,
                fee=basic["transaction"]["fee"] / 1e8,
            ),
            basic["privateKeyHex"],
            TransactionReference(
                hash=basic["transaction"]["parent"]["hash"],
                ordinal=basic["transaction"]["parent"]["ordinal"],
            ),
        )

        # Override salt for exact match
        tx.value.salt = str(basic["transaction"]["salt"])
        tx.proofs = []

        hash_result = hash_currency_transaction(tx)
        assert hash_result.value == basic["transactionHash"]


class TestSignatureVerification:
    """Test signature verification"""

    def test_reference_signature(self):
        """Verifies reference signature"""
        basic = test_vectors["testVectors"]["basicTransaction"]

        # Reconstruct transaction from test vector
        tx_data = basic["transaction"]
        tx_value = CurrencyTransactionValue(
            source=tx_data["source"],
            destination=tx_data["destination"],
            amount=tx_data["amount"],
            fee=tx_data["fee"],
            parent=TransactionReference(
                hash=tx_data["parent"]["hash"], ordinal=tx_data["parent"]["ordinal"]
            ),
            salt=str(tx_data["salt"]),
        )

        tx = Signed(
            value=tx_value,
            proofs=[
                SignatureProof(
                    id=basic["signerId"],
                    signature=basic["signature"],
                )
            ],
        )

        result = verify_currency_transaction(tx)
        assert result.is_valid is True
        assert len(result.valid_proofs) == 1
        assert len(result.invalid_proofs) == 0

    def test_multi_signature(self):
        """Verifies multi-signature transaction"""
        basic = test_vectors["testVectors"]["basicTransaction"]
        multi_sig = test_vectors["testVectors"]["multiSignature"]

        # Reconstruct transaction with multiple proofs
        tx_data = basic["transaction"]
        tx_value = CurrencyTransactionValue(
            source=tx_data["source"],
            destination=tx_data["destination"],
            amount=tx_data["amount"],
            fee=tx_data["fee"],
            parent=TransactionReference(
                hash=tx_data["parent"]["hash"], ordinal=tx_data["parent"]["ordinal"]
            ),
            salt=str(tx_data["salt"]),
        )

        # Convert dict proofs to SignatureProof objects
        proofs = [
            SignatureProof(id=proof["id"], signature=proof["signature"])
            for proof in multi_sig["proofs"]
        ]

        tx = Signed(
            value=tx_value,
            proofs=proofs,
        )

        result = verify_currency_transaction(tx)
        assert result.is_valid is True
        assert len(result.valid_proofs) == 2
        assert len(result.invalid_proofs) == 0

        # Verify both proofs are marked as valid in test vectors
        for proof in multi_sig["proofs"]:
            assert proof["valid"] is True


class TestTransactionChaining:
    """Test transaction chaining"""

    def test_chain_parent_references(self):
        """Validates transaction chain parent references"""
        chain = test_vectors["testVectors"]["transactionChaining"]["transactions"]

        # Verify first transaction parent
        assert chain[0]["parentHash"] == "a" * 64
        assert chain[0]["parentOrdinal"] == 5
        assert chain[0]["ordinal"] == 6

        # Verify second transaction chains to first
        assert chain[1]["parentHash"] == chain[0]["hash"]
        assert chain[1]["parentOrdinal"] == chain[0]["ordinal"]
        assert chain[1]["ordinal"] == 7

        # Verify third transaction chains to second
        assert chain[2]["parentHash"] == chain[1]["hash"]
        assert chain[2]["parentOrdinal"] == chain[1]["ordinal"]
        assert chain[2]["ordinal"] == 8


class TestEdgeCases:
    """Test edge cases"""

    def test_minimum_amount(self):
        """Validates minimum amount transaction"""
        min_amount = test_vectors["testVectors"]["edgeCases"]["minAmount"]
        assert min_amount["amount"] == 1
        assert min_amount["hash"]
        assert min_amount["signature"]

    def test_maximum_amount(self):
        """Validates maximum amount transaction"""
        max_amount = test_vectors["testVectors"]["edgeCases"]["maxAmount"]
        assert max_amount["amount"] == 9223372036854775807
        assert max_amount["hash"]
        assert max_amount["signature"]

    def test_non_zero_fee(self):
        """Validates transaction with non-zero fee"""
        with_fee = test_vectors["testVectors"]["edgeCases"]["withFee"]
        assert with_fee["amount"] == 10000000000
        assert with_fee["fee"] == 100000
        assert with_fee["hash"]
        assert with_fee["signature"]


class TestKryoSerialization:
    """Test Kryo serialization format"""

    def test_set_references_flag(self):
        """Validates Kryo setReferences=false format (v2 transactions)"""
        params = test_vectors["cryptoParams"]
        assert params["kryoSetReferences"] is False

    def test_kryo_header(self):
        """Validates Kryo header without reference flag (v2 format)"""
        basic = test_vectors["testVectors"]["basicTransaction"]
        kryo_hex = basic["kryoBytesHex"]
        # Should start with 0x03 (string type) followed by length, no 0x01 reference flag for v2
        assert kryo_hex.startswith("03")
        assert not kryo_hex.startswith("0301")  # No reference flag for v2
