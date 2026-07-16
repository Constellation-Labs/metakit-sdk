"""Tests for the backward-compatibility ``constellation_sdk`` shim.

The historical flat import path must keep working after the core/main/jlvm split,
including both top-level symbols and the old submodule paths, and signing must be
served from the core tier.
"""

import importlib


def test_flat_top_level_api_is_importable():
    """The classic ``from constellation_sdk import ...`` surface still resolves."""
    from constellation_sdk import (  # noqa: F401
        canonicalize,
        create_currency_transaction,
        create_signed_object,
        generate_key_pair,
        hash_data,
        sign,
        to_bytes,
        verify,
    )

    kp = generate_key_pair()
    assert kp.address.startswith("DAG")


def test_shim_exposes_version():
    import constellation_sdk

    assert isinstance(constellation_sdk.__version__, str)
    assert constellation_sdk.__version__ != ""


def test_old_core_submodule_paths_resolve():
    """``constellation_sdk.<core module>`` aliases resolve to the core tier."""
    from constellation_sdk.types import CONSTELLATION_PREFIX  # noqa: F401
    from constellation_sdk.wallet import get_address  # noqa: F401

    import constellation_sdk.sign as shim_sign
    import constellation_metagraph.core.sign as core_sign

    # The alias is the very same module object, not a copy.
    assert shim_sign is core_sign


def test_old_main_submodule_paths_resolve():
    """``constellation_sdk.<currency/network>`` aliases resolve to the main tier."""
    from constellation_sdk.currency_transaction import create_currency_transaction  # noqa: F401
    from constellation_sdk.network import MetagraphClient, create_metagraph_client  # noqa: F401

    import constellation_sdk.network as shim_network
    import constellation_metagraph.main.network as main_network

    assert shim_network is main_network


def test_signing_is_served_from_core():
    """Signing lives in core; the shim must re-export the core implementation."""
    import constellation_sdk
    import constellation_metagraph.core as core

    assert constellation_sdk.sign is core.sign
    assert constellation_sdk.verify is core.verify
    assert constellation_sdk.create_signed_object is core.create_signed_object
    assert constellation_sdk.generate_key_pair is core.generate_key_pair


def test_importable_via_import_module():
    """Guards against packaging regressions where the shim is not installed."""
    mod = importlib.import_module("constellation_sdk")
    assert hasattr(mod, "sign")
    assert hasattr(mod, "create_currency_transaction")
