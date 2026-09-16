"""
Constellation Metagraph SDK — backward-compatibility shim.

The SDK is now split into three tiers that live under the
``constellation_metagraph`` namespace:

    * ``constellation_metagraph.core`` — offline kernel (signing, verification,
      wallet, canonicalization, hashing, codecs)
    * ``constellation_metagraph.main``  — core plus currency transactions + network
    * ``constellation_metagraph.jlvm`` — reserved placeholder

This module preserves the historical flat ``constellation_sdk`` import path. It
aliases the old submodule paths (``constellation_sdk.types``,
``constellation_sdk.network``, ``constellation_sdk.wallet``, ...) onto their new
homes and re-exports the full ``main`` public surface (which itself re-exports
``core``), so existing code keeps working unchanged:

    from constellation_sdk import sign, generate_key_pair, create_currency_transaction
    from constellation_sdk.types import CONSTELLATION_PREFIX
    from constellation_sdk.network import MetagraphClient, create_metagraph_client
"""

import sys
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version

# Map every historical flat submodule path onto its new tiered location so that
# ``import constellation_sdk.<name>`` and ``from constellation_sdk.<name> import ...``
# continue to resolve. This runs BEFORE the ``import *`` below so that names which
# are both a re-exported callable *and* a submodule (``sign``, ``verify``,
# ``canonicalize``) end up bound to the callable — matching the original flat
# package — while pure-submodule names (``types``, ``network``, ...) stay bound to
# their module objects.
_SUBMODULE_ALIASES = {
    # core modules
    "binary": "constellation_metagraph.core.binary",
    "canonicalize": "constellation_metagraph.core.canonicalize",
    "codec": "constellation_metagraph.core.codec",
    "hash": "constellation_metagraph.core.hash",
    "types": "constellation_metagraph.core.types",
    "sign": "constellation_metagraph.core.sign",
    "signed_object": "constellation_metagraph.core.signed_object",
    "verify": "constellation_metagraph.core.verify",
    "wallet": "constellation_metagraph.core.wallet",
    # main-tier modules
    "currency_transaction": "constellation_metagraph.main.currency_transaction",
    "currency_types": "constellation_metagraph.main.currency_types",
    "network": "constellation_metagraph.main.network",
    "network.client": "constellation_metagraph.main.network.client",
    "network.metagraph_client": "constellation_metagraph.main.network.metagraph_client",
    "network.types": "constellation_metagraph.main.network.types",
}

for _alias, _target in _SUBMODULE_ALIASES.items():
    _module = import_module(_target)
    sys.modules[f"{__name__}.{_alias}"] = _module
    # Expose top-level (non-dotted) aliases as attributes for ``constellation_sdk.types`` etc.
    if "." not in _alias:
        setattr(sys.modules[__name__], _alias, _module)

# Re-export the full flat public API (main re-exports core, then adds currency +
# network on top). This binds the re-exported callables over any like-named
# submodule aliases registered above.
from constellation_metagraph.main import *  # noqa: E402,F401,F403
from constellation_metagraph.main import __all__ as _main_all  # noqa: E402

try:
    __version__ = version("constellation-metagraph-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development

__all__ = list(dict.fromkeys([*_main_all, "__version__"]))
