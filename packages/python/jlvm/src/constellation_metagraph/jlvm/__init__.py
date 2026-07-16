"""
Constellation Metagraph SDK — jlvm tier (reserved placeholder).

This distribution is an intentionally empty placeholder that reserves the
``constellation_metagraph.jlvm`` namespace for the future Python port of the
JLVM evaluator, crypto-opcode surface, and proof tooling. There is no runnable
source here yet; it exists so the namespace and the ``constellation-metagraph-sdk-jlvm``
distribution name are claimed and versioned in lockstep with ``core`` and ``std``.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("constellation-metagraph-sdk-jlvm")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development

__all__ = ["__version__"]
