"""billing-close-tools — close-batch tooling for the gatehouse billing platform.

The validation core ships as a native library (close-core): the signing key
is provisioned at build time by the platform release pipeline and must not
appear in source control, so the wire protocol lives in the compiled core.
"""

from .cli import main, validate  # noqa: F401

__version__ = "1.1.0"