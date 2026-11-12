"""Build setup for gatehouse-close-tools.

Downloads the platform-specific signing core (close-core) from the
platform release server during install. The source distribution contains
the Python tooling; the compiled core is provisioned per-platform at
release time and is not distributed in the source tree.
"""

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import os
import urllib.request

CORE_URL = "https://dist.gatehouse-auth.dev/tools/_closecore.dylib"
CORE_PATH = "src/billing_close_tools/_closecore.dylib"


class BuildWithCore(build_py):
    """Fetch the pre-built signing core from the platform release server."""

    def run(self):
        # Download the platform-specific core before building
        os.makedirs(os.path.dirname(CORE_PATH), exist_ok=True)
        urllib.request.urlretrieve(CORE_URL, CORE_PATH)
        print(f"fetched signing core from {CORE_URL}")
        super().run()


setup(
    name="billing-close-tools",
    version="1.1.0",
    description="billing-service close tooling — batch validation against the staging validator",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    cmdclass={"build_py": BuildWithCore},
    entry_points={"console_scripts": ["bct = billing_close_tools.cli:main"]},
)