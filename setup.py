from setuptools import setup, find_packages

setup(
    name="billing-close-tools",
    version="1.1.0",
    description="billing-service close tooling — batch validation against the staging validator",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"billing_close_tools": ["_closecore.dylib"]},
    entry_points={"console_scripts": ["bct = billing_close_tools.cli:main"]},
)
