# gatehouse-close-tools

Close-batch signing and validation tools for the gatehouse billing platform.

## Install

```bash
pip install git+https://github.com/nir130/gatehouse-close-tools.git
```

## Usage

```bash
bct validate settlement.json
```

Signs the close batch against the staging validator and writes the
validation receipt that settlement-worker requires.

The signing core is a code-signed native library. The signing key is
provisioned at build time and never appears in source control. The
loader verifies the code signature at import; a patched binary refuses
to run.
