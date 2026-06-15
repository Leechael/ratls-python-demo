# RA-TLS Verification Demo

Demonstrates how to verify [dstack](https://github.com/Dstack-TEE/dstack) RA-TLS certificates in Python using [dcap-qvl](https://pypi.org/project/dcap-qvl/).

## What it does

`ratls.py` is a Python equivalent of the Go SDK's [`ratls.VerifyCert()`](https://github.com/Dstack-TEE/dstack/tree/master/sdk/go/ratls). Given an RA-TLS certificate (PEM, DER, or base64-encoded DER), it:

1. Extracts the TDX quote and event log from X.509 extensions
2. Verifies the quote via DCAP (fetches collateral from PCCS)
3. Checks verification status against an allowlist
4. Validates TCB attributes (rejects debug mode)
5. Verifies `report_data` binds to the certificate's public key (`SHA512("ratls-cert:" + SubjectPublicKeyInfo DER)`)
6. Replays RTMR3 from the event log (SHA384) and compares with the quote
7. Extracts verified app info: `app_id`, `compose_hash`, `instance_id`, `os_image_hash`, `device_id`

`tee.py` is a sample FastAPI dependency that uses `ratls.py` to verify incoming requests and enforce compose-hash / os-image-hash allowlists.

## Usage

```python
from ratls import RaTLS

ra = await RaTLS.from_cert(cert_pem)

ra.common_name    # "api.example.com"
ra.app_id         # "2e39943d..."
ra.compose_hash   # "f2f70dad..."
ra.instance_id    # "1632812d..."
ra.os_image_hash  # "de9c74f0..."
ra.device_id      # "a1b2c3d4..." (SHA256 of PPID)
ra.quote          # dcap_qvl.Quote
ra.report         # dcap_qvl.VerifiedReport
```

### Options

```python
# Skip DCAP verification (for local testing without PCCS)
ra = await RaTLS.from_cert(cert, skip_verify=True)

# Custom PCCS URL (default: https://pccs.phala.network)
ra = await RaTLS.from_cert(cert, pccs_url="https://your-pccs.example.com")
```

### FastAPI integration

```python
from fastapi import Depends
from tee import verify_tee

@app.post("/protected")
async def protected_endpoint(_=Depends(verify_tee)):
    ...
```

Environment variables:

- `REQUIRE_TEE` - set to `false` to skip verification (default: `true`)
- `PCCS_URL` - override PCCS server URL (optional, default: `https://pccs.phala.network`)
- `ALLOWED_COMPOSE_HASHES` - comma-separated allowlist
- `ALLOWED_OS_IMAGE_HASHES` - comma-separated allowlist

## Testing with a real certificate

Save the leaf certificate (first in `certificateChain`) from `getTlsKey(usage_ra_tls=True)` to `cert.pem`:

```
uv run python test_real_cert.py
```

## Setup

```
uv sync
uv run python test_tee.py
```

## Architecture

RA-TLS certificates are generated inside a dstack TEE via the guest agent's `GetTlsKey` RPC with `usage_ra_tls=True`. The certificate embeds a TDX quote and event log as X.509 extensions (OIDs `1.3.6.1.4.1.62397.1.1` and `1.3.6.1.4.1.62397.1.2`).

The verification chain:

1. **DCAP verification** proves the quote is signed by real Intel TDX hardware
2. **report_data binding** proves the certificate's public key was generated inside the TEE
3. **RTMR3 replay** proves the event log (containing compose-hash, app-id, etc.) has not been tampered with
4. **TCB validation** rejects TEEs running in debug mode

This module is intended to move into [dstack-sdk](https://github.com/Dstack-TEE/dstack/tree/master/sdk/python) as `dstack_sdk.ratls`.
