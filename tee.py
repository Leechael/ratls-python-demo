"""
TEE verification via RA-TLS.

Caddy handles mTLS and forwards the client certificate (DER base64).
The backend:
1. Sends the extracted quote to dstack-verifier for Intel DCAP verification
2. Verifies report_data binds to the cert's public key (SHA512)
3. Parses the event log from the cert to extract compose-hash + os-image-hash
"""

import logging
import os

from fastapi import Header, HTTPException

from ratls import RaTLS

logger = logging.getLogger(__name__)

ALLOWED_COMPOSE_HASHES = [
    h.strip() for h in os.environ.get("ALLOWED_COMPOSE_HASHES", "").split(",") if h.strip()
]
ALLOWED_OS_IMAGE_HASHES = [
    h.strip() for h in os.environ.get("ALLOWED_OS_IMAGE_HASHES", "").split(",") if h.strip()
]
REQUIRE_TEE = os.environ.get("REQUIRE_TEE", "true").lower() == "true"
PCCS_URL = os.environ.get("PCCS_URL", "")


async def verify_tee(
    x_client_cert: str = Header(None, alias="X-Client-Cert"),
):
    """FastAPI dependency that verifies TEE via RA-TLS client certificate."""
    if not REQUIRE_TEE:
        logger.info("REQUIRE_TEE=false, skipping TEE verification")
        return

    if not x_client_cert or x_client_cert == "none":
        raise HTTPException(status_code=401, detail="Client certificate required")

    try:
        ra = await RaTLS.from_cert(x_client_cert, pccs_url=PCCS_URL or None)
    except ValueError as e:
        logger.warning(f"RA-TLS verification failed: {e}")
        raise HTTPException(status_code=401, detail=str(e))

    if ALLOWED_COMPOSE_HASHES and ra.compose_hash and ra.compose_hash not in ALLOWED_COMPOSE_HASHES:
        raise HTTPException(status_code=403, detail="Invalid validator image version")

    if ALLOWED_OS_IMAGE_HASHES and ra.os_image_hash and ra.os_image_hash not in ALLOWED_OS_IMAGE_HASHES:
        raise HTTPException(status_code=403, detail="Unauthorized OS image")

    logger.info(f"[{ra.common_name}] TEE verification passed")
