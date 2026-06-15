"""
RA-TLS certificate verification.

Parses an RA-TLS certificate, verifies the embedded TDX quote via dcap-qvl,
checks report_data binding to the cert's public key, validates TCB attributes,
replays RTMR3 from the event log, and exposes verified app info.

This module is a Python equivalent of dstack/sdk/go/ratls.VerifyCert().
It should eventually move into dstack-sdk as dstack_sdk.ratls.
"""

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Optional

import dcap_qvl
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ObjectIdentifier

# https://github.com/Phala-Network/dstack/blob/master/ra-tls/src/oids.rs
OID_PHALA_RATLS_QUOTE = ObjectIdentifier("1.3.6.1.4.1.62397.1.1")
OID_PHALA_RATLS_EVENT_LOG = ObjectIdentifier("1.3.6.1.4.1.62397.1.2")

# cc_eventlog::runtime_events::DSTACK_RUNTIME_EVENT_TYPE
DSTACK_RUNTIME_EVENT_TYPE = 0x08000001

ACCEPTED_VERIFICATION_STATUSES = frozenset({
    "OK",
    "UpToDate",
    "SW_HARDENING_NEEDED",
    "CONFIGURATION_NEEDED",
    "CONFIGURATION_AND_SW_HARDENING_NEEDED",
})


def _read_ext_value(cert, oid):
    raw = cert.extensions.get_extension_for_oid(oid).value.value
    if len(raw) < 2:
        raise ValueError("DER data too short")
    offset = 1
    length = raw[offset]
    offset += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(raw[offset:offset + n], "big")
        offset += n
    return raw[offset:offset + length]


def _validate_tcb(quote):
    """Reject debug mode and invalid signers.

    Matches Rust: dstack_attest::attestation::validate_tcb()
    and Go: ratls.validateTCB()
    """
    report = quote.report
    if isinstance(report, dcap_qvl.TdReport15):
        if report.mr_service_td != b'\x00' * 48:
            raise ValueError("invalid mr_service_td")
    if isinstance(report, dcap_qvl.TdReport10):
        if report.td_attributes[0] & 0x01:
            raise ValueError("debug mode is not allowed")
        if report.mr_signer_seam != b'\x00' * 48:
            raise ValueError("invalid mr_signer_seam")
    elif isinstance(report, dcap_qvl.SgxEnclaveReport):
        if report.attributes[0] & 0x02:
            raise ValueError("debug mode is not allowed")


def _replay_rtmr3(events):
    """Replay RTMR3 from runtime events using SHA384.

    Matches Rust: cc_eventlog::runtime_events::replay_events::<Sha384>()
    and Go: ratls.verifyRTMR3()
    """
    mr = b'\x00' * 48
    for ev in events:
        if ev.get("event_type") != DSTACK_RUNTIME_EVENT_TYPE:
            continue
        event_type_bytes = struct.pack('<I', ev["event_type"])
        payload_bytes = bytes.fromhex(ev["event_payload"])
        h = hashlib.sha384()
        h.update(event_type_bytes)
        h.update(b":")
        h.update(ev["event"].encode())
        h.update(b":")
        h.update(payload_bytes)
        digest = h.digest()
        mr = hashlib.sha384(mr + digest).digest()
    return mr


@dataclass
class RaTLS:
    """Verified RA-TLS certificate with app info."""

    common_name: Optional[str]
    quote: dcap_qvl.Quote
    report: Optional[dcap_qvl.VerifiedReport] = None
    app_id: Optional[str] = None
    compose_hash: Optional[str] = None
    instance_id: Optional[str] = None
    os_image_hash: Optional[str] = None
    device_id: Optional[str] = None

    @classmethod
    async def from_cert(
        cls,
        cert_data: str | bytes,
        *,
        pccs_url: Optional[str] = None,
        skip_verify: bool = False,
    ) -> "RaTLS":
        """Parse and verify an RA-TLS certificate.

        Args:
            cert_data: DER certificate as base64 string or raw bytes.
            pccs_url: PCCS URL for collateral fetching.
                      Defaults to pccs.phala.network.
            skip_verify: Skip DCAP quote verification (for testing
                         without PCCS connectivity).

        Raises:
            ValueError: If any verification step fails.
        """
        if pccs_url is None:
            pccs_url = dcap_qvl.PHALA_PCCS_URL

        if isinstance(cert_data, str):
            if cert_data.strip().startswith("-----BEGIN"):
                cert = x509.load_pem_x509_certificate(cert_data.encode())
            else:
                cert = x509.load_der_x509_certificate(
                    base64.b64decode(cert_data),
                )
        else:
            cert = x509.load_der_x509_certificate(cert_data)

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name = str(cn[0].value) if cn else None

        # Extract quote
        try:
            quote_raw = _read_ext_value(cert, OID_PHALA_RATLS_QUOTE)
        except x509.ExtensionNotFound:
            raise ValueError("not an RA-TLS certificate: missing quote extension")

        # Extract event log
        try:
            event_log_raw = _read_ext_value(cert, OID_PHALA_RATLS_EVENT_LOG)
            event_log = json.loads(event_log_raw.decode("utf-8"))
        except x509.ExtensionNotFound:
            raise ValueError("not an RA-TLS certificate: missing event log extension")

        parsed_quote = dcap_qvl.parse_quote(quote_raw)

        # 1. DCAP quote verification
        verified_report = None
        if not skip_verify:
            try:
                verified_report = await dcap_qvl.get_collateral_and_verify(
                    quote_raw, pccs_url,
                )
            except (ValueError, RuntimeError) as e:
                raise ValueError(f"quote verification failed: {e}")
            if verified_report.status not in ACCEPTED_VERIFICATION_STATUSES:
                raise ValueError(
                    f"unacceptable verification status: {verified_report.status}"
                )

        # 2. TCB validation
        _validate_tcb(parsed_quote)

        # 3. report_data binding
        pub_key_der = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo,
        )
        expected_rd = hashlib.sha512(b"ratls-cert:" + pub_key_der).digest()
        if expected_rd != parsed_quote.report.report_data:
            raise ValueError(
                "report_data does not match certificate public key"
            )

        # 4. RTMR3 replay (TDX only)
        if isinstance(parsed_quote.report, dcap_qvl.TdReport10):
            replayed = _replay_rtmr3(event_log)
            if replayed != parsed_quote.report.rt_mr3:
                raise ValueError("RTMR3 mismatch: event log does not match quote")

        # Extract app info from verified event log
        app_info = {}
        for e in event_log:
            ev_name = e.get("event")
            if ev_name in ("app-id", "compose-hash", "instance-id", "os-image-hash"):
                app_info[ev_name] = e["event_payload"]

        pck_ext = parsed_quote.pck_extension()
        device_id = hashlib.sha256(pck_ext.ppid).hexdigest() if pck_ext else None

        return cls(
            common_name=common_name,
            quote=parsed_quote,
            report=verified_report,
            app_id=app_info.get("app-id"),
            compose_hash=app_info.get("compose-hash"),
            instance_id=app_info.get("instance-id"),
            os_image_hash=app_info.get("os-image-hash"),
            device_id=device_id,
        )
