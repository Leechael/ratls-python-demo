"""Smoke tests for ratls module and tee.py."""

import hashlib
import inspect
import struct
from unittest.mock import MagicMock


def test_tee_imports():
    import tee
    assert inspect.iscoroutinefunction(tee.verify_tee)
    source = inspect.getsource(tee)
    assert "import httpx" not in source
    assert "asn1crypto" not in source
    assert "from cryptography" not in source
    print("OK: tee.py is clean — only uses ratls")


def test_ratls_imports():
    from ratls import RaTLS, ACCEPTED_VERIFICATION_STATUSES, DSTACK_RUNTIME_EVENT_TYPE
    assert inspect.iscoroutinefunction(RaTLS.from_cert)
    assert "OK" in ACCEPTED_VERIFICATION_STATUSES
    assert "REVOKED" not in ACCEPTED_VERIFICATION_STATUSES
    assert DSTACK_RUNTIME_EVENT_TYPE == 0x08000001
    print("OK: ratls module imports")


def test_read_ext_value():
    from ratls import _read_ext_value

    mock_cert = MagicMock()
    mock_cert.extensions.get_extension_for_oid.return_value.value.value = b"\x04\x03abc"
    assert _read_ext_value(mock_cert, "oid") == b"abc"

    payload = b"\x00" * 128
    mock_cert.extensions.get_extension_for_oid.return_value.value.value = b"\x04\x81\x80" + payload
    assert _read_ext_value(mock_cert, "oid") == payload
    print("OK: _read_ext_value DER parsing")


def test_replay_rtmr3():
    from ratls import _replay_rtmr3, DSTACK_RUNTIME_EVENT_TYPE

    assert _replay_rtmr3([]) == b'\x00' * 48
    assert _replay_rtmr3([{"event_type": 0, "event": "boot", "event_payload": "00"}]) == b'\x00' * 48

    event = {
        "imr": 3,
        "event_type": DSTACK_RUNTIME_EVENT_TYPE,
        "event": "compose-hash",
        "event_payload": "deadbeef",
    }
    result = _replay_rtmr3([event])
    assert len(result) == 48
    assert result != b'\x00' * 48

    event_type_bytes = struct.pack('<I', DSTACK_RUNTIME_EVENT_TYPE)
    h = hashlib.sha384()
    h.update(event_type_bytes)
    h.update(b":")
    h.update(b"compose-hash")
    h.update(b":")
    h.update(bytes.fromhex("deadbeef"))
    digest = h.digest()
    expected = hashlib.sha384(b'\x00' * 48 + digest).digest()
    assert result == expected
    print("OK: _replay_rtmr3 matches manual computation")


def test_validate_tcb():
    from ratls import _validate_tcb
    import dcap_qvl

    mock_quote = MagicMock()
    mock_report = MagicMock(spec=dcap_qvl.TdReport10)
    mock_report.td_attributes = b'\x00' * 8
    mock_report.mr_signer_seam = b'\x00' * 48
    mock_quote.report = mock_report
    _validate_tcb(mock_quote)
    print("OK: _validate_tcb passes for non-debug TDX")

    mock_report.td_attributes = b'\x01' + b'\x00' * 7
    try:
        _validate_tcb(mock_quote)
        assert False, "should have raised"
    except ValueError as e:
        assert "debug" in str(e)
    print("OK: _validate_tcb rejects debug mode")


if __name__ == "__main__":
    test_tee_imports()
    test_ratls_imports()
    test_read_ext_value()
    test_replay_rtmr3()
    test_validate_tcb()
    print("\nAll tests passed.")
