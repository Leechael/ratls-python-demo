"""Test ratls.RaTLS.from_cert with a real RA-TLS certificate from a dstack CVM.

Usage: paste the certificateChain[0] PEM into cert.pem, then run this script.
  python test_real_cert.py
"""

import asyncio
import sys

from ratls import RaTLS


async def main():
    try:
        with open("cert.pem") as f:
            pem = f.read()
    except FileNotFoundError:
        print("Put the RA-TLS certificate PEM into cert.pem and re-run.")
        sys.exit(1)

    ra = await RaTLS.from_cert(pem, skip_verify=True)

    print(f"common_name:   {ra.common_name}")
    print(f"app_id:        {ra.app_id}")
    print(f"compose_hash:  {ra.compose_hash}")
    print(f"instance_id:   {ra.instance_id}")
    print(f"os_image_hash: {ra.os_image_hash}")
    print(f"report_data:   {ra.quote.report.report_data.hex()}")
    print(f"mr_config_id:  {ra.quote.report.mr_config_id.hex()}")
    print(f"quote_type:    {'TDX' if ra.quote.is_tdx() else 'SGX'}")

    print(f"device_id:     {ra.device_id}")


asyncio.run(main())
