"""
Boltwork MCP - L402 Payment Handler
=====================================
Handles the full L402 payment flow transparently.

Supported wallet backends:
  - NWC       (Nostr Wallet Connect) — Alby, Mutiny, Coinos, Primal, Cashu.me
  - Phoenixd  — self-hosted Lightning node (ACINQ)
  - LNbits    — self-hosted or hosted Lightning wallet
  - Strike    — custodial Lightning wallet (Strike API)

Flow:
  1. Request hits L402 gateway → 402 response
  2. Extract macaroon + invoice from WWW-Authenticate header
  3. Pay invoice via configured wallet backend
  4. Retry with Authorization: L402 <macaroon>:<preimage>
"""

import os
import re
import json
import asyncio
import httpx
from typing import Optional


# ---------------------------------------------------------------------------
# WWW-Authenticate header parsing
# ---------------------------------------------------------------------------

def parse_402(www_authenticate: str) -> tuple[str, str]:
    """
    Parse the WWW-Authenticate header from a 402 response.
    Returns (macaroon, invoice).
    Handles both L402 and LSAT prefixes (Aperture emits both).
    """
    macaroon_match = re.search(r'macaroon="([^"]+)"', www_authenticate)
    invoice_match  = re.search(r'invoice="([^"]+)"', www_authenticate)

    if not macaroon_match or not invoice_match:
        raise ValueError(
            f"Could not parse L402 header: {www_authenticate[:200]}"
        )

    return macaroon_match.group(1), invoice_match.group(1)


# ---------------------------------------------------------------------------
# NWC payment backend
# ---------------------------------------------------------------------------

async def pay_invoice_nwc(invoice: str, nwc_string: str) -> str:
    """
    Pay a Lightning invoice via Nostr Wallet Connect (NWC).
    Returns the payment preimage as a hex string.

    Compatible with: Alby (nwc.getalby.com), Mutiny Wallet,
                     Coinos, Primal, Cashu.me, any NWC-compatible wallet.

    NWC connection string format:
      nostr+walletconnect://<pubkey>?relay=<relay_url>&secret=<secret>
    """
    try:
        from pynostr.key import PrivateKey
        from pynostr.encrypted_dm import EncryptedDirectMessage
        import websockets
        import uuid
        import time
    except ImportError:
        raise ImportError(
            "NWC requires: pip install pynostr websockets\n"
            "Or install: pip install boltwork-mcp[nwc]"
        )

    match = re.match(
        r"nostr\+walletconnect://([0-9a-fA-F]+)\?.*relay=([^&]+).*secret=([0-9a-fA-F]+)",
        nwc_string
    )
    if not match:
        raise ValueError("Invalid NWC connection string format")

    wallet_pubkey_hex = match.group(1)
    relay_url         = match.group(2).rstrip("/")
    secret_hex        = match.group(3)

    client_privkey = PrivateKey(bytes.fromhex(secret_hex))
    client_pubkey  = client_privkey.public_key.hex()

    request_id = str(uuid.uuid4())
    payload    = json.dumps({
        "id":     request_id,
        "method": "pay_invoice",
        "params": {"invoice": invoice},
    })

    dm = EncryptedDirectMessage(
        recipient_pubkey=wallet_pubkey_hex,
        cleartext_content=payload,
    )
    dm.encrypt(client_privkey.hex())
    event = dm.to_event()
    event.sign(client_privkey.hex())

    timeout  = 30.0
    preimage = None

    try:
        connect_fn = websockets.connect
    except AttributeError:
        connect_fn = websockets.asyncio.client.connect

    async with connect_fn(relay_url) as ws:
        sub_id  = str(uuid.uuid4())[:8]
        sub_msg = json.dumps([
            "REQ", sub_id,
            {"kinds": [23195], "#p": [client_pubkey], "since": int(time.time()) - 5}
        ])
        await ws.send(sub_msg)
        await ws.send(json.dumps(["EVENT", event.to_dict()]))

        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                msg = json.loads(raw)
                if msg[0] == "EVENT" and msg[1] == sub_id:
                    ev = msg[2]
                    dm_resp = EncryptedDirectMessage.from_event_dict(ev)
                    dm_resp.decrypt(client_privkey.hex(), public_key_hex=wallet_pubkey_hex)
                    resp = json.loads(dm_resp.cleartext_content)
                    if resp.get("result_type") == "pay_invoice":
                        if "error" in resp:
                            raise RuntimeError(f"NWC payment failed: {resp['error']}")
                        preimage = resp["result"]["preimage"]
                        break
            except asyncio.TimeoutError:
                continue

    if not preimage:
        raise TimeoutError("NWC payment timed out after 30s")
    return preimage


# ---------------------------------------------------------------------------
# Phoenixd payment backend
# ---------------------------------------------------------------------------

async def pay_invoice_phoenixd(invoice: str, phoenixd_url: str, phoenixd_password: str) -> str:
    """
    Pay a Lightning invoice via Phoenixd REST API.
    Returns the payment preimage as a hex string.

    Phoenixd: https://phoenix.acinq.co/server
    Also works with hosted Phoenixd (ACINQ cloud).
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{phoenixd_url}/payinvoice",
            data={"invoice": invoice},
            auth=("", phoenixd_password),
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Phoenixd payment failed: HTTP {response.status_code} — {response.text[:200]}"
            )
        data = response.json()
        if "preimage" not in data:
            raise RuntimeError(f"Phoenixd response missing preimage: {data}")
        return data["preimage"]


# ---------------------------------------------------------------------------
# LNbits payment backend
# ---------------------------------------------------------------------------

async def pay_invoice_lnbits(invoice: str, lnbits_url: str, lnbits_api_key: str) -> str:
    """
    Pay a Lightning invoice via LNbits REST API.
    Returns the payment preimage as a hex string.

    LNbits: https://lnbits.com — self-hosted or use lnbits.com
    Use your wallet's Invoice/read key or Admin key.

    Setup:
      1. Create a wallet at lnbits.com or your self-hosted instance
      2. Go to API info and copy your Invoice key
      3. Set LNBITS_URL and LNBITS_API_KEY env vars
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{lnbits_url.rstrip('/')}/api/v1/payments",
            json={"out": True, "bolt11": invoice},
            headers={"X-Api-Key": lnbits_api_key, "Content-Type": "application/json"},
        )
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"LNbits payment failed: HTTP {response.status_code} — {response.text[:200]}"
            )
        data = response.json()
        # LNbits returns payment_hash; fetch preimage separately
        payment_hash = data.get("payment_hash")
        if not payment_hash:
            raise RuntimeError(f"LNbits response missing payment_hash: {data}")

        # Fetch payment details to get preimage
        details = await client.get(
            f"{lnbits_url.rstrip('/')}/api/v1/payments/{payment_hash}",
            headers={"X-Api-Key": lnbits_api_key},
        )
        if details.status_code != 200:
            raise RuntimeError(f"LNbits payment details fetch failed: {details.status_code}")
        detail_data = details.json()
        preimage = detail_data.get("details", {}).get("preimage") or detail_data.get("preimage")
        if not preimage:
            raise RuntimeError(f"LNbits response missing preimage: {detail_data}")
        return preimage


# ---------------------------------------------------------------------------
# Strike payment backend
# ---------------------------------------------------------------------------

async def pay_invoice_strike(invoice: str, strike_api_key: str) -> str:
    """
    Pay a Lightning invoice via Strike API.
    Returns the payment preimage as a hex string.

    Strike: https://strike.me — create an account and get an API key
    from dashboard.strike.me/developers/api-keys

    Note: Strike API is US-focused. International availability varies.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Create payment quote
        quote_resp = await client.post(
            "https://api.strike.me/v1/payment-quotes/lightning",
            json={"lnInvoice": invoice, "sourceCurrency": "USD"},
            headers={
                "Authorization": f"Bearer {strike_api_key}",
                "Content-Type": "application/json",
            },
        )
        if quote_resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Strike quote failed: HTTP {quote_resp.status_code} — {quote_resp.text[:200]}"
            )
        quote = quote_resp.json()
        quote_id = quote.get("paymentQuoteId")
        if not quote_id:
            raise RuntimeError(f"Strike response missing paymentQuoteId: {quote}")

        # Execute payment
        pay_resp = await client.patch(
            f"https://api.strike.me/v1/payment-quotes/{quote_id}/execute",
            headers={"Authorization": f"Bearer {strike_api_key}"},
        )
        if pay_resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Strike payment failed: HTTP {pay_resp.status_code} — {pay_resp.text[:200]}"
            )
        pay_data = pay_resp.json()

        # Strike doesn't return preimage directly — poll for it
        payment_id = pay_data.get("paymentId")
        if not payment_id:
            raise RuntimeError(f"Strike response missing paymentId: {pay_data}")

        for _ in range(10):
            await asyncio.sleep(1.0)
            status_resp = await client.get(
                f"https://api.strike.me/v1/payments/{payment_id}",
                headers={"Authorization": f"Bearer {strike_api_key}"},
            )
            if status_resp.status_code == 200:
                status_data = status_resp.json()
                if status_data.get("state") == "COMPLETED":
                    preimage = status_data.get("lightning", {}).get("preimage")
                    if preimage:
                        return preimage
                elif status_data.get("state") in ("FAILED", "CANCELLED"):
                    raise RuntimeError(f"Strike payment {status_data['state']}: {status_data}")

        raise TimeoutError("Strike payment did not complete within 10 seconds")


# ---------------------------------------------------------------------------
# Main payment dispatcher
# ---------------------------------------------------------------------------

async def pay_invoice(invoice: str) -> str:
    """
    Pay a Lightning invoice using the configured wallet backend.
    Returns the preimage as a hex string.

    Reads configuration from environment variables.
    Priority order: NWC → LNbits → Strike → Phoenixd

    NWC (Alby, Mutiny, Coinos, Primal, Cashu.me):
      NWC_CONNECTION_STRING=nostr+walletconnect://...

    LNbits (self-hosted or lnbits.com):
      LNBITS_URL=https://lnbits.com   (or your instance URL)
      LNBITS_API_KEY=your-invoice-key

    Strike (custodial, US-focused):
      STRIKE_API_KEY=your-api-key

    Phoenixd (self-hosted ACINQ node):
      PHOENIXD_URL=http://localhost:9740
      PHOENIXD_PASSWORD=your-password
    """
    nwc_string        = os.environ.get("NWC_CONNECTION_STRING", "").strip()
    lnbits_url        = os.environ.get("LNBITS_URL", "").strip()
    lnbits_api_key    = os.environ.get("LNBITS_API_KEY", "").strip()
    strike_api_key    = os.environ.get("STRIKE_API_KEY", "").strip()
    phoenixd_url      = os.environ.get("PHOENIXD_URL", "").strip()
    phoenixd_password = os.environ.get("PHOENIXD_PASSWORD", "").strip()

    if nwc_string:
        return await pay_invoice_nwc(invoice, nwc_string)
    elif lnbits_url and lnbits_api_key:
        return await pay_invoice_lnbits(invoice, lnbits_url, lnbits_api_key)
    elif strike_api_key:
        return await pay_invoice_strike(invoice, strike_api_key)
    elif phoenixd_url and phoenixd_password:
        return await pay_invoice_phoenixd(invoice, phoenixd_url, phoenixd_password)
    else:
        raise RuntimeError(
            "No wallet configured. Set one of:\n"
            "  NWC_CONNECTION_STRING=nostr+walletconnect://...      (Alby, Mutiny, Coinos)\n"
            "  LNBITS_URL=https://lnbits.com + LNBITS_API_KEY=...  (LNbits)\n"
            "  STRIKE_API_KEY=...                                    (Strike)\n"
            "  PHOENIXD_URL=http://localhost:9740 + PHOENIXD_PASSWORD=...  (Phoenixd)"
        )


# ---------------------------------------------------------------------------
# Full L402 request helper
# ---------------------------------------------------------------------------

async def l402_request(
    method: str,
    url: str,
    json_body: Optional[dict] = None,
    files: Optional[dict] = None,
) -> dict:
    """
    Make an L402-authenticated request.
    1. Sends request → if 402, pays invoice and retries with credentials
    2. Returns parsed JSON response
    """
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        kwargs = {}
        if json_body is not None:
            kwargs["json"] = json_body
        if files is not None:
            kwargs["files"] = files

        response = await client.request(method, url, **kwargs)

        if response.status_code == 200:
            return response.json()

        if response.status_code != 402:
            raise RuntimeError(
                f"Unexpected HTTP {response.status_code} from {url}: "
                f"{response.text[:300]}"
            )

        www_auth = response.headers.get("WWW-Authenticate", "")
        if not www_auth:
            raise RuntimeError("Got 402 but no WWW-Authenticate header")

        macaroon, invoice = parse_402(www_auth)
        preimage = await pay_invoice(invoice)

        auth_header = f"L402 {macaroon}:{preimage}"
        response2 = await client.request(
            method, url,
            headers={"Authorization": auth_header},
            **kwargs,
        )

        if response2.status_code != 200:
            raise RuntimeError(
                f"L402 retry failed: HTTP {response2.status_code} — "
                f"{response2.text[:300]}"
            )

        return response2.json()
