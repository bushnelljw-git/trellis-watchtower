"""The ID token IAP reads, from the metadata server, as the job's own service account.

Design §3: `sa-synthetics` mints an OIDC ID token whose audience is IAP's OAuth
client id (`var.iap_oauth_client_id`, R298's External client, which IAP on the
portal, ops and CRM backends already uses) with `format=full`, and sends it in
`Proxy-Authorization: Bearer` (client.Session).

The request is Cloud Run's documented metadata call:

    GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
        ?audience=<audience>&format=full
    Metadata-Flavor: Google

never through a proxy and never following a redirect. The answer is the token
itself (a JWT, three base64url segments), held in memory for this run only and
never written anywhere. `SYNTHETICS_METADATA_HOST` exists for the tests' fake
metadata server; the job leaves it unset.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request

from synthetics import client

METADATA_HOST = "metadata.google.internal"
IDENTITY_PATH = "/computeMetadata/v1/instance/service-accounts/default/identity"
#: A JWT: three base64url segments. Anything else is not used as a token.
JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
MAX_TOKEN = 8 * 1024


def fetch_id_token(audience: str, *, host: str = METADATA_HOST, timeout: float) -> str:
    """The token, or `StepFailure("iap_token")` with the metadata server's status: the
    run's `error` (the job's own environment failed, not the site)."""
    query = urllib.parse.urlencode({"audience": audience, "format": "full"})
    request = urllib.request.Request(
        f"http://{host}{IDENTITY_PATH}?{query}",
        headers={"Metadata-Flavor": "Google", "User-Agent": client.USER_AGENT},
        method="GET",
    )
    try:
        response = client.send(client.opener(None), request, timeout=timeout)
    except client.StepFailure as failed:
        raise client.StepFailure("iap_token", failed.status) from None
    if response.status != 200:
        raise client.StepFailure("iap_token", response.status)
    try:
        token = response.body.decode("ascii").strip()
    except UnicodeDecodeError:
        raise client.StepFailure("iap_token", response.status) from None
    if len(token) > MAX_TOKEN or not JWT.match(token):
        raise client.StepFailure("iap_token", response.status)
    return token
