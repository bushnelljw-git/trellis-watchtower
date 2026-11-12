"""trellis-watchtower's synthetic journeys (bodyfirst tasks/reliability/SYNTHETICS-DESIGN.md §3).

One Cloud Run job per journey runs `python -I -m synthetics journey <name>` on
Cloud Scheduler; each run writes exactly one result line (result.py) to stdout
and nothing else. The standard library, and `cryptography` in passkey.py alone (the member sign-in robot's
passkey; synthetics/requirements.lock). Importing the package does nothing.
"""

__all__ = ["client", "iap", "journeys", "passkey", "result", "totp"]
