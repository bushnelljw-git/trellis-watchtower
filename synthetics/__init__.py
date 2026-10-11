"""trellis-watchtower's synthetic journeys (bodyfirst tasks/reliability/SYNTHETICS-DESIGN.md §3).

One Cloud Run job per journey runs `python -I -m synthetics journey <name>` on
Cloud Scheduler; each run writes exactly one result line (result.py) to stdout
and nothing else. Standard library only. Importing the package does nothing.
"""

__all__ = ["client", "iap", "journeys", "result", "totp"]
