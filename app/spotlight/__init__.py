"""CrowdStrike Spotlight ingest.

Three layers, kept separate on purpose:

    client.py   talks to the Falcon API and returns raw dicts
    ingest.py   normalizes those dicts into the staging tables
    elevate.py  turns staged findings into a Risk in the register

The split means the normalizer can be tested against a saved payload with no
network and no credentials, and the elevation logic can be tested with no
CrowdStrike involvement at all.
"""
