#!/usr/bin/env python3
"""Shared version contract for local packaging and GitHub publication."""

import re
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: validate-release-tag.py VERSION")

match = re.fullmatch(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
    sys.argv[1],
)
if not match or any(
    part.isdigit() and len(part) > 1 and part[0] == "0"
    for part in (match[4] or "").split(".")
):
    sys.exit(
        "Expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease "
        "(no leading zeroes or build metadata)"
    )
