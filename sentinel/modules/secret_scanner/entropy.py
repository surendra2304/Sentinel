"""Shannon entropy calculation for high-entropy secret detection."""

from __future__ import annotations

import math
from collections import Counter


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.

    Higher values (e.g. > 3.0 for alphanumeric strings) indicate higher randomness,
    which is characteristic of cryptographic keys, hashes, and API secrets.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)
