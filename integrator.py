"""
integrator.py — The Switchboard for Senterator
================================================
This module is the ONLY place the UI (app.py) gets its data from.
It acts as a "middleman" between the UI and the data sources.

WHY:  The UI shouldn't care whether data is fake (mock) or real
      (from teammates' code). By routing everything through here,
      swapping mock → real is literally flipping one variable.

HOW:  The USE_MOCK_DATA flag below controls everything.
      - True  = use fake data from mock_data.py (for testing)
      - False = use real modules from teammates (after they finish)
"""

# ============================================================
# THE SWITCH — Flip this to False when real modules are ready
# ============================================================
USE_MOCK_DATA = True


# ============================================================
# Import the data sources
# ============================================================
if USE_MOCK_DATA:
    # We're in testing mode — use our fake data
    from mock_data import (
        get_mock_local_analysis,
        get_mock_threat_intel,
        get_mock_verdict,
    )
else:
    # TODO: When teammates finish, import their real modules here
    # Example (uncomment and adjust when ready):
    # from elfanalyzer import compute_hashes, extract_suspicious_imports
    # from threat_intel import lookup_virustotal
    # from scoring_engine import calculate_verdict
    pass


# ============================================================
# Functions that the UI calls
# ============================================================
# The UI (app.py) will ONLY call these three functions.
# It never talks to mock_data.py or teammate modules directly.
# That way, we can change what's "under the hood" without
# touching a single line of UI code.
# ============================================================

def run_local_analysis(filepath=None):
    """
    Get local analysis results (hashes + suspicious imports).
    
    Args:
        filepath: Path to the binary file to analyze.
                  Ignored when using mock data.
    
    Returns:
        dict: Analysis results matching Person 1's JSON format.
    """
    if USE_MOCK_DATA:
        return get_mock_local_analysis()
    else:
        # TODO: Call Person 1's real code here
        # Example:
        # hashes = compute_hashes(filepath)
        # suspicious = extract_suspicious_imports(filepath)
        # return {"hashes": hashes, "suspicious_imports": suspicious, ...}
        pass


def run_threat_intel(sha256_hash=None):
    """
    Get threat intelligence results from VirusTotal / MalwareBazaar.
    
    Args:
        sha256_hash: The SHA256 hash to look up.
                     Ignored when using mock data.
    
    Returns:
        dict: Threat intel results matching Person 2's JSON format.
    """
    if USE_MOCK_DATA:
        return get_mock_threat_intel()
    else:
        # TODO: Call Person 2's real code here
        # Example:
        # return lookup_virustotal(sha256_hash)
        pass


def run_verdict(local_data=None, threat_data=None):
    """
    Get the final verdict (scoring + filtering).
    
    Args:
        local_data:  Results from run_local_analysis()
        threat_data: Results from run_threat_intel()
                     Both ignored when using mock data.
    
    Returns:
        dict: Verdict results matching Person 3's JSON format.
    """
    if USE_MOCK_DATA:
        return get_mock_verdict()
    else:
        # TODO: Call Person 3's real code here
        # Example:
        # return calculate_verdict(local_data, threat_data)
        pass
