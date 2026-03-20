"""
mock_data.py — The Fake Data Layer for Senterator
===================================================
This module provides realistic dummy data that mimics what each
teammate's module will eventually produce.

WHY: So we can build and test the entire UI without waiting
for Persons 1, 2, and 3 to finish their code.

HOW: Each function returns a Python dictionary (which is basically
a JSON object) that matches the agreed-upon "JSON contract."
"""

from datetime import datetime


def get_mock_local_analysis():
    """
    Simulates Person 1's ELFAnalyzer output.
    
    This matches the EXACT format from amrutamali6/ElfAnalyzer's
    export_json() function. We know this because we read their code!
    
    Returns a dictionary with:
    - report_generated: timestamp of when the analysis ran
    - file: full path to the binary that was analyzed
    - filename: just the filename (no path)
    - hashes: MD5, SHA1, SHA256, SHA512 of the file
    - suspicious_imports: categorized suspicious strings found
    """
    return {
        "report_generated": datetime.now().isoformat(),
        "file": "/samples/malware/suspicious_binary.elf",
        "filename": "suspicious_binary.elf",
        "hashes": {
            "MD5":    "d41d8cd98f00b204e9800998ecf8427e",
            "SHA1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        },
        "suspicious_imports": {
            "total_hits": 18,
            "categories_flagged": 6,
            "matches": {
                "Shell Execution": [
                    "system", "execve", "popen"
                ],
                "Network": [
                    "socket", "connect", "bind", "send", "recv",
                    "gethostbyname"
                ],
                "File Manipulation": [
                    "unlink", "chmod", "rename"
                ],
                "Memory Manipulation": [
                    "mmap", "mprotect"
                ],
                "Process Manipulation": [
                    "fork", "kill"
                ],
                "Obfuscation / Injection": [
                    "dlopen", "dlsym"
                ],
            }
        }
    }


def get_mock_threat_intel():
    """
    Simulates Person 2's API Integration output.
    
    This is what comes back after checking the file's hash
    against VirusTotal and MalwareBazaar.
    
    Returns a dictionary with:
    - source: which threat intel service responded
    - sha256: the hash that was looked up  
    - detection_score: "X/Y" format (X engines flagged it out of Y total)
    - malware_family: the name/type of malware (if identified)
    - tags: descriptive labels from the threat intel feed
    - detection_engines: list of which antivirus engines flagged it
    """
    return {
        "source": "VirusTotal",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detection_score": "38/70",
        "malware_family": "Mirai",
        "tags": ["botnet", "iot", "linux", "ddos"],
        "first_seen": "2025-11-15T08:32:00Z",
        "detection_engines": [
            {"engine": "ClamAV",       "result": "Linux.Mirai.Gen"},
            {"engine": "Kaspersky",    "result": "HEUR:Backdoor.Linux.Mirai.b"},
            {"engine": "ESET",         "result": "Linux/Mirai.A"},
            {"engine": "Sophos",       "result": "Linux/DDoS-CIA"},
            {"engine": "BitDefender",  "result": "Trojan.Linux.Mirai.A"},
            {"engine": "Avira",        "result": "LINUX/Mirai.lnmoe"},
            {"engine": "McAfee",       "result": "Linux/Mirai.a"},
            {"engine": "TrendMicro",   "result": "ELF_MIRAI.SM"},
        ]
    }


def get_mock_verdict():
    """
    Simulates Person 3's Scoring & Filtering output.
    
    This is the "judge" — it takes Person 1 and Person 2's data,
    applies smart logic (entropy, whitelisting, weighted scores),
    and gives a final verdict.
    
    Returns a dictionary with:
    - verdict: "Malicious", "Suspicious", or "Clean"
    - confidence: 0-100 score of how certain the verdict is
    - risk_factors: list of reasons that contributed to the score
    - recommendation: what action to take
    """
    return {
        "verdict": "Malicious",
        "confidence": 87,
        "risk_factors": [
            {
                "factor": "High VirusTotal Detection Rate",
                "weight": 35,
                "detail": "38 out of 70 engines flagged this file"
            },
            {
                "factor": "Known Malware Family Match",
                "weight": 25,
                "detail": "Identified as Mirai botnet variant"
            },
            {
                "factor": "Suspicious Network Imports",
                "weight": 15,
                "detail": "6 network-related functions (socket, connect, bind, send, recv, gethostbyname)"
            },
            {
                "factor": "Shell Execution Capabilities",
                "weight": 7,
                "detail": "Contains system(), execve(), and popen() calls"
            },
            {
                "factor": "Process Manipulation",
                "weight": 5,
                "detail": "Uses fork() and kill() — common in malware for persistence"
            },
        ],
        "recommendation": "QUARANTINE — Do not execute. Forward to incident response team."
    }
