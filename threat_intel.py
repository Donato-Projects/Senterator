import os
import requests
import json
import time
from datetime import datetime, timezone

VT_API_KEY = os.getenv("VT_API_KEY")
MB_API_KEY = os.getenv("MB_API_KEY")

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attrs= data["data"]["attributes"]

        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        first_submission_date = attrs.get("first_submission_date")

        detection_engines = []
        for engine_name, engine_data in results.items():
            result_text = engine_data.get("result")

            if result_text:
                detection_engines.append({
                     "engine": engine_name,
                     "result": result_text
                })

        first_seen_iso = None
        if first_submission_date:
            first_seen_iso = datetime.fromtimestamp(
                first_submission_date,
                tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "sha256": file_hash,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "first_seen": first_seen_iso,
            "detection_engines": detection_engines,
            "link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }

    elif response.status_code == 404:
        return {
            "status": "not_found",
            "message": "Hash not found in VirusTotal"
        }

    else:
        return {
            "status": "error",
            "code": response.status_code
        }


def check_malwarebazaar(file_hash):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": MB_API_KEY
    }

    data = {
        "query": "get_info",
        "hash": file_hash
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()

        if result.get("query_status") == "ok":
            sample = result["data"][0]
            return {
                "status": "found",
                "signature": sample.get("signature"),
                "tags": sample.get("tags", [])
            }

        elif result.get("query_status") == "hash_not_found":
            return {
                "status": "not_found",
                "message": "Hash not found in MalwareBazaar"
            }

        elif result.get("query_status") == "illegal_hash":
            return {
                "status": "error",
                "message": "Invalid hash format"
            }

        else:
            return {
                "status": "error",
                "message": result.get("query_status")
            }

    return {
        "status": "error",
        "code": response.status_code
    }

def build_final_report(file_hash):
    vt = check_virustotal(file_hash)
    time.sleep(15)
    mb = check_malwarebazaar(file_hash)

    if vt.get("status") == "not_found":
        return {
            "source": "VirusTotal",
            "sha256": file_hash,
            "status": "not_found",
            "message": "Hash not found in VirusTotal"
        }
    malware_family = None
    tags = []

    if mb.get("status") == "found":
       malware_family = mb.get("signature")
       tags = mb.get("tags", [])


    detection_score = f'{vt.get("malicious_votes",0)}/{vt.get("total_engines",0)}'

    return {
        "source": "VirusTotal",
        "sha256": file_hash,
        "detection_score": detection_score,
        "malware_family": malware_family,
        "tags": tags,
        "first_seen": vt.get("first_seen"),
        "detection_engines": vt.get("detection_engines", [])
    }


if __name__ == "__main__":
    file_hash = input("Enter SHA-256 hash: ")
    report = build_final_report(file_hash)

    print(json.dumps(report, indent=2))
