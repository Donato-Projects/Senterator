# 🛡️ Senterator — IoC Generator

An automated **Indicator of Compromise (IoC)** enrichment tool with a Matrix-themed Streamlit UI. Built as a 4-person team project for cybersecurity analysis of ELF binaries.

## 🔍 What It Does

1. **Local Analysis** — Extracts MD5/SHA1/SHA256/SHA512 hashes and flags suspicious imports from ELF binaries across 10 threat categories
2. **Threat Intelligence** — Cross-references file hashes against VirusTotal and MalwareBazaar
3. **Verdict Engine** — Applies weighted scoring to produce a confidence-rated threat verdict
4. **Full Report** — Generates downloadable JSON reports combining all analysis data

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/Donato-Projects/Senterator.git
cd senterator

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

## 📂 Project Structure

```
├── app.py              # Streamlit UI (4 tabs + Matrix rain animation)
├── integrator.py       # Switchboard — routes mock or real data to the UI
├── mock_data.py        # Simulated data for all 3 analysis modules
├── requirements.txt    # Python dependencies
└── README.md
```

## 🧱 Architecture

| Module | Owner | Role |
|--------|-------|------|
| **ELFAnalyzer** (Person 1) | Local binary parsing — hashes & suspicious imports |
| **Threat Intel** (Person 2) | API integration — VirusTotal & MalwareBazaar lookups |
| **Scoring Engine** (Person 3) | Weighted verdict — entropy, whitelisting, risk scoring |
| **Senterator UI** (Person 4) | Streamlit interface — visualization & report generation |

## 🛠️ Tech Stack

- **Python 3.11**
- **Streamlit** — Interactive web UI
- **Plotly** — Threat score gauge visualization
- **Pandas** — Data table display

## 👥 Team Senterator
