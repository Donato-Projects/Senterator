# 🛡️ Senterator — IoC Generator

An automated **Indicator of Compromise (IoC)** enrichment tool with a Matrix-themed Streamlit UI. Built as a 4-person team project for cybersecurity analysis of ELF binaries.

## 🔍 What It Does

1. **Local Analysis** — Extracts MD5/SHA1/SHA256/SHA512 hashes and flags suspicious imports from ELF binaries across 10 threat categories
2. **Threat Intelligence** — Cross-references file hashes against VirusTotal and MalwareBazaar APIs
3. **Verdict Engine** — Applies weighted scoring with false-positive reduction to produce a confidence-rated threat verdict
4. **Full Report** — Generates downloadable JSON reports combining all analysis data

## 🌐 Live Demo

**Skip the setup — try it instantly in your browser:**

👉 **[https://senterator.streamlit.app](https://senterator.streamlit.app)**

Upload an ELF binary or click **⚡ Use Sample Data** to explore the full analysis pipeline.

---

## 🚀 Run Locally

```bash
# Clone the repo
git clone https://github.com/Donato-Projects/Senterator.git
cd Senterator

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

Once running, Streamlit will open a local URL (default: `http://localhost:8501`) in your browser.

### 🔑 API Keys (Optional — for live threat intel)

The threat intelligence module queries **VirusTotal** and **MalwareBazaar**. To use live lookups, set the following environment variables before launching the app:

```bash
export VT_API_KEY="your-virustotal-api-key"
export MB_API_KEY="your-malwarebazaar-api-key"
```

> **Note:** The app works without API keys — just click **⚡ Use Sample Data** in the sidebar to explore the UI with mock data.

## 📂 Project Structure

```
├── app.py              # Streamlit UI (4 tabs + Matrix rain animation)
├── integrator.py       # Switchboard — routes mock or real data to the UI
├── local_analysis.py   # ELF binary parser — hashes & suspicious imports
├── threat_intel.py     # VirusTotal & MalwareBazaar API lookups
├── verdict.py          # Weighted scoring engine & false-positive reduction
├── mock_data.py        # Simulated data for demo / offline testing
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md
```

## 🧱 Architecture

| Module | Owner | Role |
|--------|-------|------|
| `local_analysis.py` | Person 1 | ELF binary parsing — hashes & suspicious import detection |
| `threat_intel.py` | Person 2 | API integration — VirusTotal & MalwareBazaar lookups |
| `verdict.py` | Person 3 | Weighted verdict — entropy scoring, whitelisting, false-positive reduction |
| `app.py` | Person 4 | Streamlit interface — Matrix-themed visualization & report generation |
| `integrator.py` | Person 4 | Switchboard — routes mock or real data to the UI |

### Data Flow

```
ELF Binary Upload
       │
       ▼
┌──────────────┐    ┌──────────────┐
│ local_analysis│    │ threat_intel │
│   (Person 1)  │    │  (Person 2)  │
└──────┬───────┘    └──────┬───────┘
       │                   │
       ▼                   ▼
      ┌─────────────────────┐
      │   integrator.py     │
      │   (Switchboard)     │
      └─────────┬───────────┘
                │
                ▼
        ┌───────────────┐
        │  verdict.py   │
        │  (Person 3)   │
        └───────┬───────┘
                │
                ▼
        ┌───────────────┐
        │    app.py     │
        │  (Streamlit)  │
        └───────────────┘
```

## 🛠️ Tech Stack

- **Python 3.11+**
- **Streamlit** — Interactive web UI
- **Plotly** — Threat score gauge visualization
- **Pandas** — Data table display
- **Requests** — HTTP client for API calls

## 💡 Usage

| Action | How |
|--------|-----|
| **Demo mode** | Click **⚡ Use Sample Data** in the sidebar |
| **Live analysis** | Upload an ELF binary → click **🔍 Analyze Uploaded Binary** |
| **Download report** | Go to the **📄 Full Report** tab → click **⬇️ Download Full Report (JSON)** |

## 👥 Team Senterator
