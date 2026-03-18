# AI-Powered SOC Analyst Assistant
### EC6301 Mini Project

**Team:** Herath H.M.T.B | Hettiarachchi H.A.K.G | Fernando N.D.H | [Member 4]

An intelligent SOC dashboard that uses AI to filter noise, classify threats, and provide role-based playbooks.

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Setup Gemini API (Optional)
1. Go to [Google AI Studio](https://aistudio.google.com)
2. Create a free API key
3. Create `.env` file: `GEMINI_API_KEY=your_key_here`

## Project Structure
- `app.py` — Main Streamlit dashboard
- `modules/` — AI components (expert system, severity engine, playbooks, Gemini)
- `data/` — Sample datasets
- `models/` — Trained models (place here after Colab training)
- `notebooks/` — Model training instructions

## AI Components
- **Expert System** — Rule-based threat classification + MITRE ATT&CK mapping
- **Severity Engine** — Low/Medium/High/Critical scoring
- **Playbook Engine** — L1/L2/L3 role-based response guidance
- **Gemini AI** — Plain-English incident summaries
