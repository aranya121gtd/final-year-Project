# Multi-Agent Threat Detection Pipeline — Serving Project

FastAPI serving layer for the three-agent + weighted-coordinator pipeline (Spam Agent,
Packet Agent, IP/Session Agent). Trained model artifacts are already included in
`artifacts/`, exported from the training notebook.

## Project layout

```
.
├── app.py                       # FastAPI app — loads artifacts, exposes REST endpoints
├── requirements.txt
├── .vscode/
│   └── launch.json              # F5 in VS Code runs uvicorn with the debugger attached
└── artifacts/
    ├── spam_agent.joblib            # TF-IDF + Logistic Regression
    ├── spam_vectorizer.joblib       # fitted TF-IDF vectorizer for the spam agent
    ├── packet_agent.joblib          # Random Forest (network flow)
    ├── session_agent.joblib         # Random Forest (session/payment behavior)
    └── coordinator_config.joblib    # weights, thresholds, feature-column order
```

## Setup (VS Code)

1. Open this folder in VS Code (`File → Open Folder…`).
2. Create and select a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
   In VS Code, pick this interpreter via `Ctrl/Cmd+Shift+P → Python: Select Interpreter`.
3. Run it either way:
   - **Debugger**: press `F5` (uses `.vscode/launch.json`, already configured).
   - **Terminal**: `uvicorn app:app --reload --host 0.0.0.0 --port 8000`

The app reads artifacts from `./artifacts` by default (override with the `ARTIFACT_DIR`
environment variable if you move them).

## Try it

Interactive API docs: http://localhost:8000/docs

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/score/case \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "URGENT: verify your account now",
    "flow_features": {"packet_count": 900, "avg_packet_size": 90, "flow_duration_s": 3,
                       "unique_dst_ports": 42, "syn_flag_ratio": 0.88, "bytes_per_second": 48000},
    "session_features": {"session_duration_s": 50, "num_transactions": 10, "avg_transaction_amount": 500,
                          "failed_login_attempts": 5, "ip_reputation_score": 0.15, "country_mismatch": 1, "new_device": 1}
  }'
```

`score/case` accepts any subset of `email_text`, `flow_features`, `session_features` — weights
are renormalized over whichever agents you supply. Response:

```json
{
  "agent_scores": {"spam": 0.90, "packet": 1.0, "session": 1.0},
  "elevated_votes": 3,
  "weighted_score": 0.97,
  "base_level": "Critical",
  "escalated": true,
  "final_level": "Critical"
}
```

## Endpoints

| Method | Path            | Body                              |
|---|---|---|
| GET  | `/health`         | —                                       |
| POST | `/score/email`    | `{"email_text": "..."}`                 |
| POST | `/score/flow`     | `{"flow_features": {...}}`              |
| POST | `/score/session`  | `{"session_features": {...}}`           |
| POST | `/score/case`     | any combination of the three above      |

## Notes

- These agents were trained on **synthetic** data (see the companion notebook) — retrain on
  real logs before using this in production, and re-run threshold tuning (ROC/PR curves) on
  real validation data.
- Coordinator weights and thresholds live in `artifacts/coordinator_config.joblib`; regenerate
  it from the notebook if you change `AGENT_WEIGHTS`, `ELEVATED_THRESHOLDS`, or `LEVEL_THRESHOLDS`.
