"""
Multi-Agent Cyber Threat Detection System
FastAPI Serving Layer

Agents:
1. Spam / Email Agent
2. Packet / Flow Agent
3. Session Agent
4. Coordinator
"""

import os
from typing import Optional, Dict

import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ============================================================
# ARTIFACT DIRECTORY
# ============================================================

ARTIFACT_DIR = os.environ.get(
    "ARTIFACT_DIR",
    "artifacts"
)


# ============================================================
# LOAD ARTIFACT FUNCTION
# ============================================================

def load_artifact(filename: str):

    path = os.path.join(
        ARTIFACT_DIR,
        filename
    )

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Artifact not found: {path}"
        )

    print(f"Loading: {path}")

    return joblib.load(path)


# ============================================================
# LOAD MODELS
# ============================================================

spam_agent = load_artifact(
    "spam_agent.joblib"
)

spam_vectorizer = load_artifact(
    "spam_vectorizer.joblib"
)

packet_agent = load_artifact(
    "packet_agent.joblib"
)

session_agent = load_artifact(
    "session_agent.joblib"
)

config = load_artifact(
    "coordinator_config.joblib"
)


# ============================================================
# LOAD CONFIG
# ============================================================

AGENT_WEIGHTS = config["AGENT_WEIGHTS"]

ELEVATED_THRESHOLDS = config["ELEVATED_THRESHOLDS"]

LEVEL_THRESHOLDS = config["LEVEL_THRESHOLDS"]

FLOW_FEATURES = config["FLOW_FEATURES"]

SESSION_FEATURES = config["SESSION_FEATURES"]


LEVEL_ORDER = [
    "Low",
    "Medium",
    "High",
    "Critical"
]


# ============================================================
# PRINT CONFIGURATION
# ============================================================

print("\n==========================================")
print("MULTI-AGENT THREAT DETECTION API")
print("==========================================")

print("\nFLOW FEATURES:")
print(FLOW_FEATURES)

print("\nSESSION FEATURES:")
print(SESSION_FEATURES)

print("\nAGENT WEIGHTS:")
print(AGENT_WEIGHTS)

print("\nELEVATED THRESHOLDS:")
print(ELEVATED_THRESHOLDS)

print("\nLEVEL THRESHOLDS:")
print(LEVEL_THRESHOLDS)

print("==========================================\n")


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Multi-Agent Threat Detection Pipeline",
    description="AI Multi-Agent Cyber Threat Detection API",
    version="1.0.0"
)


# ============================================================
# REQUEST MODELS
# ============================================================

class EmailRequest(BaseModel):

    email_text: str


class FlowRequest(BaseModel):

    flow_features: Dict[str, float]


class SessionRequest(BaseModel):

    session_features: Dict[str, float]


class CaseRequest(BaseModel):

    email_text: Optional[str] = None

    flow_features: Optional[Dict[str, float]] = None

    session_features: Optional[Dict[str, float]] = None


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "Multi-Agent Threat Detection Pipeline is running",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
        "features": "/features"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "models_loaded": True
    }


# ============================================================
# SHOW FEATURES
# ============================================================

@app.get("/features")
def get_features():

    return {

        "flow_features": list(
            FLOW_FEATURES
        ),

        "session_features": list(
            SESSION_FEATURES
        ),

        "agent_weights": AGENT_WEIGHTS,

        "elevated_thresholds": ELEVATED_THRESHOLDS,

        "level_thresholds": LEVEL_THRESHOLDS
    }


# ============================================================
# FEATURE VALIDATION
# ============================================================

def validate_features(
    provided_features,
    expected_features,
    agent_name
):

    if provided_features is None:

        raise ValueError(
            f"{agent_name}: feature data is missing."
        )

    missing = [
        feature
        for feature in expected_features
        if feature not in provided_features
    ]

    if missing:

        raise ValueError(
            f"{agent_name}: missing features: {missing}. "
            f"Expected features: {list(expected_features)}"
        )


# ============================================================
# CREATE DATAFRAME
# ============================================================

def make_dataframe(
    features,
    expected_features,
    agent_name
):

    validate_features(
        features,
        expected_features,
        agent_name
    )

    # Create DataFrame
    df = pd.DataFrame([features])

    # Select exact training columns
    df = df[list(expected_features)]

    # Convert everything to numeric
    df = df.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Check for NaN
    if df.isnull().any().any():

        bad_columns = df.columns[
            df.isnull().any()
        ].tolist()

        raise ValueError(
            f"{agent_name}: non-numeric or invalid "
            f"values found in: {bad_columns}"
        )

    return df


# ============================================================
# EMAIL AGENT
# ============================================================

def spam_agent_score(text: str):

    if text is None:

        raise ValueError(
            "Email text cannot be None."
        )

    if not text.strip():

        raise ValueError(
            "Email text cannot be empty."
        )

    try:

        vectorized = spam_vectorizer.transform(
            [text]
        )

        probability = spam_agent.predict_proba(
            vectorized
        )

        return float(
            probability[0][1]
        )

    except Exception as e:

        raise ValueError(
            f"Spam Agent prediction failed: {str(e)}"
        )


# ============================================================
# FLOW / PACKET AGENT
# ============================================================

def packet_agent_score(
    flow_features
):

    print("\n========== FLOW AGENT ==========")

    print("Received features:")
    print(flow_features)

    print("\nExpected features:")
    print(FLOW_FEATURES)

    # Validate
    validate_features(
        flow_features,
        FLOW_FEATURES,
        "Flow Agent"
    )

    # Create DataFrame
    row = make_dataframe(
        flow_features,
        FLOW_FEATURES,
        "Flow Agent"
    )

    print("\nModel input:")
    print(row)

    print("\nModel input shape:")
    print(row.shape)

    try:

        probability = packet_agent.predict_proba(
            row
        )

        print("\nPrediction probability:")
        print(probability)

        score = float(
            probability[0][1]
        )

        print("\nFlow score:")
        print(score)

        return score

    except Exception as e:

        print("\nFLOW MODEL ERROR:")
        print(repr(e))

        raise ValueError(
            f"Flow Agent model prediction failed: {repr(e)}"
        )


# ============================================================
# SESSION AGENT
# ============================================================

def session_agent_score(
    session_features
):

    print("\n========== SESSION AGENT ==========")

    print("Received features:")
    print(session_features)

    print("\nExpected features:")
    print(SESSION_FEATURES)

    validate_features(
        session_features,
        SESSION_FEATURES,
        "Session Agent"
    )

    row = make_dataframe(
        session_features,
        SESSION_FEATURES,
        "Session Agent"
    )

    print("\nModel input:")
    print(row)

    try:

        probability = session_agent.predict_proba(
            row
        )

        score = float(
            probability[0][1]
        )

        print("\nSession score:")
        print(score)

        return score

    except Exception as e:

        print("\nSESSION MODEL ERROR:")
        print(repr(e))

        raise ValueError(
            f"Session Agent model prediction failed: {repr(e)}"
        )


# ============================================================
# SCORE TO LEVEL
# ============================================================

def score_to_level(score):

    for threshold, level in LEVEL_THRESHOLDS:

        if score >= threshold:

            return level

    return "Low"


# ============================================================
# BUMP LEVEL
# ============================================================

def bump_level(
    level,
    minimum
):

    current = LEVEL_ORDER.index(
        level
    )

    required = LEVEL_ORDER.index(
        minimum
    )

    if current >= required:

        return level

    return minimum


# ============================================================
# COORDINATOR
# ============================================================

def coordinator(
    spam_score=None,
    packet_score=None,
    session_score=None
):

    raw = {

        "spam": spam_score,

        "packet": packet_score,

        "session": session_score

    }

    present = {

        key: value

        for key, value in raw.items()

        if value is not None

    }

    if not present:

        raise ValueError(
            "At least one agent score must be provided."
        )

    # Check weights
    for key in present:

        if key not in AGENT_WEIGHTS:

            raise ValueError(
                f"Missing weight for agent: {key}"
            )

    total_weight = sum(
        AGENT_WEIGHTS[key]
        for key in present
    )

    if total_weight == 0:

        raise ValueError(
            "Total agent weight is zero."
        )

    weighted_score = (

        sum(
            present[key] *
            AGENT_WEIGHTS[key]

            for key in present
        )

        / total_weight

    )

    elevated_votes = sum(

        1

        for key, value in present.items()

        if value >= ELEVATED_THRESHOLDS[key]

    )

    base_level = score_to_level(
        weighted_score
    )

    escalated = (
        elevated_votes >= 2
    )

    if escalated:

        final_level = bump_level(
            base_level,
            "High"
        )

    else:

        final_level = base_level

    return {

        "agent_scores": {

            key: round(
                value,
                4
            )

            for key, value in present.items()

        },

        "elevated_votes":
            elevated_votes,

        "weighted_score":
            round(
                weighted_score,
                4
            ),

        "base_level":
            base_level,

        "escalated":
            escalated,

        "final_level":
            final_level

    }


# ============================================================
# SCORE EMAIL
# ============================================================

@app.post("/score/email")
def score_email(
    req: EmailRequest
):

    try:

        score = spam_agent_score(
            req.email_text
        )

        return {

            "spam_score":
                round(
                    score,
                    4
                )

        }

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Email Agent error: {repr(e)}"
        )


# ============================================================
# SCORE FLOW
# ============================================================

@app.post("/score/flow")
def score_flow(
    req: FlowRequest
):

    try:

        score = packet_agent_score(
            req.flow_features
        )

        return {

            "packet_score":
                round(
                    score,
                    4
                )

        }

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Flow Agent error: {repr(e)}"
        )


# ============================================================
# SCORE SESSION
# ============================================================

@app.post("/score/session")
def score_session(
    req: SessionRequest
):

    try:

        score = session_agent_score(
            req.session_features
        )

        return {

            "session_score":
                round(
                    score,
                    4
                )

        }

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Session Agent error: {repr(e)}"
        )


# ============================================================
# SCORE COMPLETE CASE
# ============================================================

@app.post("/score/case")
def score_case(
    req: CaseRequest
):

    try:

        spam_score = None

        packet_score = None

        session_score = None


        # ----------------------------------------
        # EMAIL
        # ----------------------------------------

        if req.email_text is not None:

            spam_score = spam_agent_score(
                req.email_text
            )


        # ----------------------------------------
        # FLOW
        # ----------------------------------------

        if req.flow_features is not None:

            packet_score = packet_agent_score(
                req.flow_features
            )


        # ----------------------------------------
        # SESSION
        # ----------------------------------------

        if req.session_features is not None:

            session_score = session_agent_score(
                req.session_features
            )


        # ----------------------------------------
        # COORDINATOR
        # ----------------------------------------

        result = coordinator(

            spam_score=spam_score,

            packet_score=packet_score,

            session_score=session_score

        )

        return result


    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Coordinator error: {repr(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
