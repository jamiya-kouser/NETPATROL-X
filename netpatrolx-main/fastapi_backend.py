#!/usr/bin/env python3
"""
FastAPI backend for NetPatrolX Demo
Provides endpoints for single and batch prediction
"""

import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import joblib
import numpy as np
import pandas as pd
from io import StringIO
import tempfile
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    load_model()
    yield
    # Shutdown (if needed)
    pass

app = FastAPI(title="NetPatrolX API", version="1.0.0", lifespan=lifespan)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model
MODEL_PATH = "./out/global_model.pkl"
model_data = None

def load_model():
    global model_data
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
    model_data = joblib.load(MODEL_PATH)
    print(f"Loaded model from {MODEL_PATH}")

# Model loading is now handled by lifespan manager

class PredictionRequest(BaseModel):
    data: dict

def predict_single(data_dict):
    """Predict single flow using the loaded model"""
    coef = np.array(model_data["coef"])
    intercept = float(model_data["intercept"])
    scaler = model_data["scaler"]
    features = model_data["features"]

    # Build feature vector
    x_raw = [data_dict.get(f, 0.0) for f in features]
    Xs = scaler.transform([x_raw])[0]
    
    # Calculate prediction
    logit = Xs.dot(coef) + intercept
    probability = float(1 / (1 + np.exp(-logit)))
    
    # Calculate feature contributions
    contributions = Xs * coef
    feature_contributions = list(zip(features, contributions))
    feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
    
    top_contributors = feature_contributions[:3]  # Top 3 contributors
    
    return {
        "probability": probability,
        "contributions": dict(feature_contributions),
        "top_contributors": top_contributors
    }

@app.post("/predict")
async def predict_single_flow(request: PredictionRequest):
    """Predict malicious probability for a single flow"""
    try:
        result = predict_single(request.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/predict_batch")
async def predict_batch_flows(file: UploadFile = File(...)):
    """Predict malicious probability for batch of flows from CSV"""
    try:
        # Read CSV content
        content = await file.read()
        csv_content = content.decode('utf-8')
        
        # Parse CSV
        df = pd.read_csv(StringIO(csv_content))
        
        results = []
        for _, row in df.iterrows():
            try:
                result = predict_single(row.to_dict())
                results.append(result)
            except Exception as e:
                # If individual prediction fails, add error result
                results.append({
                    "probability": None,
                    "contributions": {},
                    "top_contributors": [],
                    "error": str(e)
                })
        
        return {"results": results}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Batch prediction failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "model_loaded": model_data is not None}

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "message": "NetPatrolX API",
        "version": "1.0.0",
        "endpoints": {
            "POST /predict": "Single flow prediction",
            "POST /predict_batch": "Batch CSV prediction",
            "GET /health": "Health check",
            "GET /docs": "API documentation"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
