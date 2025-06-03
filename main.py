from fastapi import FastAPI, HTTPException
import xgboost
import numpy as np
import joblib
from pydantic import BaseModel
from typing import List, Optional
from utils import feature_engineering, DANGEROUS_PERMISSIONS

class AppData(BaseModel):
    package_name: str
    app_name: str
    permissions: List[str]
    sha256: Optional[str] = None
    app_size: Optional[int] = None
    install_source: Optional[str] = None
    app_category: Optional[str] = None

class RiskPrediction(BaseModel):
    risk_score: float
    risk_label: str

app = FastAPI(
    title="CyberGuardian ML Service",
    description="ML prediction service for Android application risk assessment",
    version="1.0.0"
)

# Load the pre-trained XGBoost model and dangerous permissions
try:
    # Correctly unpack the model and dangerous_permissions tuple
    model, dangerous_permissions = joblib.load("model.pkl")
except Exception as e:
    raise RuntimeError(f"Failed to load model: {str(e)}")

@app.get("/")
async def root():
    return {"message": "CyberGuardian ML Service is running"}

@app.post("/predict", response_model=RiskPrediction)
async def predict(app_data: AppData):
    try:
        # Log the raw payload
        import json
        print(f"Raw payload: {json.dumps(app_data.dict(), indent=2)}")

        # Extract and validate permissions
        permissions = app_data.permissions
        print(f"Received permissions: {permissions}")

        if not permissions:
            raise HTTPException(status_code=400, detail="No permissions provided")

        # Map permissions to dangerous permissions
        mapped_permissions = [p for p in permissions if p in dangerous_permissions]
        print(f"Mapped permissions: {mapped_permissions}")

        # Create feature vector
        features = feature_engineering(mapped_permissions)
        print(f"Feature vector: {features}")
        print(f"Feature vector size: {features.shape}")

        # Ensure features are in correct shape (1, n_features)
        features = np.array(features).reshape(1, -1)

        # Predict risk using the model
        risk_score = model.predict_proba(features)[0][1]  # Probability of 'Threat' class
        risk_label = "suspicious" if risk_score > 0.5 else "benign"

        return {
            "risk_score": float(risk_score),
            "risk_label": risk_label
        }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 