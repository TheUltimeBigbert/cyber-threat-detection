import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import logging
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load trained model (now the SVM model with 10 features)
model = joblib.load("ml_model/svm_model_top_10.pkl")

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="dataset"), name="static")

# Define request and response models
class Features(BaseModel):
    features: list

@app.post("/predict")
async def predict(features: Features):
    try:
        logging.info(f"Received features: {features.features}")
        
        # Ensure the features are in the correct format
        if not isinstance(features.features, list):
            raise ValueError("Features must be a list")
        
        features_array = np.array(features.features).reshape(1, -1)
        logging.info(f"Features array: {features_array}")
        
        # Check if the number of features matches the model's expected input
        if features_array.shape[1] != 10: 
            raise ValueError(f"Expected 10 features, but got {features_array.shape[1]}")
        
        prediction = model.predict(features_array)
        logging.info(f"Prediction result: {prediction[0]}")
        return {"prediction": int(prediction[0])} 
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        logging.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# Run the app
if __name__ == "__main__": 
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)