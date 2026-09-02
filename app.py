import sys
import os

from dotenv import load_dotenv
load_dotenv()
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline
from fastapi.staticfiles import StaticFiles

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, Form, HTTPException, UploadFile,Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.url_feature_extraction import extract_url_features
from networksecurity.constant.training_pipeline import TARGET_COLUMN, LEGACY_FEATURE_COLUMNS_TO_DROP

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")
# @app.get("/", tags=["authentication"])
# async def index():
#     return RedirectResponse(url="/docs")

@app.get("/", tags=["Home"])
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)
    
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        preprocessor_path = "final_model/preprocessor.pkl"
        model_path = "final_model/model.pkl"
        if not os.path.exists(preprocessor_path) or not os.path.exists(model_path):
            raise HTTPException(status_code=400, detail="Model artifacts not found. Run /train first.")

        preprocesor=load_object(preprocessor_path)
        final_model=load_object(model_path)
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        prediction_df = df.drop(columns=[TARGET_COLUMN] + LEGACY_FEATURE_COLUMNS_TO_DROP, errors="ignore")
        y_pred = network_model.predict(prediction_df)
        df['predicted_column'] = y_pred
        os.makedirs("prediction_output", exist_ok=True)
        df.to_csv('prediction_output/output.csv', index=False)
        table_html = df.to_html(classes='table table-striped')
        return templates.TemplateResponse(request=request,name="table.html",context={"request": request, "table": table_html})
        
    except HTTPException:
        raise
    except Exception as e:
            raise NetworkSecurityException(e,sys)


@app.post("/predict-url")
async def predict_url_route(request: Request, url: str = Form(...)):
    try:
        preprocessor_path = "final_model/preprocessor.pkl"
        model_path = "final_model/model.pkl"
        if not os.path.exists(preprocessor_path) or not os.path.exists(model_path):
            raise HTTPException(status_code=400, detail="Model artifacts not found. Run /train first.")

        features, meta = extract_url_features(url)

        preprocesor = load_object(preprocessor_path)
        final_model = load_object(model_path)
        network_model = NetworkModel(preprocessor=preprocesor, model=final_model)

        row_df = pd.DataFrame([features])
        prediction = int(network_model.predict(row_df)[0])

        confidence = None
        try:
            transformed = network_model.preprocessor.transform(row_df)
            proba = network_model.model.predict_proba(transformed)[0]
            confidence = round(float(max(proba)) * 100, 1)
        except Exception:
            confidence = None

        return templates.TemplateResponse(
            request=request,
            name="url_result.html",
            context={
                "request": request,
                "url": meta["resolved_url"],
                "is_phishing": prediction == 0,
                "confidence": confidence,
                "fetch_error": meta["fetch_error"],
                "features": features,
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise NetworkSecurityException(e, sys)


if __name__=="__main__":
    app_run(app,host="0.0.0.0",port=int(os.getenv("PORT", "8000")))
