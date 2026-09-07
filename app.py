import sys
import os
import io
import secrets

from dotenv import load_dotenv
load_dotenv()
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline
from fastapi.staticfiles import StaticFiles

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile,Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel, validate_tree_model_integrity
from networksecurity.utils.url_feature_extraction import extract_url_features
from networksecurity.utils.url_red_flags import url_red_flags
from networksecurity.constant.training_pipeline import TARGET_COLUMN, LEGACY_FEATURE_COLUMNS_TO_DROP

# Below this model confidence a verdict is reported as inconclusive rather than
# as a definite result. See the note in predict_url_route.
UNCERTAIN_CONFIDENCE_THRESHOLD = 70.0

# Upper bound on an uploaded CSV, enforced before pandas sees it.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

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

def _require_train_token(x_api_key: str | None) -> None:
    """Gates /train. Fails closed: with no TRAIN_API_KEY configured the route is
    unavailable rather than open, so a deployment that forgets to set it cannot
    silently expose retraining."""
    expected = os.getenv("TRAIN_API_KEY")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Training endpoint is disabled. Set TRAIN_API_KEY to enable it.",
        )
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# POST, not GET: this retrains and overwrites final_model/, and a GET that mutates
# state can be triggered by a crawler or a browser prefetch.
@app.post("/train")
async def train_route(x_api_key: str = Header(default=None, alias="X-API-Key")):
    try:
        _require_train_token(x_api_key)
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except HTTPException:
        raise
    except Exception as e:
        raise NetworkSecurityException(e,sys)
    
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        # Read with a cap rather than handing an unbounded upload to pandas, which
        # would otherwise let one request exhaust the container's memory.
        raw = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"CSV exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
            )
        df=pd.read_csv(io.BytesIO(raw))
        preprocessor_path = "final_model/preprocessor.pkl"
        model_path = "final_model/model.pkl"
        if not os.path.exists(preprocessor_path) or not os.path.exists(model_path):
            raise HTTPException(status_code=400, detail="Model artifacts not found. Run /train first.")

        preprocesor=load_object(preprocessor_path)
        final_model=load_object(model_path)
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        validate_tree_model_integrity(final_model)
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

        # A blocked target was never fetched, so every content-derived feature is
        # a default. Scoring that would produce a confident-looking verdict about
        # a page nobody looked at.
        if meta["blocked_reason"]:
            raise HTTPException(status_code=400, detail=meta["blocked_reason"])

        preprocesor = load_object(preprocessor_path)
        final_model = load_object(model_path)
        network_model = NetworkModel(preprocessor=preprocesor, model=final_model)
        validate_tree_model_integrity(final_model)

        row_df = pd.DataFrame([features])
        prediction = int(network_model.predict(row_df)[0])

        confidence = None
        try:
            transformed = network_model.preprocessor.transform(row_df)
            proba = network_model.model.predict_proba(transformed)[0]
            confidence = round(float(max(proba)) * 100, 1)
        except Exception:
            confidence = None

        # The model separates real sites (>95%) from suspicious ones only weakly:
        # borderline scores are effectively coin flips, and rendering those as a
        # confident green "Legitimate" is worse than admitting uncertainty.
        if confidence is not None and confidence < UNCERTAIN_CONFIDENCE_THRESHOLD:
            verdict = "uncertain"
        elif prediction == 0:
            verdict = "phishing"
        else:
            verdict = "legitimate"

        # Structural deception in the URL itself outranks the model: these are
        # facts about the link, not predictions, and the model's training data
        # predates most of them.
        critical_flags, warning_flags = url_red_flags(url)
        if critical_flags:
            verdict = "phishing"
        elif warning_flags and verdict == "legitimate":
            verdict = "uncertain"

        return templates.TemplateResponse(
            request=request,
            name="url_result.html",
            context={
                "request": request,
                "url": meta["resolved_url"],
                "is_phishing": prediction == 0,
                "verdict": verdict,
                "critical_flags": critical_flags,
                "warning_flags": warning_flags,
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
