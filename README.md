# Network Security Phishing Detection

FastAPI application and training pipeline for phishing URL classification.

For the full AWS ECR + EC2 + Docker CI/CD walkthrough, see `DEPLOYMENT.md`.

The project can run in two modes:

- Local mode: trains from `Network_Data/phisingData.csv`.
- Cloud mode: trains from MongoDB when `MONGO_DB_URL` or `MONGODB_URL_KEY` is configured, then optionally syncs artifacts to S3 when AWS CLI and AWS credentials are available.

## Local Setup

```bash
python -m pip install -r requirements.txt
```

Train the model:

```bash
python -c "from networksecurity.pipeline.training_pipeline import TrainingPipeline; print(TrainingPipeline().run_pipeline())"
```

This creates:

- `final_model/preprocessor.pkl`
- `final_model/model.pkl`
- timestamped training artifacts under `Artifacts/`

Run the API:

```bash
python app.py
```

Open:

- API docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

Prediction upload:

```bash
curl -F "file=@valid_data/test.csv" http://127.0.0.1:8000/predict
```

The API writes predictions to `prediction_output/output.csv`.

## MongoDB Data Load

Set one of these environment variables before using MongoDB:

```bash
MONGO_DB_URL="mongodb+srv://..."
```

or:

```bash
MONGODB_URL_KEY="mongodb+srv://..."
```

Push the bundled CSV into MongoDB:

```bash
python push_data.py
```

Test MongoDB connectivity:

```bash
python test_mongodb.py
```

## CI/CD Secrets

Required GitHub Actions secrets for AWS deployment:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_REGION
AWS_ECR_LOGIN_URI
ECR_REPOSITORY_NAME
```

`AWS_ECR_LOGIN_URI` should be only the ECR registry URI, for example:

```text
722261000055.dkr.ecr.us-east-1.amazonaws.com
```

Optional secrets:

```text
MONGO_DB_URL
TRAINING_BUCKET_NAME
MLFLOW_TRACKING_URI
MLFLOW_TRACKING_USERNAME
MLFLOW_TRACKING_PASSWORD
```

The Docker container listens on port `8080` in deployment.

## EC2 Runner Docker Setup

Run these on the self-hosted EC2 runner:

```bash
sudo apt-get update -y
sudo apt-get upgrade -y
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
newgrp docker
```
