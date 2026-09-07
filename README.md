# Network Security Phishing Detection

FastAPI application and training pipeline for phishing URL classification.

For the full AWS ECR + EC2 + Docker CI/CD walkthrough, see `DEPLOYMENT.md`.

The project can run in two modes:

- Local mode: trains from `Network_Data/phisingData.csv`.
- Cloud mode: trains from MongoDB when `MONGO_DB_URL` or `MONGODB_URL_KEY` is configured, then optionally syncs artifacts to S3 when AWS CLI and AWS credentials are available.

The web UI (`/`) supports two ways to get predictions:

- **Check a URL** — paste a single link and the app fetches it live, extracts
  phishing-detection features itself (SSL certificate, domain age via WHOIS,
  DNS resolution, form/link/script analysis), and returns a Legitimate/Phishing
  verdict with a confidence score.
- **Upload CSV** — bulk-score a CSV of pre-computed website features (see
  `data_schema/schema.yaml` for the required columns).

The model is trained on a reduced version of the classic phishing-websites
dataset: 5 original columns (`web_traffic`, `Page_Rank`, `Google_Index`,
`Links_pointing_to_page`, `Statistical_report`) were dropped because they
relied on services with no free live data source anymore (Alexa rank, Google
PageRank API, etc.). Both the CSV and URL prediction paths only need the
remaining 25 live-computable features.

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

Check a single URL:

```bash
curl -F "url=https://example.com" http://127.0.0.1:8000/predict-url
```

URLs that resolve to private, loopback, or link-local addresses (including the
cloud metadata endpoint at `169.254.169.254`) are rejected with HTTP 400 rather
than fetched. Every hop of a redirect chain is re-checked, so a public host
cannot redirect the fetcher inward.

Retraining over HTTP requires a token and is disabled unless `TRAIN_API_KEY` is
set:

```bash
TRAIN_API_KEY="choose-a-long-random-value" python app.py
curl -X POST -H "X-API-Key: choose-a-long-random-value" http://127.0.0.1:8000/train
```

Without that variable `/train` returns 503. Training locally without the server
is unaffected -- call `TrainingPipeline()` directly as shown above.

Prediction upload (bulk CSV):

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
TRAIN_API_KEY
```

`TRAIN_API_KEY` gates the `/train` route on the deployed container. Leave it
unset to keep retraining over HTTP switched off entirely.

The ECR build and EC2 deployment jobs only run when the repository variable
`ENABLE_AWS_DEPLOY` is set to `true`:

```bash
gh variable set ENABLE_AWS_DEPLOY --body true
```

Without it those jobs are skipped and the pipeline runs tests and training only,
so a repository deploying by hand does not report a failed build on every push.

## Rate Limiting

Both prediction endpoints share a per-client limit, 20 requests per 60 seconds
by default. `/predict-url` performs a DNS lookup, an outbound HTTP fetch and a
WHOIS query per call against a caller-chosen target, which is worth bounding on
a public port. Tune with:

```bash
RATE_LIMIT_REQUESTS=20
RATE_LIMIT_WINDOW_SECONDS=60
```

The counter is held in memory, so it is per-container and resets on restart.
Running more than one replica means moving it to shared storage.

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
