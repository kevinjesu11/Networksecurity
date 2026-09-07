# End-to-End AWS CI/CD Deployment Guide

Use this guide to explain and demo the project in an interview.

## What This Project Demonstrates

This is an MLOps-style phishing detection project:

1. Data ingestion from MongoDB or local CSV fallback.
2. Data validation against `data_schema/schema.yaml`.
3. Data transformation with a scikit-learn preprocessing pipeline.
4. Model training and model metric generation.
5. Optional MLflow experiment tracking.
6. Docker image build.
7. Image push to AWS ECR.
8. Deployment to EC2 via AWS Systems Manager.
9. FastAPI prediction service exposed from Docker.

## Cloud Architecture

```text
GitHub push to main
        |
        v
GitHub Actions CI
  - install dependencies
  - compile/import smoke checks
  - train model
  - upload final_model artifact
        |
        v
GitHub Actions CD
  - download trained model artifact
  - build Docker image
  - tag image with commit SHA and latest
  - push image to AWS ECR
        |
        v
EC2 instance, driven by AWS SSM
  - pull latest ECR image
  - stop old container
  - run new container on port 8080
  - verify /health
```

## AWS Setup

### 1. Create ECR Repository

In AWS Console:

```text
Elastic Container Registry -> Repositories -> Create repository
```

Example repository name:

```text
networksecurity
```

After creation, your registry URI will look like:

```text
123456789012.dkr.ecr.us-east-1.amazonaws.com
```

Your full image URI will look like:

```text
123456789012.dkr.ecr.us-east-1.amazonaws.com/networksecurity:latest
```

The container image and CI both run Python 3.12. Keep them on the same version:
CI trains the model and the container loads it, and a mismatch between the two
silently corrupts predictions rather than raising.

### 2. Create EC2 Instance

Use:

- Ubuntu Server
- t2.micro or t3.micro for demo
- Security group inbound rules:
  - SSH: port `22`, your IP
  - App: port `8080`, `0.0.0.0/0` for demo only

Prefer restricting `8080` to your own IP rather than `0.0.0.0/0`. There is no
rate limiting yet, and each `/predict-url` call costs a DNS lookup, an HTTP
fetch and a WHOIS query, so an open port lets anyone drive outbound traffic from
your instance.

Install Docker on EC2:

```bash
sudo apt-get update -y
sudo apt-get upgrade -y
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
newgrp docker
docker --version
```

### 2b. Require IMDSv2 on the Instance

Do this before exposing the app. `/predict-url` fetches URLs supplied by
anonymous visitors, which is what makes the instance metadata endpoint worth
protecting: under IMDSv1 a single crafted request can read the instance role's
credentials.

```bash
aws ec2 modify-instance-metadata-options   --instance-id i-YOUR_INSTANCE_ID   --http-tokens required   --http-endpoint enabled
```

The application already refuses to fetch private, loopback and link-local
addresses, and re-checks every redirect hop. IMDSv2 is the second layer: the
application guard resolves a hostname for its check and the socket layer
resolves it again, and a hostile DNS server can answer differently between the
two. Run both.

### 3. Automated Deployment Setup

Deployment runs from a GitHub-hosted runner and drives the instance through AWS
Systems Manager. There is no self-hosted runner: this repository is public, and
a self-hosted runner attached to a public repository lets a fork's pull request
execute code on the box. Nothing needs to listen on EC2, and no inbound port has
to be open for deploys.

```text
push to main
      |
      v
GitHub-hosted runner
  - assumes an AWS role via OIDC (no stored access keys)
  - builds the image, pushes to ECR
  - aws ssm send-command --instance-ids i-xxx
      |
      v
EC2 instance
  - pulls the image using its own instance role
  - reads secrets from Parameter Store
  - restarts the container, verifies /health
```

Run the setup script once, with credentials that can create IAM resources:

```bash
./scripts/setup_aws_deploy.sh kevinjesu11/Networksecurity i-YOUR_INSTANCE_ID us-east-1
```

It creates the GitHub OIDC provider, a role only this repository's `main` branch
can assume, ECR and scoped SSM permissions, the SSM permissions the instance
needs, and a generated `TRAIN_API_KEY` in Parameter Store. It is re-runnable and
prints the exact `gh secret set` commands to finish with.

Application secrets live in Parameter Store rather than GitHub, so they are read
on the instance and never travel through the workflow or appear in SSM command
history:

```bash
aws ssm put-parameter --name /networksecurity/TRAIN_API_KEY   --value "$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"   --type SecureString --region us-east-1

# Only if training from MongoDB rather than the bundled CSV
aws ssm put-parameter --name /networksecurity/MONGO_DB_URL   --value "mongodb+srv://..." --type SecureString --region us-east-1
```

Confirm SSM can see the instance before the first deploy. An empty result means
it cannot, and the deploy will fail:

```bash
aws ssm describe-instance-information --region us-east-1   --query "InstanceInformationList[].InstanceId"
```

## GitHub Secrets

Add these in:

```text
Repo -> Settings -> Secrets and variables -> Actions -> New repository secret
```

Required:

```text
AWS_ROLE_ARN
AWS_REGION
AWS_ECR_LOGIN_URI
ECR_REPOSITORY_NAME
EC2_INSTANCE_ID
```

There is no `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY`. The workflow assumes
`AWS_ROLE_ARN` over OIDC and receives credentials that expire with the job, so
there is nothing long-lived to leak or rotate.

`TRAIN_API_KEY` is not a repository secret either -- it lives in Parameter Store
and is read by the instance at deploy time.

Deployment is off until the repository variable is set, which keeps a repo
without AWS configured from reporting a failed build on every push:

```bash
gh variable set ENABLE_AWS_DEPLOY --body true
```

Generate `TRAIN_API_KEY` with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`/train` retrains the model and overwrites `final_model/`, so it requires this
key and rejects anything else. It fails closed: if the secret is unset the route
returns 503 rather than running unauthenticated. Call it with:

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" http://EC2_PUBLIC_IP:8080/train
```

Example values:

```text
AWS_REGION=us-east-1
AWS_ECR_LOGIN_URI=123456789012.dkr.ecr.us-east-1.amazonaws.com
ECR_REPOSITORY_NAME=networksecurity
```

Optional:

```text
MONGO_DB_URL
TRAINING_BUCKET_NAME
MLFLOW_TRACKING_URI
MLFLOW_TRACKING_USERNAME
MLFLOW_TRACKING_PASSWORD
```

Use `MONGO_DB_URL` only if you want cloud training to read MongoDB instead of the bundled CSV.

Use `TRAINING_BUCKET_NAME` only if you want `/train` to sync artifacts and final model files to S3.

## AWS IAM Permissions

For an interview demo, the simplest IAM user permissions are:

```text
AmazonEC2ContainerRegistryFullAccess
```

If you also use S3 artifact sync:

```text
AmazonS3FullAccess
```

For production, replace those broad policies with least-privilege ECR and S3 permissions.

## Local Docker Commands

Build image:

```bash
docker build -t networksecurity:latest .
```

Run image:

```bash
docker run -p 8080:8080 --name networksecurity networksecurity:latest
```

Test:

```bash
curl http://127.0.0.1:8080/health
```

Open:

```text
http://127.0.0.1:8080/docs
```

## Demo Flow

1. Show the FastAPI app locally or on EC2:

```text
http://EC2_PUBLIC_IP:8080/docs
```

2. Show `/health`.

3. Use `/predict` and upload:

```text
valid_data/test.csv
```

4. Show GitHub Actions:

- CI trained the model.
- CD built the Docker image.
- Image was pushed to ECR.
- EC2 pulled and ran the container.

5. Show ECR:

- Repository contains `latest`.
- Repository contains commit SHA image tag.

6. Show EC2:

```bash
docker ps
docker logs networksecurity
```

## Interview Explanation

Short version:

```text
This project implements an MLOps CI/CD pipeline for a phishing detection model.
On every push to main, GitHub Actions validates the code, trains the model,
stores the trained model as a workflow artifact, builds a Docker image with the
model inside it, pushes the image to AWS ECR, and deploys it to an EC2 instance through AWS
Systems Manager, authenticating to AWS with short-lived OIDC credentials rather
than stored keys. The deployed FastAPI service
serves predictions through a /predict endpoint and exposes /health for deployment
verification.
```
