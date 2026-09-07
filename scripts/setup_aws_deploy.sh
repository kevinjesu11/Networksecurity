#!/usr/bin/env bash
#
# One-time AWS setup for automated deployment.
#
# Creates the pieces the GitHub Actions pipeline needs and nothing else:
#
#   1. An IAM OIDC provider for GitHub Actions, so the workflow can obtain
#      short-lived credentials instead of long-lived access keys.
#   2. A role that only this repository can assume, able to push to ECR and to
#      send exactly one SSM document to the deployment instance.
#   3. SSM permissions on the instance's existing role, so it can be driven
#      remotely and read its own secrets.
#   4. Parameter Store entries for the application secrets, which stay on the
#      AWS side and never pass through the workflow.
#
# Run it once, with credentials that can create IAM resources. It is written to
# be re-runnable: existing resources are reported and left alone.
#
# Usage:
#   ./scripts/setup_aws_deploy.sh <github-user/repo> <instance-id> [region]
#
set -euo pipefail

REPO="${1:?usage: $0 <github-user/repo> <instance-id> [region]}"
INSTANCE_ID="${2:?usage: $0 <github-user/repo> <instance-id> [region]}"
REGION="${3:-us-east-1}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ROLE_NAME="GitHubActions-NetworkSecurity"
EC2_ROLE_NAME="EC2-ECR-Role"
OIDC_HOST="token.actions.githubusercontent.com"

echo "Account:  $ACCOUNT_ID"
echo "Repo:     $REPO"
echo "Instance: $INSTANCE_ID"
echo "Region:   $REGION"
echo

# --- 1. OIDC provider -------------------------------------------------------
if aws iam list-open-id-connect-providers \
     | grep -q "$OIDC_HOST"; then
  echo "[=] OIDC provider already present"
else
  aws iam create-open-id-connect-provider \
    --url "https://$OIDC_HOST" \
    --client-id-list "sts.amazonaws.com" \
    --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" > /dev/null
  echo "[+] created OIDC provider"
fi

# --- 2. Role GitHub assumes -------------------------------------------------
# The condition on `sub` is what stops any other repository -- or a fork, or a
# pull request from one -- assuming this role. Restricted to the main branch,
# since that is the only ref that deploys.
TRUST=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_HOST}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "${OIDC_HOST}:aud": "sts.amazonaws.com" },
      "StringLike": { "${OIDC_HOST}:sub": "repo:${REPO}:ref:refs/heads/main" }
    }
  }]
}
JSON
)

if aws iam get-role --role-name "$ROLE_NAME" > /dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
    --policy-document "$TRUST" > /dev/null
  echo "[=] role $ROLE_NAME exists; trust policy refreshed"
else
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST" \
    --description "Pushes images to ECR and deploys via SSM for $REPO" > /dev/null
  echo "[+] created role $ROLE_NAME"
fi

# ECR push, plus permission to send one specific document to one specific
# instance. Deliberately not ssm:* on all resources.
PERMS=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ssm:${REGION}::document/AWS-RunShellScript",
        "arn:aws:ec2:${REGION}:${ACCOUNT_ID}:instance/${INSTANCE_ID}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [ "ssm:GetCommandInvocation", "ssm:ListCommandInvocations" ],
      "Resource": "*"
    }
  ]
}
JSON
)

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "EcrPushAndSsmDeploy" --policy-document "$PERMS"
echo "[+] attached ECR + SSM policy"

# --- 3. Instance role: SSM management + reading its own secrets -------------
if aws iam get-role --role-name "$EC2_ROLE_NAME" > /dev/null 2>&1; then
  aws iam attach-role-policy --role-name "$EC2_ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  echo "[+] attached AmazonSSMManagedInstanceCore to $EC2_ROLE_NAME"

  READ_PARAMS=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [ "ssm:GetParameter", "ssm:GetParameters" ],
    "Resource": "arn:aws:ssm:${REGION}:${ACCOUNT_ID}:parameter/networksecurity/*"
  }]
}
JSON
)
  aws iam put-role-policy --role-name "$EC2_ROLE_NAME" \
    --policy-name "ReadNetworkSecurityParameters" --policy-document "$READ_PARAMS"
  echo "[+] allowed $EC2_ROLE_NAME to read /networksecurity/* parameters"
else
  echo "[!] role $EC2_ROLE_NAME not found -- attach SSM permissions to whatever"
  echo "    instance profile the EC2 box actually uses, or the deploy cannot"
  echo "    reach it."
fi

# --- 4. Application secrets -------------------------------------------------
if ! aws ssm get-parameter --name /networksecurity/TRAIN_API_KEY \
       --region "$REGION" > /dev/null 2>&1; then
  KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null \
        || openssl rand -base64 32)"
  aws ssm put-parameter --name /networksecurity/TRAIN_API_KEY \
    --value "$KEY" --type SecureString --region "$REGION" > /dev/null
  echo "[+] generated /networksecurity/TRAIN_API_KEY"
  echo "    $KEY"
  echo "    Store this now; it is not printed again."
else
  echo "[=] /networksecurity/TRAIN_API_KEY already set"
fi

cat <<SUMMARY

Done. Set these repository secrets:

  gh secret set AWS_ROLE_ARN --body "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
  gh secret set AWS_REGION --body "${REGION}"
  gh secret set AWS_ECR_LOGIN_URI --body "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
  gh secret set ECR_REPOSITORY_NAME --body "networksecurity"
  gh secret set EC2_INSTANCE_ID --body "${INSTANCE_ID}"

Then enable deployment:

  gh variable set ENABLE_AWS_DEPLOY --body true

The instance must be running with the SSM agent active. Check with:

  aws ssm describe-instance-information --region ${REGION} \
    --query "InstanceInformationList[?InstanceId=='${INSTANCE_ID}']"

An empty result means SSM cannot see the instance: confirm it is running, that
the instance profile is attached, and that the agent is up.
SUMMARY
