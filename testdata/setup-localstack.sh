#!/bin/bash

unset AWS_PROFILE AWS_VAULT
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_SESSION_TOKEN=test
export AWS_REGION=us-east-1

# Exit immediately if any command fails.
set -e

awslocal ssm put-parameter \
  --name "/mocktpp/tpp-client-signing-key" \
  --type "SecureString" \
  --value "$(cat /keys/tpp_client_signing.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mocktpp/tpp-client-transport-key" \
  --type "SecureString" \
  --value "$(cat /keys/tpp_client_transport.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mocktpp/tpp-client-transport-cert" \
  --type "SecureString" \
  --value "$(cat /keys/tpp_client_transport.crt)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mocktpp/tpp-ca-cert" \
  --type "SecureString" \
  --value "$(cat /keys/ca.crt)" \
  --overwrite

if ! awslocal dynamodb describe-table --table-name flows --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating flows table..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "flows",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      {"AttributeName": "id",    "AttributeType": "S"}
    ],
    "KeySchema": [
      {"AttributeName": "id", "KeyType": "HASH"}
    ]
  }'
  awslocal dynamodb wait table-exists --table-name flows --region "$AWS_REGION"
else
  echo "flows already exists"
fi

if ! awslocal dynamodb describe-table --table-name sessions --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating sessions table..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "sessions",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      {"AttributeName": "id", "AttributeType": "S"}
    ],
    "KeySchema": [
      {"AttributeName": "id", "KeyType": "HASH"}
    ]
  }'
  awslocal dynamodb wait table-exists --table-name sessions --region "$AWS_REGION"
else
  echo "sessions table already exists"
fi

if ! awslocal dynamodb describe-table --table-name clients --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating clients table..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "clients",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      {"AttributeName": "id", "AttributeType": "S"}
    ],
    "KeySchema": [
      {"AttributeName": "id", "KeyType": "HASH"}
    ]
  }'
  awslocal dynamodb wait table-exists --table-name clients --region "$AWS_REGION"
else
  echo "clients table already exists"
fi

if ! awslocal dynamodb describe-table --table-name logs --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating sessions table..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "logs",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      {"AttributeName": "id", "AttributeType": "S"},
      {"AttributeName": "flow_id", "AttributeType": "S"},
      {"AttributeName": "created_at", "AttributeType": "N"}
    ],
    "KeySchema": [
      {"AttributeName": "id", "KeyType": "HASH"}
    ],
    "GlobalSecondaryIndexes": [
      {
        "IndexName": "flow_id-index",
        "KeySchema": [
          {"AttributeName": "flow_id", "KeyType": "HASH"},
          {"AttributeName": "created_at", "KeyType": "RANGE"}
        ],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]
  }'
  awslocal dynamodb wait table-exists --table-name logs --region "$AWS_REGION"
else
  echo "logs table already exists"
fi

awslocal dynamodb put-item \
  --table-name clients \
  --item '{"id":{"S":"2597c75c-01d4-414e-84ba-e61384c67382"}, "client_id":{"S":"4WsjEFBKDJr25xH0Al-99"}, "registration_token":{"S":"random_token"}}' \
  --region "$AWS_REGION"

awslocal ssm put-parameter \
  --name "/mocktpp/ready" \
  --type "SecureString" \
  --value "true" \
  --overwrite
