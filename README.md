LokiStack Installation on ROSA - README

This README provides step-by-step instructions and context for the install_lokistack.sh script, which automates the setup of LokiStack (Red Hat OpenShift Logging 6.x) in a ROSA (Red Hat OpenShift Service on AWS) cluster.

📦 Prerequisites

Before running the script, ensure the following tools are installed and accessible in your terminal session:

oc (OpenShift CLI)

rosa (ROSA CLI)

aws CLI (configured with appropriate permissions)

jq

🔐 Required AWS Permissions

The script creates and manages AWS resources:

S3 bucket

IAM policy

IAM role

Your AWS credentials must have permissions to:

s3:* on the specified bucket

iam:CreateRole, iam:CreatePolicy, iam:AttachRolePolicy

🧾 Input Requirements

Interactive Prompts:

The script will prompt for the following:

AWS Access Key ID

AWS Secret Access Key

These are used to create a Kubernetes secret for Loki to access the S3 bucket.

Alternatively, you can set them as environment variables before running:

export AWS_ACCESS_KEY_ID=... export AWS_SECRET_ACCESS_KEY=...

🏗️ Script Workflow

The script performs the following operations in order:

(A) Worker Pool Check

Verifies that the specified lokistack-mp machinepool exists

Waits for all associated nodes to be in Ready state

(B) S3 Bucket Setup

Creates a dedicated S3 bucket (if not already created)

(C) IAM Policy

Creates a custom policy allowing LokiStack to interact with the bucket

(D) IAM Role

Creates an IAM role with the trust policy for OpenShift's OIDC provider

Attaches the policy

(E) Operator Subscriptions

Installs Cluster Logging Operator

Installs Loki Operator

Waits for both to be in Succeeded state

(F) AWS Secret

Creates logging-loki-aws secret in openshift-logging namespace with credentials for S3 access

(G) LokiStack Custom Resource

Deploys a LokiStack CRD with S3 backend

Waits for LokiStack to be Ready

(H) ClusterLogForwarder (CLF)

Sets up ClusterLogForwarder to route application and infrastructure logs to LokiStack

Creates and configures necessary service accounts and role bindings

(I) UIPlugin

Installs UIPlugin for integrating logs into the OpenShift Console (Observe → Logs)

Ensures Cluster Observability Operator is installed

🧪 Validation Checklist

After running the script:

Go to Observe → Logs tab in OpenShift console

Logs should appear from application and infrastructure sources

Run a test pod to generate logs:

oc new-project test-logs oc run loggen --image=busybox --restart=Never -- /bin/sh -c 'while true; do echo "hello $(date)"; sleep 3; done'

🧯 Troubleshooting

Logs Not Showing?

Check if ClusterLogForwarder and LokiStack are Ready

IAM Issues?

Ensure the OIDC provider in your trust policy matches your OpenShift config

Run aws sts get-caller-identity to validate credentials

📘 Useful Commands

oc get pods -n openshift-logging oc get lokistack -n openshift-logging oc get clusterlogforwarder -n openshift-logging aws iam list-roles | grep lokistack

📄 License

This script and documentation are provided as-is. Use in production environments is at your own discretion.

For feedback or issues, reach out to your platform engineering team or Red Hat support.

Author: Red Hat SAA - Enzo Last Updated: June 2025
