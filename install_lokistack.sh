#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# LokiStack end-to-end installer for ROSA (Logging 6.x) – *idempotent edition*
# Author: 2025-06-19  (rev-2)
# -----------------------------------------------------------------------------
set -euo pipefail
SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SOURCE_DIR}/01_env.sh"

# Uncomment for very chatty logs
# set -x

# ---------- helper functions -------------------------------------------------
require() { command -v "$1" >/dev/null 2>&1 || { echo "❌ $1 CLI not found"; exit 1; }; }
msg()      { printf '\n\033[1;34m▶ %s\033[0m\n' "$*"; }
ok()       { printf '   \033[0;32m✓ %s\033[0m\n' "$*"; }

require oc; require aws; require rosa; require jq

msg "LOKISTACK INSTALLATION FOR ROSA"
echo "   This script follows the process for installing OpenShift Logging for version 6.x"
# ----------   auto-detect / sanity -------------------------------------------
: "${REGION:=$(oc get infrastructure cluster -o jsonpath='{.status.platformStatus.aws.region}')}"
: "${CLUSTER_NAME:=$(oc get infrastructure cluster -o jsonpath='{.status.apiServerURL}' | awk -F'.' '{print $2}')}"
OIDC_ENDPOINT=$(oc get authentication.config.openshift.io cluster -o jsonpath='{.spec.serviceAccountIssuer}' | sed 's|^https://||')
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="${CLUSTER_NAME}-${BUCKET_SUFFIX}"
S3_ENDPOINT="https://s3.${REGION}.amazonaws.com"
POLICY_NAME="${CLUSTER_NAME}-lokistack-access-policy"
ROLE_NAME="${CLUSTER_NAME}-lokistack-access-role"
ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
# -------------------------- credential prompt -------------------------------
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

msg "AWS Access Key"
read -rp "Enter AWS Access Key ID: " input_key
read -srp "Enter AWS Secret Access Key: " input_secret
echo

# Export both
export AWS_ACCESS_KEY_ID="${input_key}"
export AWS_SECRET_ACCESS_KEY="${input_secret}"

aws sts get-caller-identity >/dev/null || fail "❌ AWS credentials are invalid or incomplete."

msg "Context"
echo "  Cluster          : ${CLUSTER_NAME}"
echo "  Region           : ${REGION}"
echo "  Bucket           : ${BUCKET_NAME}"
echo "  Loki Size        : ${LOKI_SIZE}"
echo "  Logging Channel  : ${LOGGING_CHANNEL}"
echo "  Storage Class    : ${STORAGE_CLASS}"


# ---------- (A) dedicated machinepool ---------------------------------------
msg "MachinePool"

# 1️⃣  Ensure the pool exists (match on .name OR .id)
if rosa list machinepools -c "${CLUSTER_NAME}" -o json | \
     jq -e ".[] | select((.name? // .id) == \"${MACHINEPOOL_NAME}\")" >/dev/null; then
  ok "MachinePool ${MACHINEPOOL_NAME} exists"
else
  echo -e "\n❌ Required MachinePool \"${MACHINEPOOL_NAME}\" does not exist."
  echo    "   Aborting LokiStack installation – please create the pool first."
  echo "   Example: rosa create machinepool -c ${CLUSTER_NAME} \\"
  echo "            --name=${MACHINEPOOL_NAME} --replicas=2 --instance-type=m5.4xlarge"
  exit 1
fi

# 2️⃣  Determine desired replica count (handles autoscaling & fixed size)
desired=$(rosa list machinepools -c "${CLUSTER_NAME}" -o json | \
          jq -r ".[] | select((.name? // .id)==\"${MACHINEPOOL_NAME}\") | \
                 (.replicas // .autoscaling.min_replicas // 0)")

if [[ "${desired}" -eq 0 ]]; then
  echo -e "\n❌ Unable to determine desired replica count for ${MACHINEPOOL_NAME}."
  echo    "   Check the machine-pool configuration."
  exit 1
fi

# 3️⃣  Wait until every node in the pool is Ready
msg "Checking node readiness for machinepool ${MACHINEPOOL_NAME}"

# Nodes are labelled with the pool *ID* (not the friendly name)
NODE_SELECTOR="hypershift.openshift.io/nodePool=${CLUSTER_NAME}-${MACHINEPOOL_NAME}"

timeout=900     # seconds (15 min)
interval=15     # seconds between checks
elapsed=0

while true; do
  ready=$(oc get nodes -l "${NODE_SELECTOR}" -o json | \
          jq '[.items[] |
               select(.status.conditions[]? |
                      select(.type=="Ready" and .status=="True"))] | length')
 
  echo "Ready nodes: ${ready}"

  if [[ "${ready}" -ge "${desired}" ]]; then
    ok "All ${ready}/${desired} nodes in ${MACHINEPOOL_NAME} are Ready"
    break
  fi

  if [[ "${elapsed}" -ge "${timeout}" ]]; then
    echo -e "\n❌ Nodes in ${MACHINEPOOL_NAME} failed to become Ready within $((timeout/60)) minutes."
    echo    "   Aborting LokiStack installation."
    exit 1
  fi

  echo "⏳ ${ready}/${desired} nodes Ready; waiting… (${elapsed}/${timeout}s)"
  sleep "${interval}"
  elapsed=$((elapsed+interval))
done


# ---------- (B) AWS bucket ---------------------------------------------------
msg "S3 bucket"
if aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
  ok "Bucket ${BUCKET_NAME} already exists"
else
  aws s3 mb "s3://${BUCKET_NAME}" --region "${REGION}"
fi

# ---------- (C) IAM policy ---------------------------------------------------
msg "IAM policy"

policy_file=$(mktemp)          # e.g. /tmp/tmp.abC123
cat > "${policy_file}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::${BUCKET_NAME}", "arn:aws:s3:::${BUCKET_NAME}/*"]
  }]
}
EOF

POLICY_ARN=$(aws iam list-policies --scope Local \
              --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text) || true

if [[ -z "${POLICY_ARN}" ]]; then
  POLICY_ARN=$(aws iam create-policy \
                 --policy-name "${POLICY_NAME}" \
                 --policy-document "file://${policy_file}" \
                 --query Policy.Arn --output text)
  ok "Created policy ${POLICY_NAME}"
else
  ok "Policy ${POLICY_NAME} already exists"
fi

rm -f "${policy_file}"

# ---------- (D) IAM role -----------------------------------------------------
msg "IAM role"

trust_file=$(mktemp)
cat > "${trust_file}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_ENDPOINT}"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_ENDPOINT}:sub": "system:serviceaccount:openshift-logging:logging-loki"
      }
    }
  }]
}
EOF

if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  ok "Role ${ROLE_NAME} already exists"
else
  aws iam create-role \
       --role-name "${ROLE_NAME}" \
       --assume-role-policy-document "file://${trust_file}"
  ok "Created role ${ROLE_NAME}"
fi

aws iam attach-role-policy \
     --role-name "${ROLE_NAME}" \
     --policy-arn "${POLICY_ARN}" || true

rm -f "${trust_file}"
# ---------- (E) Operator subscriptions --------------------------------------
msg "Operators – Cluster Logging + Loki"

# (E1) Cluster Logging operator
if oc -n openshift-logging get csv | grep -q "^cluster-logging.*Succeeded"; then
  ok "cluster-logging operator ready"
else
  oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-logging
  namespace: openshift-logging
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-logging
  namespace: openshift-logging
spec:
  channel: ${LOGGING_CHANNEL}
  name: cluster-logging
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF
  msg "⌛ waiting for cluster-logging CSV…"
  until oc -n openshift-logging get csv | grep -q "^cluster-logging.*Succeeded"; do sleep 15; done
fi

# (E2) Loki operator – installs the LokiStack CRD
if oc -n openshift-logging get csv | grep -q "^loki-operator.*Succeeded"; then
  ok "loki-operator ready"
else
  oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: loki-operator
  namespace: openshift-logging
spec:
  channel: ${LOGGING_CHANNEL}
  name: loki-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  config:
    env:
    - name: ROLEARN
      value: ${ROLE_ARN}
EOF
  msg "⌛ waiting for loki-operator CSV…"
  until oc -n openshift-logging get csv | grep -q "^loki-operator.*Succeeded"; do sleep 15; done
fi

# ---------- Wait for LokiStack CRD -----------------------------------------
msg "⌛ Waiting for LokiStack CRD to appear…"
oc wait --for=condition=Established crd/lokistacks.loki.grafana.com --timeout=300s
ok "LokiStack CRD available"


# ---------- (F) AWS secret ---------------------------------------------------
msg "Secret logging-loki-aws"
if oc -n openshift-logging get secret logging-loki-aws >/dev/null 2>&1; then
  ok "Secret already exists"
else
  oc create -n openshift-logging secret generic logging-loki-aws \
     --from-literal=access_key_id="${AWS_ACCESS_KEY_ID}" \
     --from-literal=access_key_secret="${AWS_SECRET_ACCESS_KEY}" \
     --from-literal=bucketnames="${BUCKET_NAME}" \
     --from-literal=endpoint="${S3_ENDPOINT}" \
     --from-literal=region="${REGION}"
fi


# ---------- (G) LokiStack CR -------------------------------------------------
msg "LokiStack CR"
if oc -n openshift-logging get lokistack logging-loki >/dev/null 2>&1; then
  ok "LokiStack CR already exists"
else
  oc apply -f - <<EOF
apiVersion: loki.grafana.com/v1
kind: LokiStack
metadata:
  name: logging-loki
  namespace: openshift-logging
spec:
  size: ${LOKI_SIZE}
  storage:
    schemas:
      - effectiveDate: "$(date +%Y-%m-%d)"
        version: v13
    secret:
      name: logging-loki-aws
      type: s3
      credentialMode: static
  storageClassName: ${STORAGE_CLASS}
  tenants:
    mode: openshift-logging
  template:
    volumeClaimTemplates:
      retention: 7d
EOF
fi

msg "⌛ Waiting for LokiStack readiness…"
oc -n openshift-logging wait --for=condition=Ready lokistack logging-loki --timeout=15m

# ---------- (H) ClusterLogForwarder -----------------------------------------
msg "ClusterLogForwarder"

if oc -n openshift-logging get clusterlogforwarder observability logging >/dev/null 2>&1 \
      || oc -n openshift-logging get clusterlogforwarder instance >/dev/null 2>&1; then
  ok "CLF already exists"
else
  oc create sa logging-collector -n openshift-logging --dry-run=client -o yaml | oc apply -f -
  for role in logging-collector-logs-writer collect-application-logs collect-infrastructure-logs collect-audit-logs; do
    oc adm policy add-cluster-role-to-user "${role}" -z logging-collector -n openshift-logging || true
  done
  oc apply -f - <<EOF
apiVersion: observability.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: instance
  namespace: openshift-logging
spec:
  serviceAccount:
    name: logging-collector
  outputs:
  - name: lokistack-out
    type: lokiStack
    lokiStack:
      target:
        name: logging-loki
        namespace: openshift-logging
      authentication:
        token:
          from: serviceAccount
    tls:
      ca:
        key: service-ca.crt
        configMapName: openshift-service-ca.crt
  pipelines:
  - name: infra-app-logs
    inputRefs:
    - application
    - infrastructure
    outputRefs:
    - lokistack-out
EOF
fi

# ---------- (I) Cluster Observability Operator + UIPlugin -------------------
msg "Cluster Observability Operator"

COO_NS="openshift-observability"
COO_SUB="cluster-observability-operator"
COO_CHANNEL="stable"           # adjust if you track a different channel

# 1️⃣  Install the COO if not present
if oc get csv -n "${COO_NS}" 2>/dev/null | grep -q "^${COO_SUB}.*Succeeded"; then
  ok "COO already installed in ${COO_NS}"
else
  # Create namespace + OperatorGroup (idempotent)
  oc get ns "${COO_NS}" >/dev/null 2>&1 || oc create ns "${COO_NS}"
  if ! oc -n "${COO_NS}" get operatorgroup default >/dev/null 2>&1; then
    oc apply -n "${COO_NS}" -f - <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: default
  namespace: ${COO_NS}
EOF
  fi

  # Create/ensure the Subscription
  oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: ${COO_SUB}
  namespace: ${COO_NS}
spec:
  channel: ${COO_CHANNEL}
  name: ${COO_SUB}
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

  msg "⌛ waiting for Cluster Observability Operator CSV to succeed…"
  until oc get csv -n "${COO_NS}" 2>/dev/null | grep -q "^${COO_SUB}.*Succeeded"; do
    sleep 15
  done
  ok "COO installed"
fi

# 2️⃣  Wait for the UIPlugin CRD
msg "Waiting for UIPlugin CRD…"
if ! oc wait --for=condition=Established \
       crd/uiplugins.observability.openshift.io \
       --timeout=180s 2>/dev/null; then
  echo -e "\n⚠️  UIPlugin CRD still missing after 3 min – skipping plugin creation."
  echo    "    You can retry later with:"
  echo    "    oc apply -f uiplugin.yaml"
  UI_SKIP=true
else
  ok "UIPlugin CRD ready"
fi

# 3️⃣  Create the logging UIPlugin (if CRD is present)
if [[ -z "${UI_SKIP:-}" ]]; then
  if oc -n openshift-logging get uiplugin logging >/dev/null 2>&1; then
    ok "UIPlugin already exists"
  else
    oc apply -f - <<EOF
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: logging
  namespace: openshift-logging
spec:
  type: Logging
  logging:
    lokiStack:
      name: logging-loki
EOF
    ok "UIPlugin created"
  fi
fi


# ---------- done -------------------------------------------------------------
msg "✔ LokiStack installation complete (idempotent run)"
echo "OpenShift Console → Observe → Logs will light up once pods are Ready."
