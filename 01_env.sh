#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Variables you might want to override before running install_lokistack.sh
# -----------------------------------------------------------------------------
# Cluster 
export CLUSTER_NAME="gm-2506181348"           
export REGION="ap-southeast-1"                 
export BUCKET_SUFFIX="lokistack-storage"
export MACHINEPOOL_TYPE="m5.4xlarge"
export MACHINEPOOL_REPLICAS=2

# Loki sizing: 1x.extra-small, 2x.small, 3x.medium …
export LOKI_SIZE="1x.extra-small"

# Operator channel (check current minor on docs site)
export LOGGING_CHANNEL="stable-6.2"

# Storage class for chunks & indexes
export STORAGE_CLASS="gp3-csi"

# Change this to your Machine Pool name if you already created it
export MACHINEPOOL_NAME="lokistack-mp"


