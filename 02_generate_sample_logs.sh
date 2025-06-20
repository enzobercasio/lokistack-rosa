#!/usr/bin/env bash
# Fires a tiny log-spammer pod every 5 s
set -euo pipefail
oc new-project log-generator || true
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: log-generator
  labels:
    app: log-generator
spec:
  containers:
  - name: logger
    image: busybox
    command: ["/bin/sh","-c"]
    args: ["while true; do echo \"$(date) - test log from ROSA log-generator\"; sleep 5; done"]
    resources:
      limits: {memory: "64Mi", cpu: "50m"}
      requests: {memory: "32Mi", cpu: "10m"}
  restartPolicy: Always
EOF
echo "Pod running. Query `{ kubernetes.namespace_name=\"log-generator\" }` in the Logs UI."
