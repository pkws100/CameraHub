#!/bin/sh
set -eu
mkdir -p /data
chown -R app:app /data
exec su-exec app uvicorn app:app --host 0.0.0.0 --port 8090 --workers 1 --no-proxy-headers
