#!/bin/sh
set -eu

: "${RELAY_ID:?RELAY_ID is required}"
: "${SOURCE_URI:?SOURCE_URI is required}"
: "${OUTPUT_PORT:?OUTPUT_PORT is required}"

stopping=0
child_pid=""
stop_relay() {
  stopping=1
  if [ -n "$child_pid" ]; then
    kill -TERM "$child_pid" 2>/dev/null || true
    wait "$child_pid" 2>/dev/null || true
  fi
}
trap stop_relay INT TERM

attempt=0
while [ "$stopping" -eq 0 ]; do
  echo "relay=${RELAY_ID} state=starting transport=tcp video=copy audio=disabled"
  vlc -I dummy --no-one-instance --rtsp-tcp --no-audio \
    --no-sout-audio \
    --sout "#std{access=udp,mux=ts,dst=mediamtx:${OUTPUT_PORT}}" \
    --sout-keep --play-and-exit "$SOURCE_URI" >/dev/null 2>&1 &
  child_pid=$!
  wait "$child_pid" || exit_code=$?
  exit_code=${exit_code:-0}
  child_pid=""
  [ "$stopping" -eq 1 ] && break

  attempt=$((attempt + 1))
  case "$attempt" in
    1) delay=2 ;;
    2) delay=5 ;;
    3) delay=15 ;;
    *) delay=30 ;;
  esac
  echo "relay=${RELAY_ID} state=stopped exit=${exit_code} retry_in=${delay}s"
  sleep "$delay" &
  child_pid=$!
  wait "$child_pid" || true
  child_pid=""
  unset exit_code
done

echo "relay=${RELAY_ID} state=stopped_by_container"
