#!/bin/sh
# Start Skerry as an unprivileged user.
#
# ./data is bind-mounted from the host. On a fresh clone it belongs to whoever
# cloned the repo; on a host that ran an older image it belongs to root. Either
# way the app user could not write its database. So this script starts as
# root for exactly one job, giving the data directory to the app user, then
# hands the process to that user before anything else runs. Gunicorn and the
# app never run as root.
set -e

APP_USER=skerry
DATA_DIR=/app/data

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
    exec su-exec "$APP_USER" "$@"
fi

# Already unprivileged (for example, started with --user): run as-is.
exec "$@"
