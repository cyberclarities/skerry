#!/usr/bin/env bash
#
# Upgrade a running Skerry install.
#
# Run from anywhere on the Docker host, as the user who owns the install
# folder and can run docker:
#
#   scripts/upgrade.sh                     back up, update, rebuild, restart, verify
#   scripts/upgrade.sh --check             report what is running and what is waiting
#   scripts/upgrade.sh --rollback STAMP    put back the images from an earlier run
#   scripts/upgrade.sh --rollback STAMP --restore-db
#                                          ...and the database taken by that run
#
# Options:
#   --no-pull       do not git pull; use the code already in the folder
#                   (zip installs: extract the new release first)
#   --yes           do not prompt
#   --no-rollback   if verification fails, leave the new version running
#
# UPGRADE.md explains each step, what lands where, and how to recover.

set -Eeuo pipefail

# --- Run from a copy ----------------------------------------------------------
# git pull can rewrite this file while bash is still reading it, and bash reads
# a script as it goes. Run from a temporary copy so the pull cannot change the
# script under itself.
if [[ -z "${SKERRY_UPGRADE_ROOT:-}" ]]; then
    SKERRY_UPGRADE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    export SKERRY_UPGRADE_ROOT
    _copy="$(mktemp "${TMPDIR:-/tmp}/skerry-upgrade.XXXXXX")"
    cp "${BASH_SOURCE[0]}" "$_copy"
    exec bash "$_copy" "$@"
fi
SELF_COPY="${BASH_SOURCE[0]}"
ROOT="$SKERRY_UPGRADE_ROOT"

# --- Settings -----------------------------------------------------------------
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"   # seconds to wait for /health after restart
ROLLBACK_REPO="skerry-rollback"            # local tags kept for rollback
STAMP="$(date +%Y%m%d_%H%M%S)"

MODE=upgrade
NO_PULL=0
ASSUME_YES=0
AUTO_ROLLBACK=1
RESTORE_DB=0
ROLLBACK_STAMP=""
LOCK_DIR=""

usage() { sed -n '3,21p' "$SELF_COPY" | sed 's/^# \{0,1\}//'; }

while (($#)); do
    case "$1" in
        --check)        MODE=check ;;
        --rollback)     MODE=rollback; ROLLBACK_STAMP="${2:-}"; shift
                        [[ -n "$ROLLBACK_STAMP" ]] || { usage; exit 2; } ;;
        --restore-db)   RESTORE_DB=1 ;;
        --no-pull)      NO_PULL=1 ;;
        --yes|-y)       ASSUME_YES=1 ;;
        --no-rollback)  AUTO_ROLLBACK=0 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done
if ((RESTORE_DB)) && [[ "$MODE" != rollback ]]; then
    echo "--restore-db only goes with --rollback STAMP." >&2; exit 2
fi

# --- Output -------------------------------------------------------------------
say()  { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf '%s  WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\n%s  STOPPED: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

confirm() {
    ((ASSUME_YES)) && return 0
    [[ -t 0 ]] || die "$1 No terminal to ask on; re-run with --yes."
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" == [yY]* ]]
}

cleanup() {
    if [[ -n "$LOCK_DIR" ]]; then rmdir "$LOCK_DIR" 2>/dev/null || true; fi
    rm -f "$SELF_COPY"
}
trap cleanup EXIT
trap 'die "Command failed at line $LINENO: $BASH_COMMAND"' ERR

# --- Small helpers ------------------------------------------------------------
# Read KEY from .env, last one wins, quotes and CR stripped.
env_get() {
    sed -n "s/^${1}=//p" "$ROOT/.env" | tail -n 1 | tr -d '\r' \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

cid_of()      { docker compose ps -a -q "$1" 2>/dev/null | head -n 1; }
running_cid() { docker compose ps -q "$1" 2>/dev/null | head -n 1; }
is_running()  { [[ -n "$(running_cid "$1")" ]]; }

# Run a command in a running service; print "unknown" rather than fail.
peek() {
    local svc="$1"; shift
    local out
    out="$(docker compose exec -T "$svc" "$@" 2>/dev/null | tr -d '\r' | head -n 1)" || out=""
    printf '%s' "${out:-unknown}"
}

src_version() {
    sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/app/version.py" 2>/dev/null | head -n 1
}

running_version() {
    peek web sed -n 's/^__version__ = "\(.*\)"/\1/p' /app/app/version.py
}

# --- Preflight ----------------------------------------------------------------
preflight() {
    cd "$ROOT"
    [[ -f docker-compose.yml ]] || die "No docker-compose.yml in $ROOT."
    [[ -f .env ]]               || die "No .env in $ROOT. Nothing to upgrade."
    command -v docker >/dev/null 2>&1 || die "docker is not installed or not on PATH."
    docker compose version >/dev/null 2>&1 \
        || die "Docker Compose v2 ('docker compose') is not available."
    docker info >/dev/null 2>&1 \
        || die "Cannot reach the Docker daemon. Run as a user in the docker group, or with sudo."

    local url
    url="$(env_get DATABASE_URL)"
    url="${url:-sqlite:////app/data/risk_register.db}"
    case "$url" in
        sqlite:////app/data/*)
            DB_CPATH="${url#sqlite:///}"            # /app/data/risk_register.db
            DB_FILE="$(basename "$DB_CPATH")" ;;
        *)
            die "DATABASE_URL is '$url'. This script backs up SQLite under /app/data only. Back up by hand and follow ADMIN_GUIDE.md 10.1." ;;
    esac

    WEB_CID="$(cid_of web)"
    [[ -n "$WEB_CID" ]] \
        || die "No web container exists. This looks like a fresh install: use 'docker compose up --build -d'."
    CADDY_CID="$(cid_of caddy)"

    # Where /app/data really lives on the host: read it from the container
    # rather than assume ./data, in case the mount was changed.
    DATA_SRC="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$WEB_CID")"
    DATA_SRC="${DATA_SRC:-$ROOT/data}"

    if [[ -d .git ]] && ! git rev-parse HEAD >/dev/null 2>&1; then
        die "git cannot read this folder. If the error mentions 'dubious ownership', run as the folder's owner, not with sudo."
    fi
}

# --- State --------------------------------------------------------------------
# Everything a person would want to compare before and after, one key=value
# per line. Missing pieces print as "unknown" rather than stopping the run.
state() {
    local web caddy
    web="$(running_cid web)"; caddy="$(running_cid caddy)"
    echo "date=$(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "source_version=$(src_version)"
    if [[ -d .git ]]; then
        echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    fi
    if [[ -n "$web" ]]; then
        echo "app_version=$(running_version)"
        echo "web_image=$(docker inspect -f '{{.Config.Image}}' "$web")"
        echo "web_image_id=$(docker inspect -f '{{.Image}}' "$web")"
        echo "web_alpine=$(peek web cat /etc/alpine-release)"
        echo "web_python=$(peek web python3 -c 'import platform; print(platform.python_version())')"
        echo "gunicorn=$(peek web python3 -c 'import gunicorn; print(gunicorn.__version__)')"
    else
        echo "web=not running"
    fi
    if [[ -n "$caddy" ]]; then
        echo "caddy_image=$(docker inspect -f '{{.Config.Image}}' "$caddy")"
        echo "caddy_alpine=$(peek caddy cat /etc/alpine-release)"
        echo "caddy_version=$(peek caddy caddy version | awk '{print $1}')"
    else
        echo "caddy=not running"
    fi
}

state_value() { sed -n "s/^$1=//p" "$2" | head -n 1; }

pip_freeze() {
    if is_running web; then
        docker compose exec -T web pip freeze 2>/dev/null | tr -d '\r' > "$1" || true
    fi
}

# --- Backups ------------------------------------------------------------------
PY_BACKUP='
import os, sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
if not os.path.exists(src):
    sys.exit("database not found: " + src)
s = sqlite3.connect(src, timeout=120)
d = sqlite3.connect(dst)
s.backup(d)
s.close()
check = d.execute("PRAGMA integrity_check").fetchone()[0]
tables = d.execute("SELECT count(*) FROM sqlite_master WHERE type = ?", ("table",)).fetchone()[0]
d.close()
print(check, tables)
sys.exit(0 if check == "ok" else 1)
'

backup_database() {
    local result
    if is_running web; then
        # SQLite's backup API through the running app: consistent even mid-write.
        local tmp="/tmp/skerry-upgrade-$STAMP.db"
        result="$(docker compose exec -T web python3 -c "$PY_BACKUP" "$DB_CPATH" "$tmp" 2>&1 | tr -d '\r')" \
            || die "Database backup failed: ${result:-no output}. Nothing was changed."
        docker cp "$(running_cid web):$tmp" "$BK/$DB_FILE" >/dev/null
        docker compose exec -T web rm -f "$tmp" >/dev/null 2>&1 || true
    else
        # Stack is down, so nothing is writing. Use the current image to copy.
        result="$(docker run --rm --entrypoint python3 \
                    -v "$DATA_SRC:/app/data" -v "$BK:/backup" \
                    "$WEB_IMAGE_ID" -c "$PY_BACKUP" "$DB_CPATH" "/backup/$DB_FILE" 2>&1)" \
            || die "Database backup failed: ${result:-no output}. Nothing was changed."
    fi
    [[ -s "$BK/$DB_FILE" ]] || die "Database backup is missing or empty. Nothing was changed."
    say "Database: $BK/$DB_FILE (integrity ok, $(awk '{print $2}' <<<"$result") tables)"
}

backup_env() {
    cp "$ROOT/.env" "$BK/env.backup"
    chmod 600 "$BK/env.backup"
    say "Settings: $BK/env.backup (holds secrets; mode 600)"
}

backup_caddy() {
    [[ -n "$CADDY_CID" ]] || { warn "No Caddy container; skipping its CA backup."; return; }
    local vol
    vol="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CADDY_CID")"
    [[ -n "$vol" ]] || { warn "Could not find Caddy's data volume; skipping its CA backup."; return; }
    docker run --rm --entrypoint tar -v "$vol:/data:ro" -v "$BK:/backup" \
        "$CADDY_IMAGE_ID" czf /backup/caddy_data.tgz -C / data
    say "Caddy CA and certificates: $BK/caddy_data.tgz (volume $vol)"
}

# --- Rollback points ----------------------------------------------------------
save_rollback_point() {
    docker tag "$WEB_IMAGE_ID" "$ROLLBACK_REPO/web:$STAMP"
    if [[ -n "$CADDY_IMAGE_ID" ]]; then
        docker tag "$CADDY_IMAGE_ID" "$ROLLBACK_REPO/caddy:$STAMP"
    fi
    {
        printf 'WEB_REF=%q\n'     "$WEB_REF"
        printf 'WEB_ID=%q\n'      "$WEB_IMAGE_ID"
        printf 'CADDY_REF=%q\n'   "$CADDY_REF"
        printf 'CADDY_ID=%q\n'    "$CADDY_IMAGE_ID"
        printf 'DB_FILE=%q\n'     "$DB_FILE"
        printf 'APP_VERSION=%q\n' "$APP_VERSION_BEFORE"
        printf 'GIT_COMMIT=%q\n'  "$GIT_BEFORE"
    } > "$BK/rollback.env"
    say "Rollback point: $ROLLBACK_REPO/web:$STAMP${CADDY_IMAGE_ID:+ and $ROLLBACK_REPO/caddy:$STAMP}"
}

# Point the tags Compose uses back at the saved images, then recreate.
# Tags both the ref recorded at backup time and whatever ref the containers
# use now, in case the new docker-compose.yml names a different image.
restore_images() {
    local web_id="$1" web_ref="$2" caddy_id="$3" caddy_ref="$4"
    retag web "$web_id" "$web_ref"
    if [[ -n "$caddy_id" ]]; then
        retag caddy "$caddy_id" "$caddy_ref"
    fi
    docker compose up -d --no-build --force-recreate
}

retag() {
    local svc="$1" id="$2" ref="$3" c now_ref
    docker tag "$id" "$ref"
    c="$(cid_of "$svc")"
    if [[ -n "$c" ]]; then
        now_ref="$(docker inspect -f '{{.Config.Image}}' "$c")"
        if [[ "$now_ref" != "$ref" ]]; then
            docker tag "$id" "$now_ref"
        fi
    fi
}

# --- Verification -------------------------------------------------------------
wait_healthy() {
    local cid status restarts deadline=$((SECONDS + HEALTH_TIMEOUT))
    while :; do
        cid="$(running_cid web)"
        if [[ -n "$cid" ]]; then
            status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo gone)"
            restarts="$(docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null || echo 0)"
            [[ "$status" == healthy ]] && return 0
            [[ "$status" == unhealthy ]] && { say "web reports unhealthy."; return 1; }
            ((restarts > 0)) && { say "web has restarted $restarts time(s); it is crashing on start."; return 1; }
            if [[ "$status" == none ]]; then
                # No health check defined: ask /health directly.
                local port; port="$(env_get PORT)"
                if peek web curl -fsS "http://localhost:${port:-5000}/health" | grep -q ok; then
                    return 0
                fi
            fi
        else
            status="not running"
        fi
        ((SECONDS < deadline)) || { say "web not healthy after ${HEALTH_TIMEOUT}s (last status: $status)."; return 1; }
        sleep 5
    done
}

check_through_caddy() {
    command -v curl >/dev/null 2>&1 || { warn "curl not on the host; skipping the check through Caddy."; return 0; }
    local name port code _
    name="$(env_get SERVER_NAME)"
    port="$(docker compose port caddy 443 2>/dev/null | awk -F: '{print $NF}')"
    [[ -n "$name" && -n "$port" ]] || { warn "Could not read SERVER_NAME or Caddy's published port; skipping the check through Caddy."; return 0; }
    for _ in 1 2 3 4 5 6; do
        # Caddy only answers for SERVER_NAME, so resolve that name to this host.
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
                --resolve "$name:$port:127.0.0.1" "https://$name:$port/health" || true)"
        [[ "$code" == 200 ]] && { say "https://$name:$port/health through Caddy: 200"; return 0; }
        sleep 5
    done
    say "https://$name:$port/health through Caddy returned '${code:-no answer}'."
    return 1
}

verify() {
    local expected="$1" running
    say "Waiting for the web health check (up to ${HEALTH_TIMEOUT}s)..."
    wait_healthy || return 1
    running="$(running_version)"
    if [[ -n "$expected" && "$running" != "$expected" ]]; then
        say "Running version is $running; expected $expected. The rebuild did not take."
        return 1
    fi
    say "web is healthy, version $running."
    check_through_caddy
}

# --- Changelog ----------------------------------------------------------------
# Print the CHANGELOG entries newer than version $1 from file $2.
changelog_since() {
    awk -v v="$1" '
        /^## / { if ($2 == v) exit; p = 1 }
        p { print }
    ' "$2"
}

# From changelog text on stdin, print the "### Upgrading" bullets that ask for
# more than the routine rebuild. A bullet starting "Rebuild:" that says "no
# settings change" is routine; anything else is printed, prefixed with its
# version.
upgrade_steps() {
    awk '
        function flush() {
            if (cur != "") {
                l = tolower(cur)
                if (!(l ~ /^- rebuild:/ && l ~ /no settings change/)) print ver ": " cur
                cur = ""
            }
        }
        /^## /                    { flush(); up = 0; ver = $2; next }
        /^### /                   { flush(); up = ($0 ~ /^### Upgrading/); next }
        up && /^- /               { flush(); cur = $0; next }
        up && /^  / && cur != ""  { sub(/^ +/, ""); cur = cur " " $0; next }
        END                       { flush() }
    '
}

# --- Modes --------------------------------------------------------------------
do_check() {
    step "Running now"
    state
    if [[ -d .git ]]; then
        step "Waiting in git"
        if git fetch --quiet 2>/dev/null && git rev-parse '@{u}' >/dev/null 2>&1; then
            local behind
            behind="$(git rev-list --count 'HEAD..@{u}')"
            if ((behind == 0)); then
                echo "Up to date with $(git rev-parse --abbrev-ref '@{u}')."
            else
                echo "$behind commit(s) behind $(git rev-parse --abbrev-ref '@{u}'):"
                git log --oneline 'HEAD..@{u}' | head -n 20
                local tmp; tmp="$(mktemp)"
                if git show '@{u}:CHANGELOG.md' > "$tmp" 2>/dev/null; then
                    echo
                    changelog_since "$(src_version)" "$tmp"
                fi
                rm -f "$tmp"
            fi
        else
            echo "No upstream to compare against (or the fetch failed)."
        fi
    fi
    step "Rollback points"
    local found=0 d
    for d in "$ROOT"/backups/upgrade_*/rollback.env; do
        [[ -f "$d" ]] || continue
        found=1
        echo "  $(basename "$(dirname "$d")" | sed 's/^upgrade_//')  version $(state_value APP_VERSION "$d")"
    done
    ((found)) || echo "  none"
    echo
    echo "Base images are re-pulled on every upgrade, so a run with no new code still"
    echo "picks up Alpine, Python, and Caddy security updates."
}

do_upgrade() {
    step "Before"
    WEB_REF="$(docker inspect -f '{{.Config.Image}}' "$WEB_CID")"
    WEB_IMAGE_ID="$(docker inspect -f '{{.Image}}' "$WEB_CID")"
    CADDY_REF=""; CADDY_IMAGE_ID=""
    if [[ -n "$CADDY_CID" ]]; then
        CADDY_REF="$(docker inspect -f '{{.Config.Image}}' "$CADDY_CID")"
        CADDY_IMAGE_ID="$(docker inspect -f '{{.Image}}' "$CADDY_CID")"
    fi
    APP_VERSION_BEFORE="$(running_version)"
    [[ "$APP_VERSION_BEFORE" == unknown ]] && APP_VERSION_BEFORE="$(src_version)"
    GIT_BEFORE=""
    [[ -d .git ]] && GIT_BEFORE="$(git rev-parse HEAD)"
    local src_before; src_before="$(src_version)"

    echo "Running version $APP_VERSION_BEFORE. This run will:"
    echo "  1. back up the database, .env, and Caddy's CA to backups/upgrade_$STAMP/"
    echo "  2. keep the current images as a rollback point"
    if ((NO_PULL)) || [[ ! -d .git ]]; then
        echo "  3. use the code already in this folder (no git pull)"
    else
        echo "  3. git pull (fast-forward only)"
    fi
    echo "  4. rebuild on freshly pulled base images and restart (a few seconds offline)"
    echo "  5. check health and version, and roll back the images if that fails"
    confirm "Go ahead?" || die "Cancelled. Nothing was changed."

    BK="$ROOT/backups/upgrade_$STAMP"
    mkdir -p "$BK"
    chmod 700 "$BK"
    exec > >(tee -a "$BK/upgrade.log") 2>&1
    state > "$BK/state-before.txt"
    pip_freeze "$BK/pip-freeze-before.txt"

    step "1. Back up"
    backup_database
    backup_env
    backup_caddy

    step "2. Rollback point"
    save_rollback_point

    step "3. Code"
    if ((NO_PULL)) || [[ ! -d .git ]]; then
        say "Using the code in $ROOT as it stands (version $(src_version))."
    else
        [[ -z "$(git status --porcelain --untracked-files=no)" ]] \
            || die "Tracked files in $ROOT have local changes. Commit or stash them, or re-run with --no-pull. The backups in $BK stand; nothing else was changed."
        git fetch --quiet
        if git rev-parse '@{u}' >/dev/null 2>&1; then
            git merge --ff-only --quiet '@{u}' \
                || die "Cannot fast-forward to $(git rev-parse --abbrev-ref '@{u}'). Sort out the branch by hand, then re-run."
            say "Code: $(git rev-parse --short "$GIT_BEFORE") -> $(git rev-parse --short HEAD)"
        else
            warn "This branch has no upstream; using the code as it stands."
        fi
    fi

    local src_after; src_after="$(src_version)"
    if [[ "$src_after" != "$src_before" && -f CHANGELOG.md ]]; then
        local notes steps
        notes="$(changelog_since "$src_before" CHANGELOG.md)"
        if [[ -n "$notes" ]]; then
            step "What changed since $src_before"
            printf '%s\n' "$notes"
            steps="$(upgrade_steps <<<"$notes")"
            if [[ -n "$steps" ]]; then
                step "Upgrade steps beyond a rebuild"
                printf '%s\n' "$steps"
                echo
                # --yes never answers this one: whoever scheduled an unattended
                # run has not read these notes.
                local stop_msg="Stopped before the rebuild so the steps above can be done. The running stack is untouched and the code is already pulled. When ready: scripts/upgrade.sh --no-pull"
                ((ASSUME_YES)) && die "$stop_msg"
                [[ -t 0 ]] || die "$stop_msg"
                local answer
                read -r -p "Have you done any of these that must come before the restart? [y/N] " answer
                [[ "$answer" == [yY]* ]] || die "$stop_msg"
            fi
        fi
    elif [[ "$src_after" == "$src_before" ]]; then
        say "Application version unchanged ($src_after). The rebuild still refreshes base images and system packages."
    fi

    step "4. Rebuild"
    # Build first: if it fails, nothing running has been touched.
    docker compose build --pull web \
        || die "Build failed. The running stack is untouched and still on $APP_VERSION_BEFORE.${GIT_BEFORE:+ To return the folder to the old code: git reset --hard $(git rev-parse --short "$GIT_BEFORE")}"
    docker compose pull caddy \
        || warn "Could not pull a newer Caddy image; keeping the one on this host."
    say "Restarting."
    docker compose up -d --no-build

    step "5. Verify"
    if verify "$src_after"; then
        state > "$BK/state-after.txt"
        pip_freeze "$BK/pip-freeze-after.txt"
        step "Done"
        summary "$BK/state-before.txt" "$BK/state-after.txt"
        echo
        echo "Backups and logs: $BK"
        echo "Package list for the SBOM: $BK/pip-freeze-after.txt"
        echo "To undo: scripts/upgrade.sh --rollback $STAMP   (add --restore-db to also put back the database)"
        prune_hint
        return 0
    fi

    if ((AUTO_ROLLBACK)); then
        step "Rolling back"
        say "Verification failed. Putting back the images from before the upgrade."
        restore_images "$WEB_IMAGE_ID" "$WEB_REF" "$CADDY_IMAGE_ID" "$CADDY_REF"
        if verify "$APP_VERSION_BEFORE"; then
            state > "$BK/state-after-rollback.txt"
            die "The upgrade did not pass its checks and was rolled back. $APP_VERSION_BEFORE is running again. The database was not restored; the new version may have added tables, which the old one ignores. See docker compose logs web, and UPGRADE.md, 'If it fails'.${GIT_BEFORE:+ The folder still holds the new code; to match what is running: git reset --hard $(git rev-parse --short "$GIT_BEFORE")}"
        fi
        die "The upgrade failed and the rollback did not come up healthy either. Check docker compose logs web. Backups are in $BK; UPGRADE.md, 'Restore by hand', walks through it."
    fi
    die "Verification failed and --no-rollback was given, so the new version is still running. To undo: scripts/upgrade.sh --rollback $STAMP"
}

do_rollback() {
    BK="$ROOT/backups/upgrade_$ROLLBACK_STAMP"
    [[ -f "$BK/rollback.env" ]] || die "No rollback point $ROLLBACK_STAMP (looked for $BK/rollback.env). 'scripts/upgrade.sh --check' lists them."
    local WEB_REF WEB_ID CADDY_REF CADDY_ID DB_FILE APP_VERSION GIT_COMMIT
    # shellcheck disable=SC1091  # written by this script with printf %q
    source "$BK/rollback.env"
    docker image inspect "$WEB_ID" >/dev/null 2>&1 \
        || die "The saved web image is gone (pruned?). Restore by hand: UPGRADE.md, 'Restore by hand'."

    echo "This puts back the images saved on $ROLLBACK_STAMP (version $APP_VERSION)."
    if ((RESTORE_DB)); then
        echo "It also replaces the database with the copy taken then. Anything entered since"
        echo "is lost. The current database is set aside in $BK/ first."
    fi
    confirm "Go ahead?" || die "Cancelled. Nothing was changed."
    exec > >(tee -a "$BK/rollback-$STAMP.log") 2>&1

    if ((RESTORE_DB)); then
        step "Database"
        [[ -s "$BK/$DB_FILE" ]] || die "No database backup at $BK/$DB_FILE."
        docker compose stop web
        local aside="pre-restore-$STAMP"
        # Copy the backup in under a temporary name first, so a failed copy
        # leaves the current database where it was. Then set the current file
        # and any journal aside (a leftover journal next to the restored file
        # would be replayed into it) and move the copy into place.
        if ! docker run --rm --entrypoint sh \
            -v "$DATA_SRC:/app/data" -v "$BK:/backup" "$WEB_ID" -c '
                set -e
                db="$1"; keep="/backup/$2"; src="/backup/$3"
                cp "$src" "$db.restoring"
                mkdir -p "$keep"
                for f in "$db" "$db-journal" "$db-wal" "$db-shm"; do
                    if [ -e "$f" ]; then mv "$f" "$keep/"; fi
                done
                mv "$db.restoring" "$db"
            ' sh "$DB_CPATH" "$aside" "$DB_FILE"
        then
            if docker run --rm --entrypoint test -v "$DATA_SRC:/app/data" "$WEB_ID" -s "$DB_CPATH"; then
                docker compose start web
                die "The database restore failed. The current database is still in place and web has been restarted on it. Nothing else was changed."
            fi
            die "The database restore failed partway, and web has been left stopped so it cannot start on an empty database. The files it moved are in $BK/$aside/. UPGRADE.md, 'Restore by hand', walks through putting one back."
        fi
        say "Database restored from $BK/$DB_FILE. The one it replaced is in $BK/$aside/."
    fi

    step "Images"
    restore_images "$WEB_ID" "$WEB_REF" "$CADDY_ID" "$CADDY_REF"
    step "Verify"
    verify "$APP_VERSION" || die "The rolled-back stack is not healthy. Check docker compose logs web."
    state > "$BK/state-after-rollback-$STAMP.txt"
    say "Rolled back to $APP_VERSION."
    if [[ -n "$GIT_COMMIT" && -d .git && "$(git rev-parse HEAD)" != "$GIT_COMMIT" ]]; then
        echo
        echo "The folder still holds newer code. The next 'docker compose up --build' would"
        echo "bring it back. To match what is running:"
        echo "  git reset --hard $(git rev-parse --short "$GIT_COMMIT")"
    fi
}

summary() {
    local before="$1" after="$2" k
    printf '%-16s %-26s %s\n' "" "before" "after"
    for k in app_version git_commit web_alpine web_python gunicorn caddy_version caddy_alpine; do
        local b a
        b="$(state_value "$k" "$before")"; a="$(state_value "$k" "$after")"
        [[ -z "$b$a" ]] && continue
        printf '%-16s %-26s %s\n' "$k" "${b:--}" "${a:--}"
    done
}

prune_hint() {
    local n
    n="$(docker image ls -q "$ROLLBACK_REPO/web" 2>/dev/null | wc -l | tr -d ' ')"
    if ((n > 3)); then
        echo
        echo "There are $n rollback images. To clear old ones: UPGRADE.md, 'Cleaning up'."
    fi
}

# --- Main ---------------------------------------------------------------------
preflight
mkdir -p "$ROOT/backups"
LOCK_DIR="$ROOT/backups/.upgrade.lock"
mkdir "$LOCK_DIR" 2>/dev/null \
    || { LOCK_DIR=""; die "Another upgrade is running, or one was interrupted. If none is running, remove backups/.upgrade.lock and re-run."; }

case "$MODE" in
    check)    do_check ;;
    upgrade)  do_upgrade ;;
    rollback) do_rollback ;;
esac
