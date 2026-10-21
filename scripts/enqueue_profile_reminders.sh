#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd) || exit 1
cd "$PROJECT_DIR" || exit 1

output=$(/usr/bin/docker compose exec -T celery celery -A config call \
    cloudSyncAPI.tasks.send_incomplete_profile_reminders 2>&1)
status=$?

printf '%s\n' "$output" | /usr/bin/logger -t cloudsync-profile-reminders
exit "$status"
