#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Docker entrypoint — works for web, celery worker, and celery-beat containers
# Usage is determined by the CMD passed from docker-compose.yml
# ─────────────────────────────────────────────────────────────────────────────
set -e

# The first argument decides what role this container plays:
#   web         → run migrations + collectstatic, then start gunicorn
#   celery      → start celery worker
#   celery-beat → start celery beat scheduler
#   (anything else is executed directly)

ROLE="${1:-web}"

echo "──────────────────────────────────────────────"
echo "  CloudSync API — starting as: ${ROLE}"
echo "──────────────────────────────────────────────"

case "$ROLE" in
  web)
    echo "[entrypoint] Running database migrations…"
    python manage.py migrate --noinput

    echo "[entrypoint] Collecting static files…"
    python manage.py collectstatic --noinput --clear

    echo "[entrypoint] Starting Gunicorn…"
    exec gunicorn config.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers "${GUNICORN_WORKERS:-3}" \
        --timeout "${GUNICORN_TIMEOUT:-120}" \
        --log-level info \
        --access-logfile - \
        --error-logfile -
    ;;

  celery)
    echo "[entrypoint] Starting Celery worker…"
    exec celery -A config worker \
        --loglevel=info \
        --concurrency="${CELERY_CONCURRENCY:-2}"
    ;;

  celery-beat)
    echo "[entrypoint] Starting Celery Beat scheduler…"
    exec celery -A config beat \
        --loglevel=info \
        --schedule=/app/data/celerybeat-schedule
    ;;

  *)
    # Allows running arbitrary commands inside the container:
    #   docker compose run web python manage.py createsuperuser
    exec "$@"
    ;;
esac
