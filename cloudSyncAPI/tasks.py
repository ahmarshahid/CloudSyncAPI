from celery.utils.log import get_task_logger
from celery import shared_task
from django.contrib.auth import get_user_model

from .services import ProfileReminderService

logger = get_task_logger(__name__)


@shared_task(
    bind=True,
    name='cloudSyncAPI.tasks.send_drive_action_notification',
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3},
)
def send_drive_action_notification(self, user_id, action, filename, timestamp_str=None):
    """Send a Google Drive notification asynchronously, retrying mail failures."""
    from .services import GoogleDriveService

    user = get_user_model().objects.get(pk=user_id)
    GoogleDriveService.send_action_notification(
        user,
        action,
        filename,
        timestamp_str=timestamp_str,
        raise_on_error=True,
    )


@shared_task(name='cloudSyncAPI.tasks.send_incomplete_profile_reminders')
def send_incomplete_profile_reminders(cooldown_seconds=300):
    """
    Celery periodic task that scans for users with incomplete profiles
    and dispatches reminder emails (cooldown-guarded via Redis cache).
    """
    logger.info('Executing periodic task: send_incomplete_profile_reminders')
    count = ProfileReminderService.process_all_reminders(cooldown_seconds=cooldown_seconds)
    logger.info('Completed send_incomplete_profile_reminders. Dispatched %d reminder(s).', count)
    return count

