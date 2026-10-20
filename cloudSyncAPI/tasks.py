import logging

from celery import shared_task

from .services import ProfileReminderService

logger = logging.getLogger(__name__)


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

