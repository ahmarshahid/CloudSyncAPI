import logging

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import INVITATION_EXPIRY_MINUTES
from .models import Invitation
from .permissions import user_is_paid

logger = logging.getLogger(__name__)


def send_login_invitation(user):
    """
    Business service to issue an invitation token, build the magic link,
    and send the one-time login email.
    """
    token = Invitation.issue_for(user)
    link = f"{settings.SITE_URL.rstrip('/')}{reverse('invitation-verify')}?token={token}"
    minutes = INVITATION_EXPIRY_MINUTES
    try:
        send_mail(
            subject='Your login link',
            message=(
                f'Hello {user.first_name or user.username or user.email},\n\n'
                f'Click the link below to log in. It can be used once and expires '
                f'in {minutes} minutes.\n\n{link}\n\n'
                f'If you did not request this, you can ignore this email.'
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )
    except Exception:
        # A mail failure must not turn into a 500; it is logged for the developer.
        logger.exception('Failed to send login invitation to user %s', user.pk)
    return token


def verify_invitation_login(token):
    """
    Consumes an invitation token, verifies paid eligibility,
    updates last login, and returns (user, refresh_token) or None.
    """
    user = Invitation.consume(token)
    if user is None or not user_is_paid(user):
        return None

    update_last_login(None, user)
    refresh = RefreshToken.for_user(user)
    return user, refresh

