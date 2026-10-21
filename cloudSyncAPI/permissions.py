from rest_framework.permissions import BasePermission

from .choices import UserType
from .constants import Messages


def user_is_paid(user):
    """True for an active user whose profile is Paid."""
    # By default it will return the bool
    return bool(
        user
        and user.is_active
        and hasattr(user, 'profile')
        and user.profile.user_type == UserType.PAID
    )


class IsPaidUser(BasePermission):
    """Allows access only to authenticated users whose profile is Paid."""

    message = Messages.PAID_ONLY

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user_is_paid(user))


def user_has_google_drive(user):
    """True for an authenticated user who has connected their Google Drive."""
    return bool(
        user
        and user.is_authenticated
        and hasattr(user, 'google_drive')
        and user.google_drive is not None
    )


class HasGoogleDriveConnected(BasePermission):
    """Allows access only to users who have an active Google Drive connection."""

    message = Messages.DRIVE_NOT_CONNECTED

    def has_permission(self, request, view):
        return user_has_google_drive(request.user)

