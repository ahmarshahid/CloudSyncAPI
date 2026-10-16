from rest_framework.permissions import BasePermission

from .models import Profile


def user_is_paid(user):
    """True for an active user whose profile is Paid."""
    return bool(
        user
        and user.is_active
        and hasattr(user, 'profile')
        and user.profile.user_type == Profile.UserType.PAID
    )


class IsPaidUser(BasePermission):
    """Allows access only to authenticated users whose profile is Paid."""

    message = 'This feature is available for paid users only.'

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user_is_paid(user))
