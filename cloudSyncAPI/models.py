import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class Profile(models.Model):
    class UserType(models.TextChoices):
        FREE = 'free', 'Free'
        PAID = 'paid', 'Paid'

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile'
    )
    user_type = models.CharField(
        max_length=10, choices=UserType.choices, default=UserType.FREE
    )

    # Optional fields, filled in after registration
    phone = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    address = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=100, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.username} ({self.user_type})'



# For Paid User Passwordless Login
class Invitation(models.Model):
    """
    One-time passwordless login link for paid users.

    Only the SHA-256 hash of the token is stored; the raw token exists only in the
    email. An invitation is valid while ``expires_at`` is in the future. Clicking it
    sets ``expires_at`` to "now", which makes it expired (single use).
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='invitations'
    )
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)  # audit only

    def __str__(self):
        return f'Invitation for {self.user} (expires {self.expires_at:%Y-%m-%d %H:%M})'

    @staticmethod
    def hash_token(raw_token):
        return hashlib.sha256(raw_token.encode()).hexdigest()

    @classmethod
    def issue_for(cls, user):
        """Expire the user's older invitations and create a new one. Returns the raw token."""
        now = timezone.now()
        cls.objects.filter(user=user, expires_at__gt=now).update(expires_at=now)

        raw_token = secrets.token_urlsafe(32)
        cls.objects.create(
            user=user,
            token_hash=cls.hash_token(raw_token),
            expires_at=now + timedelta(minutes=settings.INVITATION_EXPIRY_MINUTES),
        )
        return raw_token

    @classmethod
    def consume(cls, raw_token):
        """
        Atomically expire a valid invitation and return its user, or None if the token
        is unknown, expired or already used. The single conditional UPDATE guarantees
        that two simultaneous clicks cannot both succeed.
        """
        now = timezone.now()
        token_hash = cls.hash_token(raw_token)
        updated = cls.objects.filter(
            token_hash=token_hash, expires_at__gt=now
        ).update(expires_at=now, used_at=now)
        if not updated:
            return None
        return cls.objects.select_related('user').get(token_hash=token_hash).user
