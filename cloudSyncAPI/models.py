from datetime import timedelta
from uuid import uuid4

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .choices import UserType
from .constants import INVITATION_EXPIRY_MINUTES
from .managers import UserManager



class User(AbstractUser):
    """Custom user: logs in with email; username is optional (unique when provided)."""

    username = models.CharField(
        'username',
        max_length=150,
        unique=True,
        null=True,
        blank=True,
        validators=[AbstractUser.username_validator],
        error_messages={'unique': 'A user with that username already exists.'},
    )
    email = models.EmailField(
        'email address',
        unique=True,
        error_messages={'unique': 'A user with that email already exists.'},
    )

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.lower()
        # Store "no username" as NULL so many users can leave it empty (UNIQUE allows many NULLs).
        self.username = self.username or None
        super().save(*args, **kwargs)


class TimeStampedModel(models.Model):
    """
    Abstract base model providing self-updating created_at and updated_at fields.
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Profile(TimeStampedModel):

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
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

    def __str__(self):
        return f'{self.user.email} ({self.user_type})'



# For Paid User Passwordless Login
class Invitation(TimeStampedModel):
    """
    One-time passwordless login link for paid users.

    The link carries ``token`` (a random UUID4). An invitation is valid while
    ``expires_at`` is in the future. Clicking it sets ``expires_at`` to "now", which
    makes it expired (single use).

    Inherits ``created_at`` and ``updated_at`` from TimeStampedModel.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invitations')
    token = models.UUIDField(default=uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)  # audit only

    def __str__(self):
        return f'Invitation for {self.user} (expires {self.expires_at:%Y-%m-%d %H:%M})'

    @classmethod
    def issue_for(cls, user):
        """Expire the user's older invitations and create a new one. Returns its token (UUID)."""
        now = timezone.now()
        cls.objects.filter(user=user, expires_at__gt=now).update(expires_at=now)

        invitation = cls.objects.create(
            user=user,
            expires_at=now + timedelta(minutes=INVITATION_EXPIRY_MINUTES),
        )
        return invitation.token

    @classmethod
    def consume(cls, token):
        """
        Atomically expire a valid invitation and return its user, or None if the token
        is unknown, expired or already used. The single conditional UPDATE guarantees
        that two simultaneous clicks cannot both succeed.
        """
        now = timezone.now()
        updated = cls.objects.filter(token=token, expires_at__gt=now).update(
            expires_at=now, used_at=now
        )
        if not updated:
            return None
        try:
            return cls.objects.select_related('user').get(token=token).user
        except (cls.DoesNotExist, cls.MultipleObjectsReturned):
            return None


class GoogleDriveCredential(TimeStampedModel):
    """
    Stores OAuth 2.0 credentials for a user's connected Google Drive account.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='google_drive'
    )
    access_token = models.TextField()
    refresh_token = models.TextField(null=True, blank=True)
    token_uri = models.CharField(
        max_length=255, default='https://oauth2.googleapis.com/token'
    )
    client_id = models.CharField(max_length=255, blank=True)
    client_secret = models.CharField(max_length=255, blank=True)
    scopes = models.TextField(blank=True)
    expiry = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Google Drive Credential'
        verbose_name_plural = 'Google Drive Credentials'

    def __str__(self):
        return f'Google Drive ({self.user.email})'


