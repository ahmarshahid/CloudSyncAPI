from datetime import timedelta
from uuid import uuid4

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone

from .choices import UserType
from .constants import (
    INVITATION_EXPIRY_MINUTES,
    MAX_LENGTH_ADDRESS,
    MAX_LENGTH_COUNTRY,
    MAX_LENGTH_PHONE,
    MAX_LENGTH_USER_TYPE,
)


class UserManager(BaseUserManager):
    """Manager for a user model that logs in with an email address instead of a username."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The email address must be set.')
        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, password, **extra_fields)

    def get_by_natural_key(self, email):
        # Used by authentication; makes login case-insensitive.
        return self.get(**{f'{self.model.USERNAME_FIELD}__iexact': email})


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


class Profile(models.Model):
    UserType = UserType  # Backward compatibility alias

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    user_type = models.CharField(
        max_length=MAX_LENGTH_USER_TYPE, choices=UserType.choices, default=UserType.FREE
    )

    # Optional fields, filled in after registration
    phone = models.CharField(max_length=MAX_LENGTH_PHONE, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    address = models.CharField(max_length=MAX_LENGTH_ADDRESS, blank=True)
    country = models.CharField(max_length=MAX_LENGTH_COUNTRY, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.email} ({self.user_type})'


# For Paid User Passwordless Login
class Invitation(models.Model):
    """
    One-time passwordless login link for paid users.

    The link carries ``token`` (a random UUID4). An invitation is valid while
    ``expires_at`` is in the future. Clicking it sets ``expires_at`` to "now", which
    makes it expired (single use).
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invitations')
    token = models.UUIDField(default=uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
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
