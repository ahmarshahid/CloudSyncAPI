import datetime
import io
import json
import logging
import random
import string

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.urls import reverse
from django.utils import timezone
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import (
    DRIVE_AUTH_FAILED, DRIVE_FILE_NOT_FOUND, DRIVE_NOT_CONNECTED,
    DRIVE_STATE_MISMATCH, GOOGLE_DRIVE_SCOPES, INVITATION_EXPIRY_MINUTES,
)
from .models import GoogleDriveCredential, Invitation
from .permissions import user_is_paid

logger = logging.getLogger(__name__)
User = get_user_model()


# ===========================================================================
# 1. Invitation & Passwordless Login Service
# ===========================================================================

class InvitationService:
    """
    Handles issuance, email delivery, and verification of single-use
    passwordless login invitation links.
    """

    @staticmethod
    def send_invitation(user):
        """
        Issues an invitation token, builds the magic link,
        and sends the one-time login email.
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
            logger.exception('Failed to send login invitation to user %s', user.pk)
        return token

    @staticmethod
    def verify_token(token):
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


# ===========================================================================
# 2. Google Drive Service
# ===========================================================================

class GoogleDriveService:
    """
    Manages OAuth 2.0 handshake, credentials synchronization,
    API client sessions, and Drive file operations (list, download, upload, delete).
    Can be used statically or instantiated with a user: `GoogleDriveService(user)`.
    """

    def __init__(self, user=None):
        self.user = user

    def _resolve_user(self, user=None):
        resolved = user or self.user
        if not resolved:
            raise ValidationError({'detail': 'User context is required for this operation.'})
        return resolved

    # -----------------------------------------------------------------------
    # Credential Translation Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def build_credentials(drive_credential):
        """
        Constructs a google.oauth2.credentials.Credentials instance
        from a GoogleDriveCredential model. Converts timezone-aware expiry
        to naive UTC to satisfy Google SDK requirements.
        """
        scopes = []
        if drive_credential.scopes:
            try:
                scopes = json.loads(drive_credential.scopes)
            except (ValueError, TypeError):
                scopes = drive_credential.scopes.split()

        expiry = drive_credential.expiry
        if expiry is not None and timezone.is_aware(expiry):
            expiry = expiry.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        return Credentials(
            token=drive_credential.access_token,
            refresh_token=drive_credential.refresh_token,
            token_uri=drive_credential.token_uri,
            client_id=drive_credential.client_id,
            client_secret=drive_credential.client_secret,
            scopes=scopes,
            expiry=expiry,
        )

    @staticmethod
    def update_tokens(drive_credential, credentials):
        """
        Updates stored tokens on a GoogleDriveCredential model from a refreshed
        google.oauth2.credentials.Credentials instance.
        """
        drive_credential.access_token = credentials.token
        if credentials.refresh_token:
            drive_credential.refresh_token = credentials.refresh_token
        if credentials.expiry:
            expiry = credentials.expiry
            if timezone.is_naive(expiry):
                expiry = timezone.make_aware(expiry, datetime.timezone.utc)
            drive_credential.expiry = expiry
        drive_credential.save(
            update_fields=['access_token', 'refresh_token', 'expiry', 'updated_at']
        )

    # -----------------------------------------------------------------------
    # OAuth 2.0 Flow
    # -----------------------------------------------------------------------

    @staticmethod
    def get_oauth_flow(state=None):
        """Instantiates a Google OAuth 2.0 Flow configured from Django settings."""
        client_config = {
            'web': {
                'client_id': settings.GOOGLE_CLIENT_ID,
                'client_secret': settings.GOOGLE_CLIENT_SECRET,
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [settings.GOOGLE_REDIRECT_URI],
            }
        }
        flow = Flow.from_client_config(
            client_config,
            scopes=GOOGLE_DRIVE_SCOPES,
            state=state,
        )
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        return flow

    @classmethod
    def generate_oauth_url(cls, user=None):
        """
        Generates the Google OAuth 2.0 authorization URL for connecting a user's Google Drive.
        Embeds a cryptographically signed state token with the user's ID and PKCE code_verifier.
        """
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise ValidationError({
                'detail': 'Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.'
            })

        flow = cls.get_oauth_flow()

        # Generate PKCE code verifier and attach to flow
        chars = string.ascii_letters + string.digits + '-._~'
        rnd = random.SystemRandom()
        code_verifier = ''.join(rnd.choice(chars) for _ in range(128))
        flow.code_verifier = code_verifier
        #use django default signing.....

        signer = TimestampSigner()
        state = signer.sign_object({'user_id': user.pk, 'code_verifier': code_verifier})

        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            state=state,
        )
        return authorization_url, state

    @classmethod
    def exchange_code(cls, code, state):
        """
        Exchanges authorization code for tokens, verifies state signature and PKCE verifier,
        and stores/updates GoogleDriveCredential for the user.
        """
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise ValidationError({
                'detail': 'Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.'
            })

        signer = TimestampSigner()
        try:
            data = signer.unsign_object(state, max_age=900)  # valid for 15 minutes
        except (BadSignature, SignatureExpired):
            raise ValidationError({'detail': DRIVE_STATE_MISMATCH})

        user_id = data.get('user_id')
        code_verifier = data.get('code_verifier')

        user = User.objects.filter(pk=user_id).first()
        if not user:
            raise ValidationError({'detail': 'User matching this OAuth request was not found.'})

        flow = cls.get_oauth_flow(state=state)
        if code_verifier:
            flow.code_verifier = code_verifier

        try:
            flow.fetch_token(code=code)
        except Exception as exc:
            logger.exception('Failed to fetch Google OAuth token: %s', exc)
            raise ValidationError({'detail': f'{DRIVE_AUTH_FAILED}: {str(exc)}'})

        credentials = flow.credentials
        scopes_json = json.dumps(
            list(credentials.scopes) if credentials.scopes else GOOGLE_DRIVE_SCOPES
        )

        expiry = credentials.expiry
        if expiry is not None and timezone.is_naive(expiry):
            expiry = timezone.make_aware(expiry, datetime.timezone.utc)

        drive_credential, _ = GoogleDriveCredential.objects.update_or_create(
            user=user,
            defaults={
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id or settings.GOOGLE_CLIENT_ID,
                'client_secret': credentials.client_secret or settings.GOOGLE_CLIENT_SECRET,
                'scopes': scopes_json,
                'expiry': expiry,
            },
        )
        return user, drive_credential

    @classmethod
    def disconnect_user(cls, user):
        """Disconnects Google Drive for a user by removing their stored credentials."""
        try:
            drive_credential = user.google_drive
        except GoogleDriveCredential.DoesNotExist:
            raise ValidationError({'detail': DRIVE_NOT_CONNECTED})

        drive_credential.delete()
        return True

    def disconnect(self, user=None):
        return self.disconnect_user(self._resolve_user(user))

    # -----------------------------------------------------------------------
    # API Client & File Operations
    # -----------------------------------------------------------------------

    @classmethod
    def get_api_client(cls, user):
        """
        Returns an authorized Google Drive v3 API resource service for the given user.
        Auto-refreshes the access token if expired and saves the new token to the DB.
        """
        try:
            drive_credential = user.google_drive
        except GoogleDriveCredential.DoesNotExist:
            raise ValidationError({'detail': DRIVE_NOT_CONNECTED})

        credentials = cls.build_credentials(drive_credential)
        try:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                cls.update_tokens(drive_credential, credentials)
        except Exception as exc:
            logger.exception('Failed to refresh Google Drive token for user %s: %s', user.pk, exc)
            raise ValidationError({'detail': DRIVE_AUTH_FAILED})

        try:
            return build('drive', 'v3', credentials=credentials, cache_discovery=False)
        except Exception as exc:
            logger.exception('Failed to build Google Drive API client for user %s: %s', user.pk, exc)
            raise ValidationError({'detail': f'{DRIVE_AUTH_FAILED}: {str(exc)}'})

    @classmethod
    def list_files(cls, user=None, page_size=20, page_token=None, query=None):
        """Lists files in the user's connected Google Drive account."""
        service = cls.get_api_client(user)
        q_parts = ['trashed = false']
        if query:
            safe_query = query.replace("'", "\\'")
            q_parts.append(f"name contains '{safe_query}'")
        q = ' and '.join(q_parts)

        try:
            results = (
                service.files()
                .list(
                    q=q,
                    pageSize=page_size,
                    pageToken=page_token,
                    fields='nextPageToken, files(id, name, mimeType, size, createdTime, modifiedTime, webViewLink, iconLink)',
                )
                .execute()
            )
        except HttpError as exc:
            logger.exception('Error listing Google Drive files: %s', exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})
        except Exception as exc:
            logger.exception('Unexpected error listing Google Drive files: %s', exc)
            raise ValidationError({'detail': f'Google Drive error: {str(exc)}'})

        return {
            'files': results.get('files', []),
            'next_page_token': results.get('nextPageToken'),
        }

    @classmethod
    def download_file(cls, user, file_id=None):
        """
        Downloads binary file content and metadata from Google Drive.
        Supports both download_file(user, file_id) and service.download_file(file_id).
        """
        if isinstance(user, str) and file_id is not None:
            user, file_id = file_id, user

        service = cls.get_api_client(user)
        try:
            meta = service.files().get(fileId=file_id, fields='id, name, mimeType, size').execute()
        except HttpError as exc:
            if exc.resp.status == 404:
                raise NotFound({'detail': DRIVE_FILE_NOT_FOUND})
            logger.exception('Error fetching file metadata for %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})

        try:
            request = service.files().get_media(fileId=file_id)
            buffer = io.BytesIO()
            downloader = MediaIoBaseDownload(buffer, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            buffer.seek(0)
            return (
                buffer,
                meta.get('name', 'downloaded_file'),
                meta.get('mimeType', 'application/octet-stream'),
            )
        except HttpError as exc:
            if exc.resp.status == 404:
                raise NotFound({'detail': DRIVE_FILE_NOT_FOUND})
            logger.exception('Error downloading Google Drive file %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})

    @classmethod
    def upload_file(cls, user, uploaded_file=None):
        """
        Uploads a new file to Google Drive and triggers an email notification to the user.
        Supports upload_file(user, uploaded_file) and service.upload_file(uploaded_file).
        """
        if uploaded_file is None:
            user, uploaded_file = None, user

        service = cls.get_api_client(user)
        try:
            file_metadata = {'name': uploaded_file.name}
            media = MediaIoBaseUpload(
                uploaded_file,
                mimetype=uploaded_file.content_type or 'application/octet-stream',
                resumable=True,
            )
            created_file = (
                service.files()
                .create(
                    body=file_metadata,
                    media_body=media,
                    fields='id, name, mimeType, size, createdTime, modifiedTime, webViewLink',
                )
                .execute()
            )
        except HttpError as exc:
            logger.exception('Error uploading Google Drive file: %s', exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})
        except Exception as exc:
            logger.exception('Unexpected error uploading Google Drive file: %s', exc)
            raise ValidationError({'detail': f'Google Drive error: {str(exc)}'})

        cls._queue_action_notification(user, action='uploaded', filename=uploaded_file.name)
        return created_file

    @classmethod
    def delete_file(cls, user, file_id=None):
        """
        Deletes a file from Google Drive and triggers an email notification to the user.
        Supports delete_file(user, file_id) and service.delete_file(file_id).
        """
        if isinstance(user, str) and file_id is not None:
            user, file_id = file_id, user

        service = cls.get_api_client(user)
        try:
            meta = service.files().get(fileId=file_id, fields='name').execute()
            filename = meta.get('name', file_id)
        except HttpError as exc:
            if exc.resp.status == 404:
                raise NotFound({'detail': DRIVE_FILE_NOT_FOUND})
            logger.exception('Error fetching file metadata for delete %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})
        except Exception as exc:
            logger.exception('Unexpected error fetching file metadata for delete %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive error: {str(exc)}'})

        try:
            service.files().delete(fileId=file_id).execute()
        except HttpError as exc:
            if exc.resp.status == 404:
                raise NotFound({'detail': DRIVE_FILE_NOT_FOUND})
            logger.exception('Error deleting Google Drive file %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive API error: {exc.reason}'})
        except Exception as exc:
            logger.exception('Unexpected error deleting Google Drive file %s: %s', file_id, exc)
            raise ValidationError({'detail': f'Google Drive error: {str(exc)}'})
        cls._queue_action_notification(user, action='deleted', filename=filename)
        return filename

    @staticmethod
    def _queue_action_notification(user, action, filename):
        """Queue a Drive notification, falling back to the existing sync path."""
        timestamp_str = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        try:
            # Import lazily to avoid a circular import: tasks also use services.
            from .tasks import send_drive_action_notification

            send_drive_action_notification.delay(user.pk, action, filename, timestamp_str)
        except Exception:
            logger.exception(
                'Failed to enqueue file %s notification for user %s; sending synchronously',
                action,
                user.pk,
            )
            GoogleDriveService.send_action_notification(
                user,
                action,
                filename,
                timestamp_str=timestamp_str,
            )

    @staticmethod
    def send_action_notification(user, action, filename, timestamp_str=None, raise_on_error=False):
        """
        Sends an email notification to the user after a write or delete operation
        on their connected Google Drive.
        """
        subject = f'Google Drive Notification: File {action.capitalize()}'
        if timestamp_str is None:
            timestamp_str = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        message = (
            f'Hello {user.first_name or user.username or user.email},\n\n'
            f'A file action was recently performed on your connected Google Drive account:\n\n'
            f'  • Action: {action.upper()}\n'
            f'  • File Name: {filename}\n'
            f'  • Timestamp: {timestamp_str}\n\n'
            f'If you did not perform this action, please review your Google Drive security settings.\n\n'
            f'Best regards,\nCloudSyncAPI Team'
        )
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
        except Exception:
            logger.exception('Failed to send file %s notification email to %s', action, user.email)
            if raise_on_error:
                raise


# ===========================================================================
# 3. Profile Completion Reminder Service (Celery Beat)
# ===========================================================================

class ProfileReminderService:
    """
    Scans active users for incomplete profile fields, respects Redis cooldowns
    to prevent spam, and dispatches completion reminder emails.
    """
    
    @staticmethod
    def get_missing_fields(user):
        """
        Checks if a user has missing profile fields.
        Monitors: username, first_name, last_name, phone, date_of_birth, bio.
        Returns a list of missing human-readable field labels.
        """
        profile = getattr(user, 'profile', None)
        checks = [
            ('Username', user.username),
            ('First Name', user.first_name),
            ('Last Name', user.last_name),
            ('Phone Number', profile.phone if profile else None),
            ('Date of Birth', profile.date_of_birth if profile else None),
            ('Bio', profile.bio if profile else None),
        ]
        return [label for label, value in checks if not value]

    @staticmethod
    def send_reminder(user, missing_fields):
        """
        Sends an email to the user listing their missing profile fields
        and urging them to complete their account setup.
        """
        subject = 'Please complete your CloudSync profile'
        fields_list = '\n'.join(f'  • {field}' for field in missing_fields)
        message = (
            f'Hello {user.first_name or user.username or user.email},\n\n'
            f'We noticed that your CloudSync profile is missing some important information:\n\n'
            f'{fields_list}\n\n'
            f'Completing your profile ensures full account features and seamless synchronization.\n\n'
            f'Please log in to your account to update your profile.\n\n'
            f'Best regards,\n'
            f'CloudSyncAPI Team'
        )
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
            return True
        except Exception:
            logger.exception('Failed to send profile completion reminder to %s', user.email)
            return False

    @classmethod
    def process_all_reminders(cls, cooldown_seconds=300):
        """
        Finds active users with incomplete profiles, checks Redis cache to prevent spamming,
        sends reminder emails, and updates cache cooldown.
        Returns the count of reminders successfully dispatched.
        """
        users = User.objects.filter(is_active=True).select_related('profile')
        sent_count = 0

        for user in users:
            cache_key = f'profile_reminder:{user.pk}'
            if cache.get(cache_key):
                # Already reminded recently within cooldown, skip
                continue

            missing = cls.get_missing_fields(user)
            if missing:
                success = cls.send_reminder(user, missing)
                if success:
                    cache.set(cache_key, True, timeout=cooldown_seconds)
                    sent_count += 1

        return sent_count


