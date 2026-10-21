"""
Application constants and defaults for CloudSyncAPI.

Keep this module free of Django runtime/model imports so that it can be safely
imported anywhere (including config/settings.py).
"""

import os

# Business logic constants
INVITATION_EXPIRY_MINUTES = 10

# Default configuration values (can be overridden via environment/.env)
DEFAULT_PAGE_SIZE = 20
DEFAULT_SITE_URL = 'http://127.0.0.1:8000'
DEFAULT_FROM_EMAIL_FALLBACK = 'no-reply@cloudsync.local'

# Throttle configuration
THROTTLE_SCOPE_INVITATION = 'invitation'
DEFAULT_THROTTLE_RATE_INVITATION = '5/hour'

# Google Drive Configuration
GOOGLE_DRIVE_SCOPES = ['https://www.googleapis.com/auth/drive']
DEFAULT_GOOGLE_REDIRECT_URI = 'http://localhost:8000/api/drive/callback/'


"""Standardized API response messages."""
LOGIN_LINK_SENT = 'A login link has been sent to your email.'
NOT_PAID_ACCOUNT = 'This email does not belong to a paid account.'
LINK_INVALID_OR_EXPIRED = 'This login link is invalid or has expired.'
PAID_ONLY = 'This feature is available for paid users only.'
PAID_PING = 'Welcome, paid user!'
LOGGED_OUT = 'Logged out successfully.'
LOGGED_IN = 'Logged in successfully.'
PASSWORD_UPDATED = 'Password updated successfully.'
INVALID_REFRESH_TOKEN = 'Invalid or expired refresh token.'
CANNOT_DELETE_SELF = 'You cannot delete your own account.'

# Google Drive messages
DRIVE_ALREADY_CONNECTED = 'Google Drive is already connected for this user.'
DRIVE_NOT_CONNECTED = 'Google Drive is not connected. Please connect your Google Drive first.'
DRIVE_CONNECTED_SUCCESS = 'Google Drive connected successfully.'
DRIVE_DISCONNECTED_SUCCESS = 'Google Drive disconnected successfully.'
DRIVE_AUTH_FAILED = 'Failed to authenticate with Google Drive.'
DRIVE_STATE_MISMATCH = 'Invalid or expired OAuth state parameter.'
DRIVE_FILE_UPLOADED = 'File uploaded successfully.'
DRIVE_FILE_DELETED = 'File deleted successfully.'
DRIVE_FILE_NOT_FOUND = 'File not found in Google Drive.'
