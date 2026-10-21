import re
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from unittest.mock import MagicMock, patch

from .constants import DRIVE_DISCONNECTED_SUCCESS, DRIVE_FILE_DELETED, DRIVE_FILE_UPLOADED, DRIVE_NOT_CONNECTED, PAID_ONLY
from .models import GoogleDriveCredential, Invitation, Profile, UserType
from .services import GoogleDriveService, ProfileReminderService
from .tasks import send_incomplete_profile_reminders



User = get_user_model()

PASSWORD = 'StrongPass#123'


class UserManagerTests(TestCase):
    def test_create_user_uses_email_and_lowercases_it(self):
        user = User.objects.create_user('Bob@Example.COM', PASSWORD)
        self.assertEqual(user.email, 'bob@example.com')
        self.assertTrue(user.check_password(PASSWORD))
        self.assertNotEqual(user.password, PASSWORD)  # hashed
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_user_requires_email(self):
        with self.assertRaises(ValueError):
            User.objects.create_user('', PASSWORD)

    def test_create_superuser(self):
        admin = User.objects.create_superuser('admin@example.com', PASSWORD)
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

    def test_create_superuser_rejects_wrong_flags(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser('a@example.com', PASSWORD, is_staff=False)
        with self.assertRaises(ValueError):
            User.objects.create_superuser('b@example.com', PASSWORD, is_superuser=False)

    def test_login_field_is_email(self):
        self.assertEqual(User.USERNAME_FIELD, 'email')

    def test_profile_is_created_automatically_as_free(self):
        user = User.objects.create_user('bob@example.com', PASSWORD)
        self.assertEqual(user.profile.user_type, UserType.FREE)

    def test_email_is_unique_case_insensitively(self):
        User.objects.create_user('bob@example.com', PASSWORD)
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user('BOB@example.com', PASSWORD)

    def test_username_is_optional(self):
        first = User.objects.create_user('one@example.com', PASSWORD)
        second = User.objects.create_user('two@example.com', PASSWORD, username='')
        self.assertIsNone(first.username)
        self.assertIsNone(second.username)  # blank is stored as NULL, so no clash

    def test_username_is_unique_when_provided(self):
        User.objects.create_user('one@example.com', PASSWORD, username='bob')
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user('two@example.com', PASSWORD, username='bob')


class AuthAndProfileTests(APITestCase):
    def register(self, **extra):
        data = {
            'email': 'alice@example.com',
            'password': PASSWORD, 'password2': PASSWORD,
        }
        data.update(extra)
        return self.client.post('/api/auth/register/', data, format='json')

    def login(self, email='alice@example.com', password=PASSWORD):
        return self.client.post(
            '/api/auth/login/', {'email': email, 'password': password}, format='json'
        )

    def login_and_auth(self, email='alice@example.com'):
        res = self.login(email)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {res.data['access']}")
        return res.data

    def test_register_with_only_required_fields(self):
        res = self.register()
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertNotIn('password', res.data)
        user = User.objects.get(email='alice@example.com')
        self.assertIsNone(user.username)
        self.assertEqual(user.profile.user_type, 'free')

    def test_register_with_optional_fields(self):
        res = self.register(username='alice', first_name='Alice', last_name='A')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email='alice@example.com')
        self.assertEqual((user.username, user.first_name, user.last_name), ('alice', 'Alice', 'A'))

    def test_register_requires_email(self):
        res = self.client.post(
            '/api/auth/register/', {'password': PASSWORD, 'password2': PASSWORD}, format='json'
        )
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', res.data)

    def test_register_password_mismatch(self):
        res = self.register(password2='different')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_duplicate_email_is_case_insensitive(self):
        self.register()
        res = self.register(email='ALICE@example.com')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_duplicate_username(self):
        self.register(username='alice')
        res = self.register(email='bob@example.com', username='alice')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', res.data)

    def test_two_users_can_register_without_username(self):
        self.assertEqual(self.register().status_code, status.HTTP_201_CREATED)
        res = self.register(email='bob@example.com')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)

    def test_login_is_case_insensitive_on_email(self):
        self.register()
        self.assertEqual(self.login('ALICE@Example.com').status_code, status.HTTP_200_OK)

    def test_login_with_wrong_password_fails(self):
        self.register()
        self.assertEqual(self.login(password='wrong').status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_username_is_not_supported(self):
        self.register(username='alice')
        res = self.client.post(
            '/api/auth/login/', {'username': 'alice', 'password': PASSWORD}, format='json'
        )
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_profile_requires_auth(self):
        self.assertEqual(self.client.get('/api/profile/').status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_and_update_profile(self):
        self.register()
        self.login_and_auth()
        res = self.client.get('/api/profile/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['email'], 'alice@example.com')
        self.assertIsNone(res.data['username'])

        res = self.client.patch(
            '/api/profile/',
            {'profile': {'phone': '12345', 'country': 'India', 'user_type': 'paid'}},
            format='json',
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        profile = User.objects.get(email='alice@example.com').profile
        self.assertEqual(profile.phone, '12345')
        self.assertEqual(profile.country, 'India')
        self.assertEqual(profile.user_type, 'free')  # cannot self-upgrade

    def test_update_username_through_profile(self):
        self.register()
        self.login_and_auth()
        res = self.client.patch('/api/profile/', {'username': 'alice99'}, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['username'], 'alice99')

    def test_cannot_take_another_users_username_or_email(self):
        self.register(email='bob@example.com', username='bob')
        self.register()
        self.login_and_auth()
        res = self.client.patch('/api/profile/', {'username': 'bob'}, format='json')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        res = self.client.patch('/api/profile/', {'email': 'BOB@example.com'}, format='json')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_cannot_delete_profile(self):
        self.register()
        self.login_and_auth()
        res = self.client.delete('/api/profile/')
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertTrue(User.objects.filter(email='alice@example.com').exists())

    def test_logout_blacklists_refresh_token(self):
        self.register()
        tokens = self.login_and_auth()
        res = self.client.post('/api/auth/logout/', {'refresh': tokens['refresh']}, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.post('/api/auth/token/refresh/', {'refresh': tokens['refresh']}, format='json')
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_password(self):
        self.register()
        self.login_and_auth()
        res = self.client.post(
            '/api/auth/change-password/',
            {'old_password': PASSWORD, 'new_password': 'AnotherPass#456'},
            format='json',
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.get(email='alice@example.com').check_password('AnotherPass#456'))


class AdminAndUserTypeTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('admin@example.com', PASSWORD)
        self.user = User.objects.create_user('bob@example.com', PASSWORD)

    def test_normal_user_cannot_access_admin_api(self):
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.get('/api/admin/users/').status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_promotes_user_to_paid(self):
        self.client.force_authenticate(self.admin)
        res = self.client.patch(f'/api/admin/users/{self.user.id}/', {'user_type': 'paid'}, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.user_type, 'paid')

    def test_admin_filters_by_user_type(self):
        self.client.force_authenticate(self.admin)
        res = self.client.get('/api/admin/users/?user_type=free')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 2)

    def test_admin_deactivates_user_who_then_cannot_login(self):
        self.client.force_authenticate(self.admin)
        res = self.client.patch(f'/api/admin/users/{self.user.id}/', {'is_active': False}, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.client.force_authenticate(None)
        res = self.client.post(
            '/api/auth/login/', {'email': 'bob@example.com', 'password': PASSWORD}, format='json'
        )
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_admin_deletes_user(self):
        self.client.force_authenticate(self.admin)
        res = self.client.delete(f'/api/admin/users/{self.user.id}/')
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(pk=self.user.id).exists())

    def test_admin_cannot_delete_self(self):
        self.client.force_authenticate(self.admin)
        res = self.client.delete(f'/api/admin/users/{self.admin.id}/')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_paid_only_endpoint(self):
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.get('/api/paid/ping/').status_code, status.HTTP_403_FORBIDDEN)
        self.user.profile.user_type = 'paid'
        self.user.profile.save()
        self.assertEqual(self.client.get('/api/paid/ping/').status_code, status.HTTP_200_OK)


class DjangoAdminSiteTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('admin@example.com', PASSWORD)
        self.client.force_login(self.admin)

    def test_user_list_and_change_pages_load(self):
        user = User.objects.create_user('bob@example.com', PASSWORD)
        self.assertEqual(self.client.get('/admin/cloudSyncAPI/user/').status_code, 200)
        self.assertEqual(self.client.get(f'/admin/cloudSyncAPI/user/{user.pk}/change/').status_code, 200)

    def test_add_user_page_creates_user_and_profile(self):
        self.assertEqual(self.client.get('/admin/cloudSyncAPI/user/add/').status_code, 200)
        res = self.client.post('/admin/cloudSyncAPI/user/add/', {
            'email': 'New@Example.com', 'username': '',
            'usable_password': 'true', 'password1': PASSWORD, 'password2': PASSWORD,
        })
        self.assertEqual(res.status_code, 302)
        user = User.objects.get(email='new@example.com')
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(user.profile.user_type, 'free')

    def test_edit_user_in_admin_without_username(self):
        user = User.objects.create_user('bob@example.com', PASSWORD, first_name='Bob')
        url = f'/admin/cloudSyncAPI/user/{user.pk}/change/'
        res = self.client.post(url, {
            'email': 'Bob@Example.com', 'username': '', 'first_name': 'Robert',
            'last_name': '', 'is_active': 'on',
            'date_joined_0': '2024-01-01', 'date_joined_1': '00:00:00',
            'profile-TOTAL_FORMS': '1', 'profile-INITIAL_FORMS': '1',
            'profile-MIN_NUM_FORMS': '0', 'profile-MAX_NUM_FORMS': '1',
            'profile-0-id': user.profile.pk, 'profile-0-user': user.pk,
            'profile-0-user_type': 'paid', 'profile-0-phone': '', 'profile-0-bio': '',
            'profile-0-address': '', 'profile-0-country': '',
        })
        self.assertEqual(res.status_code, 302)
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'Robert')
        self.assertIsNone(user.username)
        self.assertEqual(user.email, 'bob@example.com')
        self.assertEqual(user.profile.user_type, 'paid')

    def test_invitation_admin_pages_load(self):
        self.assertEqual(self.client.get('/admin/cloudSyncAPI/invitation/').status_code, 200)


class PasswordlessLoginTests(APITestCase):
    REQUEST_URL = '/api/auth/passwordless/request/'
    VERIFY_URL = '/api/auth/passwordless/verify/'

    def setUp(self):
        cache.clear()  # reset throttle counters
        self.paid = User.objects.create_user('paid@example.com', PASSWORD, first_name='Paula')
        self.paid.profile.user_type = 'paid'
        self.paid.profile.save()
        self.free = User.objects.create_user('free@example.com', PASSWORD)

    def request_link(self, email='paid@example.com'):
        return self.client.post(self.REQUEST_URL, {'email': email}, format='json')

    def token_from_email(self, index=-1):
        match = re.search(r'token=([0-9a-f-]{36})', mail.outbox[index].body)
        self.assertIsNotNone(match, 'no token found in the email body')
        return match.group(1)

    def verify(self, token):
        return self.client.get(self.VERIFY_URL, {'token': token})

    def test_paid_user_receives_link(self):
        res = self.request_link()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['paid@example.com'])
        self.assertIn('Hello Paula', mail.outbox[0].body)
        invitation = Invitation.objects.get(user=self.paid)
        self.assertEqual(str(invitation.token), self.token_from_email())

    def test_email_lookup_is_case_insensitive(self):
        self.request_link('PAID@Example.com')
        self.assertEqual(len(mail.outbox), 1)

    def test_no_email_for_free_unknown_or_inactive_user(self):
        inactive = User.objects.create_user('gone@example.com', PASSWORD, is_active=False)
        inactive.profile.user_type = 'paid'
        inactive.profile.save()
        for email in ('free@example.com', 'nobody@example.com', 'gone@example.com'):
            self.assertEqual(self.request_link(email).status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(Invitation.objects.count(), 0)

    def test_non_paid_users_get_denied_message(self):
        free = self.request_link('free@example.com')
        unknown = self.request_link('nobody@example.com')
        self.assertEqual(free.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(free.data['detail'], 'This email does not belong to a paid account.')
        # An unknown email gets exactly the same response, so account existence is not revealed.
        self.assertEqual(free.data, unknown.data)
        self.assertEqual(free.status_code, unknown.status_code)

    def test_paid_user_gets_success_message(self):
        res = self.request_link('paid@example.com')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['detail'], 'A login link has been sent to your email.')

    def test_request_requires_valid_email(self):
        res = self.client.post(self.REQUEST_URL, {'email': 'not-an-email'}, format='json')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_link_works_only_once(self):
        self.request_link()
        token = self.token_from_email()

        first = self.verify(token)
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        self.assertEqual(first.data['detail'], 'Logged in successfully.')
        self.assertIn('access', first.data)
        self.assertIn('refresh', first.data)

        second = self.verify(token)
        self.assertEqual(second.status_code, status.HTTP_400_BAD_REQUEST)

    def test_click_expires_invitation_and_records_use(self):
        self.request_link()
        token = self.token_from_email()
        self.verify(token)
        invitation = Invitation.objects.get(user=self.paid)
        self.assertIsNotNone(invitation.used_at)
        self.assertLessEqual(invitation.expires_at, timezone.now())

    def test_returned_jwt_works_on_protected_endpoint(self):
        self.request_link()
        tokens = self.verify(self.token_from_email()).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        res = self.client.get('/api/profile/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['email'], 'paid@example.com')

    def test_expired_invitation_is_rejected(self):
        self.request_link()
        token = self.token_from_email()
        Invitation.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.verify(token).status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_or_missing_token_is_rejected(self):
        self.assertEqual(self.verify('garbage').status_code, status.HTTP_400_BAD_REQUEST)
        unknown_uuid = '00000000-0000-4000-8000-000000000000'
        self.assertEqual(self.verify(unknown_uuid).status_code, status.HTTP_400_BAD_REQUEST)
        res = self.client.get(self.VERIFY_URL)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_new_request_invalidates_previous_link(self):
        self.request_link()
        self.request_link()
        old, new = self.token_from_email(0), self.token_from_email(1)
        self.assertEqual(self.verify(old).status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(self.verify(new).status_code, status.HTTP_200_OK)

    def test_downgraded_user_cannot_use_link(self):
        self.request_link()
        token = self.token_from_email()
        self.paid.profile.user_type = 'free'
        self.paid.profile.save()
        self.assertEqual(self.verify(token).status_code, status.HTTP_400_BAD_REQUEST)

    def test_deactivated_user_cannot_use_link(self):
        self.request_link()
        token = self.token_from_email()
        self.paid.is_active = False
        self.paid.save()
        self.assertEqual(self.verify(token).status_code, status.HTTP_400_BAD_REQUEST)

    def test_request_endpoint_is_throttled(self):
        for _ in range(5):
            self.assertEqual(self.request_link().status_code, status.HTTP_200_OK)
        self.assertEqual(self.request_link().status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class GoogleDriveTests(APITestCase):
    CONNECT_URL = '/api/drive/connect/'
    CALLBACK_URL = '/api/drive/callback/'
    STATUS_URL = '/api/drive/status/'
    FILES_URL = '/api/drive/files/'
    FILE_DETAIL_URL = '/api/drive/files/{file_id}/'

    def setUp(self):
        self.free_user = User.objects.create_user('free@example.com', PASSWORD)
        self.free_user.profile.user_type = UserType.FREE
        self.free_user.profile.save()

        self.paid_user = User.objects.create_user('paid@example.com', PASSWORD)
        self.paid_user.profile.user_type = UserType.PAID
        self.paid_user.profile.save()

    def _attach_drive_credential(self, user):
        return GoogleDriveCredential.objects.create(
            user=user,
            access_token='ya29.mock_token',
            refresh_token='1//mock_refresh',
            token_uri='https://oauth2.googleapis.com/token',
            client_id='mock_client_id',
            client_secret='mock_client_secret',
            scopes='["https://www.googleapis.com/auth/drive"]',
            expiry=timezone.now() + timedelta(hours=1),
        )

    def test_unauthenticated_requests_are_rejected(self):
        self.assertEqual(self.client.get(self.CONNECT_URL).status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(self.client.get(self.STATUS_URL).status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(self.client.get(self.FILES_URL).status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(self.client.post(self.FILES_URL).status_code, status.HTTP_401_UNAUTHORIZED)
        detail_url = self.FILE_DETAIL_URL.format(file_id='file123')
        self.assertEqual(self.client.get(detail_url).status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(self.client.delete(detail_url).status_code, status.HTTP_401_UNAUTHORIZED)

    def test_drive_not_connected_returns_forbidden(self):
        # Paid user has no GoogleDriveCredential yet
        self.client.force_authenticate(user=self.paid_user)
        res = self.client.get(self.FILES_URL)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn(DRIVE_NOT_CONNECTED, str(res.data))

        # Free user has no GoogleDriveCredential yet
        self.client.force_authenticate(user=self.free_user)
        res = self.client.get(self.FILES_URL)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn(DRIVE_NOT_CONNECTED, str(res.data))

    @patch('cloudSyncAPI.services.GoogleDriveService.generate_oauth_url')
    def test_connect_endpoint_returns_auth_url(self, mock_gen_url):
        mock_gen_url.return_value = ('https://accounts.google.com/o/oauth2/v2/auth?test=1', 'state_abc')
        self.client.force_authenticate(user=self.paid_user)
        res = self.client.get(self.CONNECT_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('authorization_url', res.data)
        self.assertEqual(res.data['authorization_url'], 'https://accounts.google.com/o/oauth2/v2/auth?test=1')

    def test_status_endpoint_reports_connection_and_disconnects(self):
        self.client.force_authenticate(user=self.paid_user)

        # Before connection
        res = self.client.get(self.STATUS_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertFalse(res.data['is_connected'])

        # After connection
        self._attach_drive_credential(self.paid_user)
        res = self.client.get(self.STATUS_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data['is_connected'])

        # Disconnect
        del_res = self.client.delete(self.STATUS_URL)
        self.assertEqual(del_res.status_code, status.HTTP_200_OK)
        self.assertEqual(del_res.data['detail'], DRIVE_DISCONNECTED_SUCCESS)
        self.assertFalse(GoogleDriveCredential.objects.filter(user=self.paid_user).exists())

    @patch('cloudSyncAPI.services.GoogleDriveService.list_files')
    def test_free_user_can_list_files(self, mock_list):
        mock_list.return_value = {'files': [{'id': '1', 'name': 'test.txt'}], 'next_page_token': None}
        self._attach_drive_credential(self.free_user)
        self.client.force_authenticate(user=self.free_user)

        res = self.client.get(self.FILES_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data['files']), 1)
        self.assertEqual(res.data['files'][0]['name'], 'test.txt')

    @patch('cloudSyncAPI.services.GoogleDriveService.download_file')
    def test_free_user_can_download_file(self, mock_download):
        import io
        mock_download.return_value = (io.BytesIO(b'file content'), 'doc.txt', 'text/plain')
        self._attach_drive_credential(self.free_user)
        self.client.force_authenticate(user=self.free_user)

        res = self.client.get(self.FILE_DETAIL_URL.format(file_id='doc123'))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(b''.join(res.streaming_content), b'file content')

    def test_free_user_cannot_upload_file(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        self._attach_drive_credential(self.free_user)
        self.client.force_authenticate(user=self.free_user)

        dummy_file = SimpleUploadedFile('test.pdf', b'PDF dummy content', content_type='application/pdf')
        res = self.client.post(self.FILES_URL, {'file': dummy_file}, format='multipart')
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res.data['detail'], PAID_ONLY)

    def test_free_user_cannot_delete_file(self):
        self._attach_drive_credential(self.free_user)
        self.client.force_authenticate(user=self.free_user)

        res = self.client.delete(self.FILE_DETAIL_URL.format(file_id='file_xyz'))
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res.data['detail'], PAID_ONLY)

    @patch('cloudSyncAPI.services.GoogleDriveService.upload_file')
    def test_paid_user_can_upload_file(self, mock_upload):
        from django.core.files.uploadedfile import SimpleUploadedFile
        mock_upload.return_value = {'id': 'created123', 'name': 'report.docx'}
        self._attach_drive_credential(self.paid_user)
        self.client.force_authenticate(user=self.paid_user)

        dummy_file = SimpleUploadedFile('report.docx', b'Word doc content', content_type='application/msword')
        res = self.client.post(self.FILES_URL, {'file': dummy_file}, format='multipart')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['detail'], DRIVE_FILE_UPLOADED)
        self.assertEqual(res.data['file']['name'], 'report.docx')

    @patch('cloudSyncAPI.services.GoogleDriveService.delete_file')
    def test_paid_user_can_delete_file(self, mock_delete):
        mock_delete.return_value = 'old_report.docx'
        self._attach_drive_credential(self.paid_user)
        self.client.force_authenticate(user=self.paid_user)

        res = self.client.delete(self.FILE_DETAIL_URL.format(file_id='del123'))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['detail'], DRIVE_FILE_DELETED)
        self.assertEqual(res.data['file_name'], 'old_report.docx')

    def test_action_notifications_send_emails_with_filename(self):
        mail.outbox.clear()

        # 1. Test upload notification
        GoogleDriveService.send_action_notification(self.paid_user, action='uploaded', filename='quarterly_results.xlsx')
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, ['paid@example.com'])
        self.assertIn('Uploaded', email.subject)
        self.assertIn('quarterly_results.xlsx', email.body)
        self.assertIn('UPLOADED', email.body)

        # 2. Test delete notification
        GoogleDriveService.send_action_notification(self.paid_user, action='deleted', filename='deprecated_plan.pdf')
        self.assertEqual(len(mail.outbox), 2)
        delete_email = mail.outbox[1]
        self.assertEqual(delete_email.to, ['paid@example.com'])
        self.assertIn('Deleted', delete_email.subject)
        self.assertIn('deprecated_plan.pdf', delete_email.body)
        self.assertIn('DELETED', delete_email.body)

    @patch('cloudSyncAPI.tasks.send_drive_action_notification.delay')
    def test_drive_action_notification_is_queued_with_action_timestamp(self, mock_delay):
        GoogleDriveService._queue_action_notification(
            self.paid_user,
            action='deleted',
            filename='report.docx',
        )

        mock_delay.assert_called_once()
        user_id, action, filename, timestamp = mock_delay.call_args.args
        self.assertEqual(user_id, self.paid_user.pk)
        self.assertEqual(action, 'deleted')
        self.assertEqual(filename, 'report.docx')
        self.assertRegex(timestamp, r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$')

    @patch('cloudSyncAPI.services.GoogleDriveService.send_action_notification')
    @patch('cloudSyncAPI.tasks.send_drive_action_notification.delay', side_effect=RuntimeError('broker is down'))
    def test_drive_action_notification_falls_back_if_queue_is_unavailable(
        self,
        mock_delay,
        mock_send_notification,
    ):
        GoogleDriveService._queue_action_notification(
            self.paid_user,
            action='uploaded',
            filename='report.docx',
        )

        mock_delay.assert_called_once()
        mock_send_notification.assert_called_once()
        args, kwargs = mock_send_notification.call_args
        self.assertEqual(args[:3], (self.paid_user, 'uploaded', 'report.docx'))
        self.assertRegex(kwargs['timestamp_str'], r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$')


class ProfileCompletionReminderTests(TestCase):
    def setUp(self):
        cache.clear()
        mail.outbox.clear()
        self.user = User.objects.create_user('incomplete@example.com', PASSWORD)

    def test_get_missing_profile_fields_identifies_all_empty_fields(self):
        missing = ProfileReminderService.get_missing_fields(self.user)
        self.assertIn('Username', missing)
        self.assertIn('First Name', missing)
        self.assertIn('Last Name', missing)
        self.assertIn('Phone Number', missing)
        self.assertIn('Date of Birth', missing)
        self.assertIn('Bio', missing)

    def test_get_missing_profile_fields_returns_empty_when_completed(self):
        import datetime
        self.user.username = 'completeuser'
        self.user.first_name = 'John'
        self.user.last_name = 'Doe'
        self.user.save()

        profile = self.user.profile
        profile.phone = '+123456789'
        profile.date_of_birth = datetime.date(1995, 5, 20)
        profile.bio = 'Software Engineer'
        profile.save()

        missing = ProfileReminderService.get_missing_fields(self.user)
        self.assertEqual(missing, [])

    def test_send_profile_completion_reminder_sends_email(self):
        missing = ['Username', 'First Name', 'Phone Number']
        sent = ProfileReminderService.send_reminder(self.user, missing)
        self.assertTrue(sent)
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, [self.user.email])
        self.assertIn('complete your CloudSync profile', email.subject)
        self.assertIn('Username', email.body)
        self.assertIn('First Name', email.body)
        self.assertIn('Phone Number', email.body)

    def test_process_incomplete_profile_reminders_and_cooldown(self):
        # 1. First run sends 1 reminder
        sent = ProfileReminderService.process_all_reminders(cooldown_seconds=300)
        self.assertEqual(sent, 1)
        self.assertEqual(len(mail.outbox), 1)

        # 2. Immediate second run is blocked by Redis cache cooldown
        sent_again = ProfileReminderService.process_all_reminders(cooldown_seconds=300)
        self.assertEqual(sent_again, 0)
        self.assertEqual(len(mail.outbox), 1)  # No new email sent

    def test_celery_task_execution(self):
        count = send_incomplete_profile_reminders.apply(kwargs={'cooldown_seconds': 300}).get()
        self.assertEqual(count, 1)
        self.assertEqual(len(mail.outbox), 1)


