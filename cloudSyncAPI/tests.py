import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from .models import Invitation

PASSWORD = 'StrongPass#123'


class AuthAndProfileTests(APITestCase):
    def register(self, **extra):
        data = {
            'username': 'alice', 'email': 'alice@example.com',
            'password': PASSWORD, 'password2': PASSWORD,
        }
        data.update(extra)
        return self.client.post('/api/auth/register/', data, format='json')

    def login_and_auth(self, username='alice'):
        res = self.client.post(
            '/api/auth/login/', {'username': username, 'password': PASSWORD}, format='json'
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {res.data['access']}")
        return res.data

    def test_register_creates_free_profile(self):
        res = self.register()
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertNotIn('password', res.data)
        self.assertEqual(User.objects.get(username='alice').profile.user_type, 'free')

    def test_register_password_mismatch(self):
        res = self.register(password2='different')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_duplicate_email(self):
        self.register()
        res = self.register(username='bob', email='ALICE@example.com')
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_profile_requires_auth(self):
        self.assertEqual(self.client.get('/api/profile/').status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_and_update_profile(self):
        self.register()
        self.login_and_auth()
        res = self.client.get('/api/profile/')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['username'], 'alice')

        res = self.client.patch(
            '/api/profile/',
            {'profile': {'phone': '12345', 'country': 'India', 'user_type': 'paid'}},
            format='json',
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        profile = User.objects.get(username='alice').profile
        self.assertEqual(profile.phone, '12345')
        self.assertEqual(profile.country, 'India')
        self.assertEqual(profile.user_type, 'free')  # cannot self-upgrade

    def test_user_cannot_delete_profile(self):
        self.register()
        self.login_and_auth()
        res = self.client.delete('/api/profile/')
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertTrue(User.objects.filter(username='alice').exists())

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
        self.assertTrue(User.objects.get(username='alice').check_password('AnotherPass#456'))


class AdminAndUserTypeTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('admin', 'admin@example.com', PASSWORD)
        self.user = User.objects.create_user('bob', 'bob@example.com', PASSWORD)

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
        res = self.client.post('/api/auth/login/', {'username': 'bob', 'password': PASSWORD}, format='json')
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


# Paid User testcases for password less login


class PasswordlessLoginTests(APITestCase):
    REQUEST_URL = '/api/auth/passwordless/request/'
    VERIFY_URL = '/api/auth/passwordless/verify/'

    def setUp(self):
        cache.clear()  # reset throttle counters
        self.paid = User.objects.create_user('paiduser', 'paid@example.com', PASSWORD)
        self.paid.profile.user_type = 'paid'
        self.paid.profile.save()
        self.free = User.objects.create_user('freeuser', 'free@example.com', PASSWORD)

    def request_link(self, email='paid@example.com'):
        return self.client.post(self.REQUEST_URL, {'email': email}, format='json')

    def token_from_email(self, index=-1):
        match = re.search(r'token=([\w-]+)', mail.outbox[index].body)
        self.assertIsNotNone(match, 'no token found in the email body')
        return match.group(1)

    def verify(self, token):
        return self.client.get(self.VERIFY_URL, {'token': token})

    def test_paid_user_receives_link(self):
        res = self.request_link()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['paid@example.com'])
        raw = self.token_from_email()
        invitation = Invitation.objects.get(user=self.paid)
        self.assertNotEqual(invitation.token_hash, raw)  # only the hash is stored
        self.assertEqual(invitation.token_hash, Invitation.hash_token(raw))

    def test_email_lookup_is_case_insensitive(self):
        self.request_link('PAID@Example.com')
        self.assertEqual(len(mail.outbox), 1)

    def test_no_email_for_free_unknown_or_inactive_user(self):
        inactive = User.objects.create_user(
            'gone', 'gone@example.com', PASSWORD, is_active=False
        )
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
        self.assertEqual(res.data['username'], 'paiduser')

    def test_expired_invitation_is_rejected(self):
        self.request_link()
        token = self.token_from_email()
        Invitation.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.verify(token).status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_or_missing_token_is_rejected(self):
        self.assertEqual(self.verify('garbage').status_code, status.HTTP_400_BAD_REQUEST)
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
