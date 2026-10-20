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

from .models import Invitation, Profile

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
        self.assertEqual(user.profile.user_type, Profile.UserType.FREE)

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
