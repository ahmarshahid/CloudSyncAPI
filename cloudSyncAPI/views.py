import logging

from django.conf import settings
from django.contrib.auth.models import User, update_last_login
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import mixins, status, viewsets
from rest_framework.generics import CreateAPIView, GenericAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Invitation, Profile
from .permissions import IsPaidUser, user_is_paid
from .serializers import (
    AdminUserSerializer, ChangePasswordSerializer, InvitationRequestSerializer,
    InvitationVerifySerializer, LogoutSerializer, RegisterSerializer, UserSerializer,
)

logger = logging.getLogger(__name__)


class RegisterView(CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            RefreshToken(serializer.validated_data['refresh']).blacklist()
        except TokenError:
            return Response(
                {'detail': 'Invalid or expired refresh token.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({'detail': 'Logged out successfully.'})


class ChangePasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response({'detail': 'Password updated successfully.'})


class ProfileView(RetrieveUpdateAPIView):
    """Read / update the logged-in user's own profile. No delete for normal users."""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Covers users created before the signal existed
        Profile.objects.get_or_create(user=self.request.user)
        return self.request.user


class AdminUserViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """
    Admin only.
      PATCH  {"is_active": false}     -> deactivate (reversible)
      PATCH  {"user_type": "paid"}    -> promote / demote
      DELETE                          -> permanently remove the user
    """

    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminUser]
    http_method_names = ['get', 'patch', 'delete', 'head', 'options']

    def get_queryset(self):
        qs = User.objects.select_related('profile').order_by('id')
        user_type = self.request.query_params.get('user_type')
        if user_type:
            qs = qs.filter(profile__user_type=user_type)
        return qs

    def destroy(self, request, *args, **kwargs):
        if self.get_object() == request.user:
            return Response(
                {'detail': 'You cannot delete your own account.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)


class PaidPingView(GenericAPIView):
    """Tiny example of a paid-only endpoint; remove once real paid features exist."""

    permission_classes = [IsAuthenticated, IsPaidUser]

    def get(self, request):
        return Response({'detail': 'Welcome, paid user!'})


class InvitationRequestView(GenericAPIView):
    """
    Passwordless login, step 1: send a one-time login link to a paid user's email.

    Paid users get the link and a success message. Any other email (free user, unknown
    email, inactive account) gets the same 403 response, so the response does not reveal
    whether an account exists for that email.
    """

    serializer_class = InvitationRequestSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'invitation'

    SUCCESS_RESPONSE = {
        'detail': 'A login link has been sent to your email.'
    }

    DENIED_RESPONSE = {
        'detail': 'This email does not belong to a paid account.'
    }

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        users = list(
            User.objects.select_related('profile').filter(email__iexact=email, is_active=True)
        )
        if len(users) == 1 and user_is_paid(users[0]):
            self._send_invitation(users[0])
            return Response(self.SUCCESS_RESPONSE)

        return Response(self.DENIED_RESPONSE, status=status.HTTP_403_FORBIDDEN)

    def _send_invitation(self, user):
        raw_token = Invitation.issue_for(user)
        link = f"{settings.SITE_URL.rstrip('/')}{reverse('invitation-verify')}?token={raw_token}"
        minutes = settings.INVITATION_EXPIRY_MINUTES
        try:
            send_mail(
                subject='Your login link',
                message=(
                    f'Hello {user.username},\n\n'
                    f'Click the link below to log in. It can be used once and expires '
                    f'in {minutes} minutes.\n\n{link}\n\n'
                    f'If you did not request this, you can ignore this email.'
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
        except Exception:
            # A mail failure must not turn into a 500; it is logged for the developer.
            logger.exception('Failed to send login invitation to user %s', user.pk)


class InvitationVerifyView(GenericAPIView):
    """Passwordless login, step 2: the link from the email. Single use."""

    serializer_class = InvitationVerifySerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        user = Invitation.consume(serializer.validated_data['token'])
        # Eligibility is re-checked at click time (user may have been downgraded/deactivated).
        if user is None or not user_is_paid(user):
            return Response(
                {'detail': 'This login link is invalid or has expired.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        update_last_login(None, user)
        refresh = RefreshToken.for_user(user)
        response = Response({
            'detail': 'Logged in successfully.',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
        response['Cache-Control'] = 'no-store'
        return response
