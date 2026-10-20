import logging

from django.contrib.auth import get_user_model
from django.http import FileResponse
from rest_framework import mixins, status, viewsets
from rest_framework.generics import CreateAPIView, GenericAPIView, RetrieveUpdateAPIView
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.exceptions import TokenError

from .constants import Messages, THROTTLE_SCOPE_INVITATION
from .models import Profile
from .permissions import HasGoogleDriveConnected, IsPaidUser, user_has_google_drive, user_is_paid
from .serializers import (
    AdminUserSerializer, ChangePasswordSerializer, GoogleDriveFileListQuerySerializer,
    GoogleDriveFileUploadSerializer, GoogleDriveOAuthCallbackSerializer,
    GoogleDriveStatusSerializer, InvitationRequestSerializer,
    InvitationVerifySerializer, LogoutSerializer, RegisterSerializer, UserSerializer,
)
from .services import (
    delete_drive_file, disconnect_google_drive, download_drive_file,
    exchange_google_oauth_code, generate_google_oauth_url, list_drive_files,
    send_login_invitation, upload_drive_file, verify_invitation_login,
)

User = get_user_model()
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
            serializer.save()
        except TokenError:
            return Response(
                {'detail': Messages.INVALID_REFRESH_TOKEN},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({'detail': Messages.LOGGED_OUT})


class ChangePasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': Messages.PASSWORD_UPDATED})


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



# filter backend
    def get_queryset(self):
        qs = User.objects.select_related('profile').order_by('id')
        user_type = self.request.query_params.get('user_type')
        if user_type:
            qs = qs.filter(profile__user_type=user_type)
        return qs

    def destroy(self, request, *args, **kwargs):
        if self.get_object() == request.user:
            return Response(
                {'detail': Messages.CANNOT_DELETE_SELF},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)


class PaidPingView(GenericAPIView):
    """Tiny example of a paid-only endpoint; remove once real paid features exist."""

    permission_classes = [IsAuthenticated, IsPaidUser]

    def get(self, request):
        return Response({'detail': Messages.PAID_PING})


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
    throttle_scope = THROTTLE_SCOPE_INVITATION

    SUCCESS_RESPONSE = {
        'detail': Messages.LOGIN_LINK_SENT
    }

    DENIED_RESPONSE = {
        'detail': Messages.NOT_PAID_ACCOUNT
    }

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = (
            User.objects.select_related('profile')
            .filter(email__iexact=email, is_active=True)
            .first()
        )
        if user is not None and user_is_paid(user):
            send_login_invitation(user)
            return Response(self.SUCCESS_RESPONSE)

        return Response(self.DENIED_RESPONSE, status=status.HTTP_403_FORBIDDEN)

    # Backward compatibility alias
    _send_invitation = staticmethod(send_login_invitation)


class InvitationVerifyView(GenericAPIView):
    """Passwordless login, step 2: the link from the email. Single use."""

    serializer_class = InvitationVerifySerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        result = verify_invitation_login(serializer.validated_data['token'])
        if result is None:
            return Response(
                {'detail': Messages.LINK_INVALID_OR_EXPIRED},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, refresh = result
        response = Response({
            'detail': Messages.LOGGED_IN,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
        response['Cache-Control'] = 'no-store'
        return response


# ---------------------------------------------------------------------------
# Google Drive Views
# ---------------------------------------------------------------------------

class GoogleDriveConnectView(GenericAPIView):
    """
    Initiates Google OAuth 2.0 flow for the authenticated user.
    Returns the Google consent URL containing a signed CSRF state token.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        authorization_url, _ = generate_google_oauth_url(request.user)
        return Response({'authorization_url': authorization_url})


class GoogleDriveCallbackView(GenericAPIView):
    """
    OAuth 2.0 redirect endpoint. Google redirects here with ?code=...&state=...
    Exchanges authorization code for credentials and links Google Drive to the user.
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    serializer_class = GoogleDriveOAuthCallbackSerializer

    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        user, _ = exchange_google_oauth_code(
            code=serializer.validated_data['code'],
            state=serializer.validated_data['state'],
        )
        return Response({
            'detail': Messages.DRIVE_CONNECTED_SUCCESS,
            'email': user.email,
        })


class GoogleDriveStatusView(GenericAPIView):
    """
    GET: Checks if the user's Google Drive is connected and returns metadata.
    DELETE: Disconnects the user's Google Drive.
    """

    serializer_class = GoogleDriveStatusSerializer

    def get_permissions(self):
        if self.request.method == 'DELETE':
            return [IsAuthenticated(), HasGoogleDriveConnected()]
        return [IsAuthenticated()]

    def get(self, request):
        if user_has_google_drive(request.user):
            cred = request.user.google_drive
            data = {
                'is_connected': True,
                'expiry': cred.expiry,
                'created_at': cred.created_at,
                'updated_at': cred.updated_at,
            }
        else:
            data = {
                'is_connected': False,
                'expiry': None,
                'created_at': None,
                'updated_at': None,
            }
        serializer = self.get_serializer(data)
        return Response(serializer.data)

    def delete(self, request):
        disconnect_google_drive(request.user)
        return Response({'detail': Messages.DRIVE_DISCONNECTED_SUCCESS})


class GoogleDriveFilesView(GenericAPIView):
    """
    GET: Lists files in Google Drive. Available to both Free and Paid users.
    POST: Uploads a new file to Google Drive. Restricted to Paid users only.
          Triggers an email notification with the uploaded filename.
    """

    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated(), HasGoogleDriveConnected(), IsPaidUser()]
        return [IsAuthenticated(), HasGoogleDriveConnected()]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return GoogleDriveFileUploadSerializer
        return GoogleDriveFileListQuerySerializer

    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        data = list_drive_files(
            user=request.user,
            page_size=serializer.validated_data.get('page_size', 20),
            page_token=serializer.validated_data.get('page_token'),
            query=serializer.validated_data.get('query'),
        )
        return Response(data)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data['file']
        file_info = upload_drive_file(request.user, uploaded_file)
        return Response(
            {
                'detail': Messages.DRIVE_FILE_UPLOADED,
                'file': file_info,
            },
            status=status.HTTP_201_CREATED,
        )


class GoogleDriveFileDetailView(GenericAPIView):
    """
    GET: Downloads a file by ID. Available to both Free and Paid users.
    DELETE: Deletes a file by ID. Restricted to Paid users only.
            Triggers an email notification with the deleted filename.
    """

    def get_permissions(self):
        if self.request.method == 'DELETE':
            return [IsAuthenticated(), HasGoogleDriveConnected(), IsPaidUser()]
        return [IsAuthenticated(), HasGoogleDriveConnected()]

    def get(self, request, file_id):
        buffer, filename, mime_type = download_drive_file(request.user, file_id)
        return FileResponse(
            buffer,
            as_attachment=True,
            filename=filename,
            content_type=mime_type,
        )

    def delete(self, request, file_id):
        filename = delete_drive_file(request.user, file_id)
        return Response({
            'detail': Messages.DRIVE_FILE_DELETED,
            'file_name': filename,
        })

