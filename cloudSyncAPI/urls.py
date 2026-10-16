from django.urls import include, path
from rest_framework.routers import SimpleRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    AdminUserViewSet, ChangePasswordView, InvitationRequestView, InvitationVerifyView,
    LogoutView, PaidPingView, ProfileView, RegisterView,
)

router = SimpleRouter()
router.register('admin/users', AdminUserViewSet, basename='admin-user')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', TokenObtainPairView.as_view(), name='login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path(
        'auth/passwordless/request/',
        InvitationRequestView.as_view(),
        name='invitation-request',
    ),
    path(
        'auth/passwordless/verify/',
        InvitationVerifyView.as_view(),
        name='invitation-verify',
    ),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('paid/ping/', PaidPingView.as_view(), name='paid-ping'),
    path('', include(router.urls)),
]
