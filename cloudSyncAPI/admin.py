from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .forms import UserAdminChangeForm, UserAdminCreationForm
from .models import GoogleDriveCredential, Invitation, Profile

User = get_user_model()


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False




@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    inlines = [ProfileInline]

    ordering = ('email',)
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'user_type')
    list_filter = BaseUserAdmin.list_filter + ('profile__user_type',)
    search_fields = ('email', 'username', 'first_name', 'last_name')

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'usable_password', 'password1', 'password2'),
        }),
    )

    @admin.display(description='User type', ordering='profile__user_type')
    def user_type(self, obj):
        profile = getattr(obj, 'profile', None)
        return profile.user_type if profile else '-'

    def get_inline_instances(self, request, obj=None):
        # The signal creates the profile on user creation; showing the inline on
        # the "add user" page would try to create a second one.
        if obj is None:
            return []
        return super().get_inline_instances(request, obj)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    """Read-only view of passwordless login invitations, for debugging."""

    list_display = ('user', 'created_at', 'expires_at', 'used_at')
    search_fields = ('user__email', 'user__username')
    exclude = ('token',)
    readonly_fields = ('user', 'created_at', 'expires_at', 'used_at')

    def has_add_permission(self, request):
        return False


@admin.register(GoogleDriveCredential)
class GoogleDriveCredentialAdmin(admin.ModelAdmin):
    """Admin view of connected Google Drive accounts, protecting raw tokens."""

    list_display = ('user', 'expiry', 'created_at', 'updated_at')
    search_fields = ('user__email', 'user__username')
    readonly_fields = (
        'user',
        'token_uri',
        'client_id',
        'client_secret',
        'scopes',
        'expiry',
        'created_at',
        'updated_at',
    )
    exclude = ('access_token', 'refresh_token')

    def has_add_permission(self, request):
        return False

