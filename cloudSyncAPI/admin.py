from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

from .models import Invitation, Profile


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False


class UserAdmin(BaseUserAdmin):
    inlines = [ProfileInline]
    list_display = BaseUserAdmin.list_display + ('user_type',)
    list_filter = BaseUserAdmin.list_filter + ('profile__user_type',)

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


admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    """Read-only view of passwordless login invitations, for debugging."""

    list_display = ('user', 'created_at', 'expires_at', 'used_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('user', 'token_hash', 'created_at', 'expires_at', 'used_at')

    def has_add_permission(self, request):
        return False
