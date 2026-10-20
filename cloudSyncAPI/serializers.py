from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.tokens import RefreshToken

from .choices import UserType
from .models import Profile

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(
            queryset=User.objects.all(), lookup='iexact',
            message='A user with this email already exists.',
        )],
    )
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password2', 'username', 'first_name', 'last_name']
        extra_kwargs = {
            'username': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password2'):
            raise serializers.ValidationError({'password2': 'Passwords do not match.'})
        return attrs

    def create(self, validated_data):
        # create_user hashes the password; the post_save signal creates the Profile
        return User.objects.create_user(**validated_data)


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'user_type', 'phone', 'date_of_birth', 'bio', 'avatar',
            'address', 'country', 'created_at', 'updated_at',
        ]
        read_only_fields = ['user_type', 'created_at', 'updated_at']


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'profile']
        read_only_fields = ['id']

    def validate_email(self, value):
        qs = User.objects.filter(email__iexact=value).exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError('A user with this email already exists.')
        return value

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        profile, _ = Profile.objects.get_or_create(user=instance)
        for attr, value in profile_data.items():
            setattr(profile, attr, value)
        profile.save()
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])

    def validate_old_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError('Old password is incorrect.')
        return value

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)

    def save(self, **kwargs):
        RefreshToken(self.validated_data['refresh']).blacklist()


class AdminUserSerializer(serializers.ModelSerializer):
    user_type = serializers.ChoiceField(
        choices=UserType.choices, source='profile.user_type', required=False
    )

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'is_active', 'is_staff', 'date_joined', 'user_type',
        ]
        read_only_fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'is_staff', 'date_joined',
        ]

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if profile_data:
            profile, _ = Profile.objects.get_or_create(user=instance)
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
        return instance


class InvitationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class InvitationVerifySerializer(serializers.Serializer):
    token = serializers.UUIDField()


# ---------------------------------------------------------------------------
# Google Drive Serializers
# ---------------------------------------------------------------------------

class GoogleDriveStatusSerializer(serializers.Serializer):
    """Represents the status and metadata of a user's Google Drive connection."""

    is_connected = serializers.BooleanField()
    expiry = serializers.DateTimeField(allow_null=True, required=False)
    created_at = serializers.DateTimeField(allow_null=True, required=False)
    updated_at = serializers.DateTimeField(allow_null=True, required=False)


class GoogleDriveOAuthCallbackSerializer(serializers.Serializer):
    """Validates the redirect query parameters sent by Google OAuth."""

    code = serializers.CharField(required=False, default=None)
    state = serializers.CharField(required=True)
    error = serializers.CharField(required=False, allow_null=True, default=None)

    def validate(self, attrs):
        if attrs.get('error'):
            raise serializers.ValidationError({'error': f"Google OAuth error: {attrs['error']}"})
        if not attrs.get('code'):
            raise serializers.ValidationError({'code': 'Missing OAuth authorization code.'})
        return attrs


class GoogleDriveFileListQuerySerializer(serializers.Serializer):
    """Validates query parameters when listing files from Google Drive."""

    page_size = serializers.IntegerField(required=False, default=20, min_value=1, max_value=100)
    page_token = serializers.CharField(required=False, allow_blank=True, default=None)
    query = serializers.CharField(required=False, allow_blank=True, default=None)


class GoogleDriveFileUploadSerializer(serializers.Serializer):
    """Validates file upload payload for Google Drive."""

    file = serializers.FileField(required=True)

