from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm, UsernameField

User = get_user_model()


class OptionalUsernameField(UsernameField):
    """Django's UsernameField assumes a required username; ours may be left empty."""

    def to_python(self, value):
        if value in self.empty_values:
            return None
        return super().to_python(value)


class UserAdminCreationForm(AdminUserCreationForm):
    """Admin "add user" form for the email-based custom user."""

    class Meta(AdminUserCreationForm.Meta):
        model = User
        fields = ('email', 'username')
        field_classes = {'username': OptionalUsernameField}

    def clean_email(self):
        # Emails are stored in lowercase, so compare them that way too.
        return self.cleaned_data['email'].lower()


class UserAdminChangeForm(UserChangeForm):
    """Admin "change user" form for the email-based custom user."""

    class Meta(UserChangeForm.Meta):
        model = User
        field_classes = {'username': OptionalUsernameField}

    def clean_email(self):
        return self.cleaned_data['email'].lower()
