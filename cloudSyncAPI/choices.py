from django.db.models import TextChoices


class UserType(TextChoices):
    FREE = 'free', 'Free'
    PAID = 'paid', 'Paid'
