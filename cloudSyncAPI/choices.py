from django.db import models


class UserType(models.TextChoices):
    FREE = 'free', 'Free'
    PAID = 'paid', 'Paid'
