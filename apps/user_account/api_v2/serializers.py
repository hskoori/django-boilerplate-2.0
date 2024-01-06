from django.contrib.auth import get_user_model
from rest_framework import serializers

from apps.user_account.models import User as UserType


User = get_user_model()


class UserSerializer(serializers.ModelSerializer[UserType]):
    class Meta:
        model = User
        fields = ["full_name", "dob", "phone","email",]

        extra_kwargs = {
            "url": {"view_name": "api:user-detail", "lookup_field": "username"},
        }
