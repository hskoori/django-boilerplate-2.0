from django.contrib.auth import get_user_model
from rest_framework import serializers

from apps.user_account.models import User as UserType,LoginHistory
from django.contrib.sessions.models import Session
from django.contrib.sessions.backends.db import SessionStore


User = get_user_model()


class UserSerializer(serializers.ModelSerializer[UserType]):

    password = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = ["full_name","username", "dob", "phone","email","password"]

        extra_kwargs = {
            "url": {"view_name": "api:user-detail", "lookup_field": "username"},
            'password': {'write_only': True},
        }
          
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        account = User(**validated_data)
        if password is not None:
            account.set_password(password)
        account.save()
        return account
# class PhoneLoginSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = [
#             "phone", "password",
#         ]

# class EmailLoginSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = [
#             "email", "password",
#         ]


class AccountPropertiesSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password'] 

        extra_kwargs = {
            'password': {'write_only': True},
        }

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.username = validated_data.get('username', instance.username)
        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)

        instance.save()
        return instance
    

class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
    new_password = serializers.CharField(write_only=True)

class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = '__all__'
        # fields = ['login_date', 'ip_address', 'login_method']