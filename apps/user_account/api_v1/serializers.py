from django.contrib.auth import get_user_model
from rest_framework import serializers
from apps.user_account.models import User as UserType,LoginHistory
from apps.user_account.functions import get_new_username,validate_phone,validate_email

User = get_user_model()


class UserSerializer(serializers.ModelSerializer[UserType]):
    password = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = ["id","full_name","username", "dob", "country_code","phone","phone_verified","email","email_verified","password"]

        extra_kwargs = {
            "url": {"view_name": "api:user-detail", "lookup_field": "username"},
            'password': {'write_only': True},
            'username': {'read_only': True},
            'phone_verified': {'read_only': True},
            'email_verified': {'read_only': True},
        }
          
    def create(self, validated_data):
        username = get_new_username()
        password = validated_data.pop('password', None)
        account = User(**validated_data,username=username)
        if password is not None:
            account.set_password(password)
        account.save()
        return account
    
    def update(self, instance, validated_data):
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email) 

        if(("phone" and "country_code" in validated_data) and (instance.phone+instance.country_code != validated_data["phone"]+validated_data["country_code"]) and (validate_phone(validated_data["country_code"],validated_data["phone"]))):
            instance.phone = validated_data.get('phone', instance.phone)
            instance.country_code = validated_data.get('country_code', instance.country_code)
            instance.phone_verified = False
        
        if(("email" and "country_code" in validated_data) and (instance.email != validated_data["email"]) and (validate_email(validated_data["country_code"],validated_data["email"]))):
            instance.email = validated_data.get('email', instance.email)
            instance.email_verified = False

        password = validated_data.pop('password', None)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
        

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


# class AccountPropertiesSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['username', 'email', 'password'] 
#         extra_kwargs = {
#             'password': {'write_only': True},
#         }
#     def update(self, instance, validated_data):
#         instance.email = validated_data.get('email', instance.email)
#         instance.username = validated_data.get('username', instance.username)
#         password = validated_data.get('password', None)
#         if password:
#             instance.set_password(password)
#         instance.save()
#         return instance
    


class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
    new_password = serializers.CharField(write_only=True)


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = '__all__'

