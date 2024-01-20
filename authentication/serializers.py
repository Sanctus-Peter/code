import base64
import re

from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from decouple import config
import pyotp
from django.conf import settings
from grito_talent_pool_server.utils import (
    custom_normalize_email,
    GenerateKey, send_otp_email
)
from .mixins import OTPVerificationMixin
from .models import User


class SuperAdminRegistrationSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = "__all__"

    def send_otp_email(self, user):
        key = self.generate_key(user)
        send_otp_email(user.email, key, user.name)

        user_data = self.get_user_data(user)
        user_data["otp_code"] = key

    @staticmethod
    def generate_key(user):
        keygen = OTPVerificationMixin()
        key = keygen.generate_key(user)
        return key

    @staticmethod
    def get_user_data(user):
        serializer = UserUpdateVerifiedSerializer(user)
        user_data = serializer.data
        user_data["otp_code"] = None
        return user_data

    @staticmethod
    def validate__password(value):
        password_pattern = r'^(?=.*?[A-Z])(?=(.*[a-z]){1,})(?=(.*[\d]){1,})(?=(.*[\W]){1,})(?!.*\s).{8,}$'
        if re.match(password_pattern, value) is None:
            return 406, "Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character."
        return value

    def create(self, validated_data):
        email = custom_normalize_email(validated_data["email"])

        existing_user = User.objects.filter(email=email).exists()
        if existing_user:
            return 406, "User with the provided email already exists."

        password = validated_data.pop("password")
        validated_password = self.validate__password(password)
        if isinstance(validated_password, tuple):
            return validated_password[0], validated_password[1]
        user = User.objects.create(**validated_data)
        user.set_password(validated_password)
        user.is_verified = False
        user.user_type = "super-admin"
        user.is_superuser = True
        user.is_active = True
        user.is_staff = True
        user.save()

        group, _ = Group.objects.get_or_create(name="super-admin")
        user.groups.add(group)

        self.send_otp_email(user)
        user_data = self.get_user_data(user)

        return 200, user_data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class UserUpdateVerifiedSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = ('__all__')
        exclude = (
            "is_active",
            "password",
            "is_superuser",
            "user_permissions",
            "groups",
        )


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def save(self, user):
        password_1 = self.validated_data["password"]
        password_2 = self.validated_data["confirm_password"]

        if password_1 == password_2:
            user.set_password(password_1)
            user.is_email_verified = True
            user.save()

            return user.name


class EmailandPhoneNumberSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)


class OTPVerificationSerializer(serializers.Serializer):
    otp_code = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    @staticmethod
    def get_name(user_data):
        name = ''
        if user_data.user_type == 'customer':
            name = user_data.first_name + ' ' + user_data.last_name
        elif user_data.user_type == 'business':
            name = user_data.business_name
        elif user_data.user_type == 'super-admin':
            name = user_data.name + ' ' + '(Admin)'

        return name

    def validate(self, data):
        otp_code = data["otp_code"]
        email = data.get("email", None)

        user = None
        user_mode = None

        if email:
            user_mode = "email"
            user = User.objects.filter(email=email).first()

        if not user:
            raise ValidationError(f"User with the provided {user_mode} does not exist")

        otp_mixin = OTPVerificationMixin()
        verified_user = otp_mixin.verify_otp(user, otp_code)
        user.is_verified = True
        user.save()

        return {
            "user": verified_user,
            "user_mode": user_mode,
            'name': self.get_name(verified_user)
        }


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist")

    def resend_otp(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        self.send_otp_email(user)

    def send_otp_email(self, user):
        key = self.generate_key(user)
        send_otp_email(user.email, key, user.name)

    @staticmethod
    def generate_key(user):
        keygen = OTPVerificationMixin()
        key = keygen.generate_key(user)
        return key
