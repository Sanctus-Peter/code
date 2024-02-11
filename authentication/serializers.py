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
    GenerateKey, 
    send_otp_email
)
from django_countries.fields import CountryField
from .mixins import OTPVerificationMixin
from .models import User
from .models import Talent
from cloudinary import uploader


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
        exclude = (
            "is_active",
            "password",
            "is_superuser",
            "user_permissions",
            "groups",
        )


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    otp_code = serializers.CharField(required=True)
    
    def validate(self, data):
        password = data["password"]
        otp_code = data["otp_code"]
        email = data["email"]
        
        
        user = User.objects.filter(email=email).first()

        if not user:
            raise ValidationError(f"User with the provided email does not exist")

        otp_mixin = OTPVerificationMixin()
        verified_user = otp_mixin.verify_otp(user, otp_code)

        if password:
            user.set_password(password)
            user.save()

            return  {
                "name": user.name,
                "user": verified_user,
            }


class EmailandPhoneNumberSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)


class OTPVerificationSerializer(serializers.Serializer):
    otp_code = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

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
            'name': user.name
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


class CreateUpdateSerializer(serializers.ModelSerializer):
    GENDER = (("male", "Male"), ("female", "Female"))
    LEVEL = (("beginner", "Beginner"), ("intermediate", "Intermediate"), ("professional", "Professional"))
    name = serializers.CharField()
    gender = serializers.ChoiceField(choices=GENDER)
    country = serializers.CharField()
    email = serializers.CharField(required=True)
    image = serializers.ImageField()
    resume = serializers.ImageField()
    level = serializers.ChoiceField(choices=LEVEL)
    contact_number = serializers.CharField(max_length=15)

    class Meta:
        model = Talent
        exclude = ["user", "is_archived", "resume_file_url"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Make all fields optional
        for field_name, field in self.fields.items():
            field.required = False

    @staticmethod
    def create_or_update(data, method):
        name = data.pop('name', None)
        gender = data.pop('gender', None)
        country = data.pop('country', None)
        email = data.pop('email', None)
        image_file = data.pop('image', None)
        resume_file = data.pop('resume', None)

        # Cloudinary upload for image
        if image_file:
            image_upload_result = uploader.upload(image_file)
            image_url = image_upload_result.get('url')

        # Cloudinary upload for resume
        if resume_file:
            resume_upload_result = uploader.upload(resume_file)
            data['resume_file_url'] = resume_upload_result.get('url')

        user_instance, created = User.objects.get_or_create(email=email)
        user_instance.name = name
        user_instance.gender = gender
        user_instance.country = country
        user_instance.is_active = user_instance.is_verified = True
        user_instance.user_type = 'talent'
        if image_file:
            user_instance.image_url = image_url

        user_instance.save()

        talent_instance, created = Talent.objects.get_or_create(user=user_instance)
        for key, value in data.items():
            setattr(talent_instance, key, value)

        talent_instance.save()

        if method == 'post':
            group, _ = Group.objects.get_or_create(name="talent")
            user_instance.groups.add(group)

        return 200, user_instance
    

class TalentWithUserSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Talent
        fields = '__all__'

    def get_user(self, talent):
        user = talent.user
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'contact_number': user.phone,
            'name': user.name,
            'gender': user.gender,
            'country': user.country,
            'image_url': user.image_url,
        }
    