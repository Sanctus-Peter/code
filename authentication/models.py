from django.db import models
from django.contrib.auth.models import (
    AbstractUser,
    PermissionsMixin,
)
from .manager import CustomUserManager
from django_countries.fields import CountryField
from django.contrib.postgres.fields import ArrayField
# from grito_talent_pool_server.models import BaseModel
import uuid


class User(AbstractUser, PermissionsMixin):
    GENDER = (("male", "Male"), ("female", "Female"))
    USER_TYPE = (
        ("talent", "Talent"),
        ("client", "Client"),
        ("super-admin", "Super Admin"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(max_length=254, unique=True, db_index=True)
    phone = models.CharField(max_length=20, null=True, blank=True, unique=True)
    image_url = models.TextField(null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER, null=True, blank=True)
    user_type = models.CharField(
        max_length=255, choices=USER_TYPE, null=True, blank=True
    )
    address = models.TextField(null=True, blank=True)
    country = CountryField(default="NG")
    is_verified = models.BooleanField(default=False, null=True, blank=True)
    is_active = models.BooleanField(default=False, null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = CustomUserManager()

    def __str__(self) -> str:
        return f"{self.user_type}: {self.last_name} {self.first_name}"


class OTPContainer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=10, null=True, blank=True)
    otp_base32 = models.TextField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.user.email} - {self.otp_code}"


class Talent(models.Model):
    SKILL_LEVEL = (("beginner", "Beginner"), ("intermediate", "Intermediate"), ("professional", "Professional"))
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="talent")
    skill_level = models.CharField(max_length=255, null=True, blank=True)
    profile_link = models.TextField(null=True, blank=True)
    core_skill = models.CharField(max_length=255, null=True, blank=True)
    skill_set = ArrayField(models.CharField(max_length=255, blank=True), null=True)
    resume_file_url = models.TextField(null=True, blank=True)
    profile_summary = models.TextField(null=True, blank=True)
    is_archived = models.BooleanField(default=False, null=True, blank=True)

