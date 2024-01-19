from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model
import base64
import pyotp
from django.conf import settings

from authentication.models import OTPContainer
from grito_talent_pool_server.utils import GenerateKey

User = get_user_model()


class OTPVerificationMixin:
    @staticmethod
    def generate_key(user):
        keygen = GenerateKey()
        key_bytes = keygen.return_value(user.email).encode()
        key_base32 = base64.b32encode(key_bytes).decode('utf-8')
        OTP = pyotp.TOTP(key_base32, interval=settings.OTP_TIMEOUT)

        user_otp, _ = OTPContainer.objects.get_or_create(user=user)
        user_otp.otp_code = OTP.now()
        user_otp.otp_base32 = key_base32
        user_otp.save()
        return OTP.now()

    @staticmethod
    def verify_otp(user, otp_code):
        user_otp = OTPContainer.objects.filter(user=user).first()
        if user_otp is None:
            raise ValidationError("OTP verification failed")
        if user_otp.otp_code != otp_code:
            raise ValidationError("OTP verification failed")
        OTP = pyotp.TOTP(user_otp.otp_base32, interval=settings.OTP_TIMEOUT)

        if OTP.verify(otp_code):
            OTPContainer.objects.filter(user=user).delete()
            return user
        else:
            raise ValidationError("OTP verification failed")
