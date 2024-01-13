from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model
import base64
import pyotp
from django.conf import settings

from grito_talent_pool_server.utils import GenerateKey

User = get_user_model()


class OTPVerificationMixin:
    @staticmethod
    def generate_key(user):
        keygen = GenerateKey()
        key_bytes = keygen.return_value(user.email).encode()
        key_base32 = base64.b32encode(key_bytes).decode('utf-8')
        return key_base32

    def verify_otp(self, user, otp_code, user_mode):
        key = self.generate_key(user)
        OTP = pyotp.TOTP(key, interval=settings.OTP_TIMEOUT)
        # logger.info(OTP.verify(otp_code))

        if OTP.verify(otp_code):
            if user_mode == "email":
                user.is_email_verified = True
            elif user_mode == "phone":
                user.is_phone_number_verified = True
            user.save()
            return user
        else:
            raise ValidationError("OTP verification failed")
