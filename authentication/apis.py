import base64
import pyotp
from django.contrib.auth import login, logout, authenticate
from django.conf import settings
from decouple import config

from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.serializers import (
    SuperAdminRegistrationSerializer,
    LoginSerializer,
    UserUpdateVerifiedSerializer,
    ResetPasswordSerializer,
    EmailandPhoneNumberSerializer,
    OTPVerificationSerializer,
    ResendOTPSerializer
)

from grito_talent_pool_server.utils import (
    error_400,
    error_406,
    error_401,
    serializer_errors,
    error_404,
    GenerateKey,
    error_response,
)

User = get_user_model()


class AdminRegistrationView(APIView):
    permission_classes = (AllowAny,)  # For now, it is open
    serializer_class = SuperAdminRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            code, result = serializer.create(serializer.validated_data)
            if code == 406:
                return error_406(result)
            email = result["email"]
            user = User.objects.get(email=email)
            refresh = RefreshToken.for_user(user)
            user_data = UserUpdateVerifiedSerializer(user).data
            return Response(
                {
                    "code": 201,
                    "status": "success",
                    "message": "Super User created successfully, Check email for verification code",
                    "name": user_data['name'],
                    'email': user_data['email'],
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)

                },
                status=status.HTTP_201_CREATED,
            )
        else:
            default_errors = serializer.errors
            error_message = serializer_errors(default_errors)
            return error_400(error_message)


class LogoutView(APIView):
    @staticmethod
    def post(request):
        logout(request)
        return Response({'message': "Logout successful"})


class AdminLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]
            user = authenticate(request, email=email.lower(), password=password)

            if user is not None:
                if user.is_verified:
                    if user.groups.filter(name="super-admin").exists():
                        the_serializer = UserUpdateVerifiedSerializer(user).data

                        refresh = RefreshToken.for_user(user)

                        return Response(
                            {
                                "code": 200,
                                "status": "success",
                                "message": "Login Successful",
                                "is_verified": the_serializer['is_verified'],
                                "user_type": the_serializer['user_type'],
                                "name": the_serializer['name'] + ' (Admin)',
                                "email": the_serializer['email'],
                                "refresh": str(refresh),
                                "access": str(refresh.access_token)
                            },
                            status=status.HTTP_200_OK,
                        )
                    else:
                        return error_response(
                            "User is not an admin. Kindly contact us for further assistance",
                            status.HTTP_401_UNAUTHORIZED
                        )
                else:
                    return error_406("User is not verified. Kindly contact us for further assistance")

            else:
                return error_response("Incorrect Email/Password Inserted", status.HTTP_401_UNAUTHORIZED)
        else:
            default_errors = serializer.errors
            error_message = serializer_errors(default_errors)
            return error_response(error_message, status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(id=request.user.id)
            name = serializer.save(user=user)
            user_data = UserUpdateVerifiedSerializer(user).data
            return Response(
                {
                    "code": 200,
                    "message": "Your password has been changed successfully!",
                    "email_verification": user_data['is_email_verified'],
                    "user_type": user_data['user_type'],
                    "name": name
                },
                status=status.HTTP_200_OK,
            )
        default_errors = serializer.errors
        error_message = serializer_errors(default_errors)
        return error_400(error_message)


class ResetPasswordEmailView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = EmailandPhoneNumberSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email_address = serializer.data.get("email").lower()
            try:
                keygen = GenerateKey()
                key = base64.b32encode(keygen.return_value(email_address).encode()).decode("utf-8")
                OTP = pyotp.TOTP(key, interval=settings.OTP_TIMEOUT)
                otp_code = OTP.now()
                message = "Kindly check your email for your verification code to reset your password"
                email = email_address
                user = User.objects.get(email=email)
                # send_otp_email(email, otp_code, user.first_name)

                return Response(
                    {
                        "status": "Successful",
                        "message": message
                    },
                    status=status.HTTP_200_OK,
                )

            except User.DoesNotExist:
                return error_404("User with this email does not exist")

        else:
            default_errors = serializer.errors
            error_message = serializer_errors(default_errors)
            return error_400(error_message)


class OTPVerificationView(APIView):
    serializer_class = OTPVerificationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            verified_user = serializer.validated_data["user"]
            name = serializer.validated_data["name"]
            user_data = UserUpdateVerifiedSerializer(verified_user).data
            login(request, verified_user)
            refresh = RefreshToken.for_user(verified_user)

            return Response(
                {
                    "code": 200,
                    "status": "success",
                    "message": "OTP verification successful",
                    "email_verification": user_data['is_email_verified'] or None,
                    "phone_verification": user_data['is_phone_number_verified'] or None,
                    "user_type": user_data['user_type'],
                    "name": name,
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                },
                status=status.HTTP_200_OK,
            )
        else:
            default_errors = serializer.errors
            error_message = serializer_errors(default_errors)
            return error_400(error_message)


class ResendOTPView(APIView):
    @staticmethod
    def post(request, *args, **kwargs):
        email = request.data.get("email")

        serializer = ResendOTPSerializer(data={"email": email})
        if serializer.is_valid():
            serializer.resend_otp()
            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
