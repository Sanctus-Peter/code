import json
from decouple import config
import requests
from datetime import datetime
from rest_framework.response import Response
from rest_framework import status, serializers
from django.http import JsonResponse
from django.conf import settings


def send_otp_email(email, otp_code, name, product_name="Grito Talent Pool"):
    try:
        zepto_auth = config("ZEPTO_API_KEY")
        otp_template = config("VERIFY_EMAIL_TEMPLATE")

        url = "https://api.zeptomail.com/v1.1/email/template"
        payload_json = {
            "merge_info": {
                "name": name,
                "OTP": otp_code,
                "product_name": product_name
            },
            "template_key": otp_template,
            "from": {"address": "support@grito.africa"},
            "to": [{"email_address": {"address": email, "name": name}}]
        }

        payload = json.dumps(payload_json)
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': zepto_auth,
        }
        response = requests.request("POST", url, data=payload, headers=headers)

        return response.text
    except Exception as e:
        print(e)


class GenerateKey:
    @staticmethod
    def return_value(phone):
        return f"{phone}{datetime.now().timestamp()}{settings.SECRET_KEY}"


def error_500(request):
    message = "An error occurred"
    # send_mail to developer to handle error
    response = JsonResponse(data={"message": message, "status_code": 404})
    response.status_code = 500
    return response


def error_401(message):
    return Response(
        {
            "code": status.HTTP_401_UNAUTHORIZED,
            "status": "error",
            "message": message,
        },
        status=status.HTTP_401_UNAUTHORIZED,
    )


def error_400(message):
    return Response(
        {
            "code": status.HTTP_400_BAD_REQUEST,
            "status": "error",
            "message": message,
        },
        status=status.HTTP_400_BAD_REQUEST,
    )


def error_404(message):
    return Response(
        {
            "code": status.HTTP_404_NOT_FOUND,
            "status": "error",
            "message": message,
        },
        status=status.HTTP_404_NOT_FOUND,
    )


def error_406(message):
    return Response(
        {
            "code": status.HTTP_406_NOT_ACCEPTABLE,
            "status": "error",
            "message": message,
        },
        status=status.HTTP_406_NOT_ACCEPTABLE,
    )


def serializer_error_400(message):
    return serializers.ValidationError(
        {"code": 400, "status": "error", "message": message}
    )


def error_response(message, status_code):
    return Response(
        {"message": message},
        status=status_code,
    )


def serializer_errors(default_errors):
    error_messages = ""
    for field_name, field_errors in default_errors.items():
        if field_errors[0].code == "unique":
            error_messages += f"{field_name} already exists"
        else:
            error_messages += f"{field_name} is {field_errors[0].code}"

    return error_messages


def format_phone_number(phone_number):
    if not phone_number or len(phone_number) < 2:
        return None

    if len(phone_number) > 2 and phone_number[0] == "+":
        return phone_number[1:]

    elif len(phone_number) > 2 and phone_number[:3] == "234":
        return phone_number

    elif len(phone_number) > 2 and phone_number[:3] != "234" and phone_number[0] != "+":
        return f"234{phone_number[1:]}"


def custom_normalize_email(email):
    return email.strip().lower()
