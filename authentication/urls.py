from django.urls import path
from . import apis as view
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = router.urls

urlpatterns += [
    path(
        "admin/sign-up",
        view.AdminRegistrationView.as_view(),
        name="create-admin-user"
    ),
    path("login/admin/", view.AdminLoginView.as_view(), name="login-admin"),
    path("logout/", view.LogoutView.as_view(), name="logout"),
    path("reset-password/", view.ResetPasswordView.as_view(), name="reset-password"),
    path("confirm-otp/", view.OTPVerificationView.as_view(), name="confirm-otp"),
    path("resend-otp/", view.ResendOTPView.as_view(), name="resend-otp"),

    path(
        "reset-password-request/",
        view.ResetPasswordEmailView.as_view(),
        name="reset-password-link",
    ),

    path(
      "admin/talent",
      view.CreateUpdateTalentView.as_view(),
      name="create-or-update-talent"
    ),
    path(
      "talent-request",
      view.TalentRequestView.as_view(),
      name="talent-request"
    ),
    # path(
      
    # )
]
