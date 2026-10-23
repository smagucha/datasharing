# users/urls.py
from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView


urlpatterns = [
    path("auth/register/", views.register_user, name="register"),
    path("auth/login/", views.login_user, name="login"),
    path("auth/token/refresh/", views.refresh_token, name="token_refresh"),
    path("auth/profile/", views.user_profile, name="profile"),
    path("auth/forgot-password/", views.forgot_password, name="forgot_password"),
    path("auth/change_password/", views.change_password, name="change_password"),
    path(
        "auth/reset_password_confirm/<str:uidb64>/<str:token>/",
        views.reset_password_confirm,
        name="reset_password_confirm",
    ),
    path("auth/logout/", views.logout_user, name="logout"),
    path(
        "account-confirm-email/<str:uidb64>/<str:token>/",
        views.email_confirm_redirect,
        name="account_confirm_email",
    ),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("verify-token/", TokenVerifyView.as_view(), name="token_verify"),
]
