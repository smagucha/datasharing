# users/urls.py
from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView


urlpatterns = [
    # path("auth/register/", views.register_user, name="register"),
    path("auth/register/", views.user_list_create, name="register"),
    path("auth/login/", views.login_user, name="login"),  # use your current path here
    path("auth/login/verify/", views.login_verify_otp, name="login-verify"),
    path("auth/login/resend/", views.login_resend_otp, name="login-resend"),
    path("auth/token/refresh/", views.refresh_token, name="token_refresh"),
    path("auth/profile/", views.user_profile, name="profile"),
    path("auth/forgot_password/", views.forgot_password, name="forgot_password"),
    path("auth/change_password/", views.change_password, name="change_password"),
    path(
        "auth/reset_password_confirm/<str:uidb64>/<str:token>/",
        views.reset_password_confirm,
        name="reset_password_confirm",
    ),
    path("auth/logout/", views.logout_user, name="logout"),
    path("auth/set_password/", views.set_password, name="set-password"),
    path(
        "users/<int:pk>/resend-invite/",
        views.user_resend_invite,
        name="user-resend-invite",
    ),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("verify-token/", TokenVerifyView.as_view(), name="token_verify"),
    path("user_detail/<int:pk>/", views.user_detail, name="user_detail"),
    path("deactivate_user/<int:pk>/", views.user_deactivate, name="deactivate_user"),
    path("activate_user/<int:pk>/", views.user_activate, name="activate_user"),
]
