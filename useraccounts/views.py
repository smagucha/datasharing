from rest_framework.decorators import api_view, permission_classes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.password_validation import validate_password
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.core.mail import send_mail
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from useraccounts.serializers import (
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    ChangePasswordSerializer,
    UserRegistrationSerializer,
    PasswordResetSerializer,
    ResendEmailVerificationSerializer,
    VerifyEmailSerializer,
    LoginSerializer,
    UserAdminSerializer,
)
from .tokens import email_verification_token
import logging
from django.db import IntegrityError, transaction
from django.utils.crypto import get_random_string
from rest_framework.pagination import PageNumberPagination

# ...keep your other existing imports (models, permissions, serializers)
from .tokens import email_verification_token  # adjust to wherever yours lives
from .permissions import CanManageUsers

logger = logging.getLogger(__name__)
MANAGER_PERMISSIONS = [IsAuthenticated, CanManageUsers]

User = get_user_model()


@api_view(["GET"])
@permission_classes([AllowAny])
def email_confirm_redirect(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return HttpResponse("Invalid verification link.", status=400)

    if user.is_active:
        return HttpResponse("Email already verified.", status=200)

    if email_verification_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse(
            "Email verified successfully. You can now log in.",
            status=200,
        )
    return HttpResponse("Verification link is invalid or expired.", status=400)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    return LoginView.as_view()(request._request)
    # {"email":"smagucha@gmail.com", "password":"P@ssWord123"}


@api_view(["POST"])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Accepts a valid refresh token to issue a new short-lived access token.
    """
    return TokenRefreshView.as_view()(request._request)


# //P@ssWord123
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    return Response(
        {
            "message": "Authentication successful!",
            "user_profile": {
                "email": user.email,
                "full_name": f"{user.first_name} {user.middle_name or ''} {user.last_name}".strip(),
                "role": user.role,
                "jurisdiction": {
                    "county": user.assigned_county.name
                    if user.assigned_county
                    else None,
                    "sub_county": user.assigned_sub_county.name
                    if user.assigned_sub_county
                    else None,
                    "ward": user.assigned_ward.name if user.assigned_ward else None,
                },
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data["email"]
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Security best practice: Don't reveal if an email exists or not to prevent user enumeration
        return Response(
            {
                "message": "If a matching account exists, a password reset link has been dispatched."
            },
            status=status.HTTP_200_OK,
        )

    # Generate secure reset tokens bound to this specific user profile instance
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    # In a production environment, send this out via django.core.mail.send_mail()
    # Your frontend dashboard client landing URL structure will look like:
    # https://yourfrontend.com...
    reset_link = f"http://127.0.0.1:8000/useraccounts/auth/reset_password_confirm/{uidb64}/{token}/"

    # Printing link to terminal console for debugging locally
    print("\n" + "=" * 50)
    print(f"PASSWORD RESET LINK GENERATED FOR: {email}")
    print(reset_link)
    print("=" * 50 + "\n")

    return Response(
        {
            "message": "If a matching account exists, a password reset link has been dispatched."
        },
        status=status.HTTP_200_OK,
    )
    # {"email":"smagucha@gmail.com"}


@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password_confirm(request, uidb64, token):
    serializer = ResetPasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    uidb64 = serializer.validated_data["uidb64"]
    token = serializer.validated_data["token"]
    new_password = serializer.validated_data["new_password"]

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.set_password(new_password)
        user.save()
        return Response(
            {"message": "Password has been successfully updated."},
            status=status.HTTP_200_OK,
        )

    return Response(
        {"error": "The reset link is invalid, altered, or has expired."},
        status=status.HTTP_400_BAD_REQUEST,
    )
    # {"uidb64":"MQ", "token":"dhs0xd-e7d694bba6ad109598b511ce5e9a5df8", "new_password":"P@ssWord123!"}


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    old_password = request.data.get("old_password")
    new_password = request.data.get("new_password")

    if not old_password or not new_password:
        return Response(
            {"error": "old_password and new_password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not user.check_password(old_password):
        return Response(
            {"error": "Current password is incorrect."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if old_password == new_password:
        return Response(
            {"error": "New password must be different from the temporary one."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        validate_password(new_password, user)
    except ValidationError as e:
        return Response({"error": list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.must_change_password = False
    user.save()
    return Response({"message": "Password changed successfully."})
    # {"old_password": "P@ssWord123!","new_password": "MyNewSecurePass456!"}


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    Accepts a refresh token and blacklists it.
    """
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response(
            {"error": "Refresh token is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except TokenError:
        return Response(
            {"error": "Invalid or expired token."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {"message": "Logged out successfully."},
        status=status.HTTP_200_OK,
    )


# study the second part


def scoped_users(actor):
    """Users the actor is allowed to see and touch."""
    qs = User.objects.select_related(
        "assigned_county", "assigned_sub_county", "assigned_ward"
    ).order_by("email")

    if actor.role == User.Role.COUNTY_ADMIN:
        qs = qs.filter(
            assigned_county=actor.assigned_county,
            role__in=User.MANAGEABLE_ROLES[User.Role.COUNTY_ADMIN],
        )
    return qs  # National admin: everything


def get_scoped_user_or_404(actor, pk):
    return get_object_or_404(scoped_users(actor), pk=pk)


@api_view(["GET", "PUT", "PATCH"])
@permission_classes(MANAGER_PERMISSIONS)
def user_detail(request, pk):
    user = get_scoped_user_or_404(request.user, pk)

    if request.method == "GET":
        return Response(UserAdminSerializer(user, context={"request": request}).data)

    serializer = UserAdminSerializer(
        user,
        data=request.data,
        partial=(request.method == "PATCH"),
        context={"request": request},
    )
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes(MANAGER_PERMISSIONS)
def user_deactivate(request, pk):
    user = get_scoped_user_or_404(request.user, pk)

    if user == request.user:
        return Response(
            {"detail": "You can't deactivate yourself."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if user.is_national_admin and not other_active_national_admin_exists(user):
        return Response(
            {"detail": "You can't deactivate the last National Admin."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user.is_active = False
    user.save(update_fields=["is_active"])
    return Response(UserAdminSerializer(user, context={"request": request}).data)


@api_view(["POST"])
@permission_classes(MANAGER_PERMISSIONS)
def user_activate(request, pk):
    user = get_scoped_user_or_404(request.user, pk)
    user.is_active = True
    user.save(update_fields=["is_active"])
    return Response(UserAdminSerializer(user, context={"request": request}).data)


def generate_temp_password(length=12):
    # Letters + digits + a guaranteed mix, to satisfy typical validators
    return (
        get_random_string(length - 3)
        + get_random_string(1, "ABCDEFGHJKLMNPQRSTUVWXYZ")
        + get_random_string(1, "abcdefghijkmnopqrstuvwxyz")
        + get_random_string(1, "23456789")
    )


def send_verification_email(request, user, raw_password):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_verification_token.make_token(user)
    link = request.build_absolute_uri(
        f"/useraccounts/account-confirm-email/{uid}/{token}/"
    )
    send_mail(
        subject="Verify your email",
        message=(
            "An administrator has created an account for you.\n\n"
            f"Email: {user.email}\n"
            f"Temporary password: {raw_password}\n\n"
            f"Verify your email to activate the account:\n{link}\n\n"
            "Please change your password after your first login."
        ),
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )


@api_view(["GET", "POST"])
@permission_classes(MANAGER_PERMISSIONS)
def user_list_create(request):
    if request.method == "GET":
        qs = scoped_users(request.user)
        params = request.query_params

        for param, field in [
            ("role", "role"),
            ("county", "assigned_county"),
            ("sub_county", "assigned_sub_county"),
            ("ward", "assigned_ward"),
        ]:
            if param in params:
                qs = qs.filter(**{field: params[param]})

        if "is_active" in params:
            qs = qs.filter(is_active=params["is_active"].lower() in ("true", "1"))

        paginator = PageNumberPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = UserAdminSerializer(page, many=True, context={"request": request})
        return paginator.get_paginated_response(serializer.data)

    # POST: create user + send verification email
    data = request.data.copy()
    raw_password = data.get("password") or generate_temp_password()
    data["password"] = raw_password

    serializer = UserAdminSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)

    try:
        # If the email fails, the whole creation rolls back
        with transaction.atomic():
            user = serializer.save(is_active=False)  # activated via email link
            send_verification_email(request, user, raw_password)
    except IntegrityError:
        # Race condition: another request took the email / ID / phone first
        return Response(
            {
                "error": "Unable to create user.",
                "message": "A user with these details already exists.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Exception:
        logger.exception("Failed to send verification email")
        return Response(
            {
                "error": "Failed to send verification email.",
                "message": "The user was not created. Please try again.",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return Response(
        {
            "message": "User registered successfully. A verification email has been sent.",
            "user": UserAdminSerializer(user, context={"request": request}).data,
        },
        status=status.HTTP_201_CREATED,
    )


# {"email":"admin@admin.com", "first_name":"hfdjgh", "middle_name":"djhjdk", "lastname":"hfgk","role":"NATIONAL", "national_id":454616542, "phone_number":"+254741285890", "password": "P@ssWord123
