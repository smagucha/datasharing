from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.exceptions import ValidationError


User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, min_length=6, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "first_name",
            "middle_name",
            "last_name",
            "national_id",
            "phone_number",
            "role",
            "assigned_county",
            "assigned_sub_county",
            "assigned_ward",
        ]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ResetPasswordSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True, write_only=True)
    token = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={"input_type": "password"},
        help_text="Enter a secure, unique new password structure.",
    )

    def validate_new_password(self, value):
        try:
            # Using a blank user instance context to evaluate baseline password security rules
            validate_password(value, user=None)
        except ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return value


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(
        required=True, write_only=True, style={"input_type": "password"}
    )

    def validate_new_password(self, value):
        try:
            validate_password(value, user=None)
        except ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return value


class PasswordResetSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={
            "required": "The encoded user identifier (uidb64) is required."
        },
    )
    token = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={
            "required": "The secure transaction validation token is required."
        },
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        style={"input_type": "password"},
        help_text="Enter a secure, unique new password configuration.",
    )

    def validate_new_password(self, value):
        try:
            # Evaluates basic security parameters without a user instance context
            validate_password(value, user=None)
        except ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return value


class ResendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
        error_messages={
            "required": "The email field cannot be blank.",
            "invalid": "Please enter a valid email address format.",
        },
    )

    def validate_email(self, value):
        """
        Normalizes the email address to lowercase format.
        """
        return value.lower().strip()


class VerifyEmailSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={
            "required": "The base64 encoded user identity parameter is required."
        },
    )
    token = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={
            "required": "The email verification signature token is required."
        },
    )


class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        if self.user.must_change_password:
            data["redirect_to"] = "/change-password"  # first login
        else:
            data["redirect_to"] = "/dashboard"  # normal login
        return data
