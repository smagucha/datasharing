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


from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from .models import User

GEO_FIELDS = ("assigned_county", "assigned_sub_county", "assigned_ward")


def other_active_national_admin_exists(user):
    return (
        User.objects.filter(role=User.Role.NATIONAL_ADMIN, is_active=True)
        .exclude(pk=user.pk)
        .exists()
    )


class UserAdminSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=False, validators=[validate_password]
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "national_id",
            "phone_number",
            "role",
            "assigned_county",
            "assigned_sub_county",
            "assigned_ward",
            "is_active",
            "must_change_password",
            "password",
        ]
        read_only_fields = ["must_change_password"]

    def validate(self, attrs):
        actor = self.context["request"].user
        inst = self.instance

        # if not inst and not attrs.get("password"):
        #     raise serializers.ValidationError(
        #         {"password": "Required when creating a user."}
        #     )

        role = attrs.get("role", inst.role if inst else User.Role.REGULAR_USER)

        # If any geography field is sent, it replaces the whole geography;
        # parents are derived from the most specific one provided.
        if any(f in attrs for f in GEO_FIELDS):
            ward = attrs.get("assigned_ward")
            sub = attrs.get("assigned_sub_county")
            county = attrs.get("assigned_county")
        elif inst:
            ward, sub, county = (
                inst.assigned_ward,
                inst.assigned_sub_county,
                inst.assigned_county,
            )
        else:
            ward = sub = county = None

        county, sub, ward = User.resolve_geography(ward, sub, county)

        try:
            User.validate_hierarchy(role, county, sub, ward)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)

        # Scope check on the resulting state (blocks privilege escalation
        # and moving users out of the actor's county)
        if not actor.can_manage_target(role, county):
            raise serializers.ValidationError(
                "You are not allowed to assign this role or area."
            )

        # Don't lock the system out of national admins
        if inst and inst.is_national_admin:
            demoting = role != User.Role.NATIONAL_ADMIN
            deactivating = attrs.get("is_active", True) is False
            if (demoting or deactivating) and not other_active_national_admin_exists(
                inst
            ):
                raise serializers.ValidationError(
                    "You can't remove the last active National Admin."
                )

        attrs.update(
            assigned_county=county, assigned_sub_county=sub, assigned_ward=ward
        )
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        user.must_change_password = True
        user.save(update_fields=["must_change_password"])
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.must_change_password = True
            user.save(update_fields=["password", "must_change_password"])
        return user
