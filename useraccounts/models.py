# users/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from .managers import CustomUserManager


class County(models.Model):
    name = models.CharField(max_length=100, unique=True)

    class Meta:
        verbose_name_plural = "Counties"

    def __str__(self):
        return self.name


class SubCounty(models.Model):
    county = models.ForeignKey(
        County, on_delete=models.CASCADE, related_name="sub_counties"
    )
    name = models.CharField(max_length=100)

    class Meta:
        unique_together = ("county", "name")
        verbose_name_plural = "Sub-Counties"

    def __str__(self):
        return f"{self.name} ({self.county.name})"


class Ward(models.Model):
    sub_county = models.ForeignKey(
        SubCounty, on_delete=models.CASCADE, related_name="wards"
    )
    name = models.CharField(max_length=100)

    class Meta:
        unique_together = ("sub_county", "name")
        verbose_name_plural = "Wards"

    def __str__(self):
        return f"{self.name} (Sub-County: {self.sub_county.name})"


class User(AbstractUser):
    class Role(models.TextChoices):
        NATIONAL_ADMIN = "NATIONAL", "National Admin"
        COUNTY_ADMIN = "COUNTY", "County Admin"
        SUB_COUNTY_ADMIN = "SUB_COUNTY", "Sub-County Admin"
        WARD_ADMIN = "WARD", "Ward Admin"
        REGULAR_USER = "REGULAR", "Regular User"

    username = None

    email = models.EmailField(_("email address"), unique=True)
    first_name = models.CharField(max_length=150, blank=False)
    middle_name = models.CharField(
        max_length=150, null=True, blank=True, verbose_name="Middle Name"
    )
    last_name = models.CharField(max_length=150, blank=False)
    national_id = models.CharField(
        max_length=20, unique=True, verbose_name="National ID"
    )
    phone_number = PhoneNumberField(unique=True, region="KE")

    role = models.CharField(
        max_length=20, choices=Role.choices, default=Role.REGULAR_USER
    )
    assigned_county = models.ForeignKey(
        County, on_delete=models.SET_NULL, null=True, blank=True
    )
    assigned_sub_county = models.ForeignKey(
        SubCounty, on_delete=models.SET_NULL, null=True, blank=True
    )
    assigned_ward = models.ForeignKey(
        Ward, on_delete=models.SET_NULL, null=True, blank=True
    )
    must_change_password = models.BooleanField(default=False)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["national_id", "phone_number", "first_name", "last_name"]
    MANAGEABLE_ROLES = {
        Role.NATIONAL_ADMIN: {
            Role.NATIONAL_ADMIN,
            Role.COUNTY_ADMIN,
            Role.SUB_COUNTY_ADMIN,
            Role.WARD_ADMIN,
            Role.REGULAR_USER,
        },
        Role.COUNTY_ADMIN: {
            Role.SUB_COUNTY_ADMIN,
            Role.WARD_ADMIN,
            Role.REGULAR_USER,
        },
    }

    @property
    def is_national_admin(self):
        return self.is_active and self.role == self.Role.NATIONAL_ADMIN

    @property
    def can_manage_users(self):
        return self.is_active and self.role in self.MANAGEABLE_ROLES

    @staticmethod
    def resolve_geography(ward, sub_county, county):
        """Fill in parents upwards: ward -> sub-county -> county."""
        if ward:
            sub_county = sub_county or ward.sub_county
            county = county or sub_county.county
        elif sub_county:
            county = county or sub_county.county
        return county, sub_county, ward

    @classmethod
    def validate_hierarchy(cls, role, county, sub_county, ward):
        R = cls.Role
        if ward and ward.sub_county_id != sub_county.id:
            raise ValidationError("Ward does not belong to the selected sub-county.")
        if sub_county and sub_county.county_id != county.id:
            raise ValidationError("Sub-county does not belong to the selected county.")

        if role == R.NATIONAL_ADMIN:
            if county or sub_county or ward:
                raise ValidationError(
                    "National admins must not be tied to a geographic area."
                )
        elif role == R.COUNTY_ADMIN and not county:
            raise ValidationError("A county admin must have an assigned county.")
        elif role == R.SUB_COUNTY_ADMIN and not sub_county:
            raise ValidationError(
                "A sub-county admin must have an assigned sub-county."
            )
        elif role == R.WARD_ADMIN and not ward:
            raise ValidationError("A ward admin must have an assigned ward.")

    def can_manage_target(self, target_role, target_county):
        """May this user hold/create/edit a user with this role in this county?"""
        allowed = self.MANAGEABLE_ROLES.get(self.role)
        if not self.is_active or not allowed or target_role not in allowed:
            return False
        if self.role == self.Role.NATIONAL_ADMIN:
            return True
        return (
            bool(self.assigned_county_id)
            and target_county is not None
            and target_county.id == self.assigned_county_id
        )

    def clean(self):
        super().clean()
        county, sub, ward = self.resolve_geography(
            self.assigned_ward, self.assigned_sub_county, self.assigned_county
        )
        self.validate_hierarchy(self.role, county, sub, ward)

    objects = CustomUserManager()

    def save(self, *args, **kwargs):
            if self.assigned_ward:
            if not self.assigned_sub_county:
                self.assigned_sub_county = self.assigned_ward.sub_county
            if not self.assigned_county:
                self.assigned_county = self.assigned_ward.sub_county.county
        elif self.assigned_sub_county and not self.assigned_county:
            self.assigned_county = self.assigned_sub_county.county

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.email} ({self.role})"
