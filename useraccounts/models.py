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

    objects = CustomUserManager()

    def save(self, *args, **kwargs):
        # Auto-cascade upwards through the geographic hierarchy
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
