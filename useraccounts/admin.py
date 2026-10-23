# users/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, County, SubCounty, Ward


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = (
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
        "is_staff",
    )
    list_filter = (
        "role",
        "assigned_county",
        "assigned_sub_county",
        "is_staff",
        "is_active",
    )
    search_fields = (
        "email",
        "national_id",
        "phone_number",
        "first_name",
        "middle_name",
        "last_name",
    )
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            _("Personal Info"),
            {
                "fields": (
                    "first_name",
                    "middle_name",
                    "last_name",
                    "national_id",
                    "phone_number",
                )
            },
        ),
        (
            _("Role & Jurisdiction Scope"),
            {
                "fields": (
                    "role",
                    "assigned_county",
                    "assigned_sub_county",
                    "assigned_ward",
                )
            },
        ),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password",
                    "password2",
                    "first_name",
                    "middle_name",
                    "last_name",
                    "national_id",
                    "phone_number",
                    "role",
                    "assigned_county",
                    "assigned_sub_county",
                    "assigned_ward",
                ),
            },
        ),
    )


class WardInline(admin.TabularInline):
    model = Ward
    extra = 1


@admin.register(County)
class CountyAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)


@admin.register(SubCounty)
class SubCountyAdmin(admin.ModelAdmin):
    list_display = ("name", "county")
    list_filter = ("county",)
    search_fields = ("name", "county__name")
    inlines = [WardInline]  # Manage Wards inside their parent Sub-County panel easily


@admin.register(Ward)
class WardAdmin(admin.ModelAdmin):
    list_display = ("name", "sub_county", "get_county")
    list_filter = ("sub_county__county", "sub_county")
    search_fields = ("name", "sub_county__name", "sub_county__county__name")

    def get_county(self, obj):
        return obj.sub_county.county

    get_county.short_description = "County"
