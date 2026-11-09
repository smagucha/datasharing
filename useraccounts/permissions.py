from rest_framework.permissions import BasePermission


class CanManageUsers(BasePermission):
    message = "You do not have permission to manage users."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.can_manage_users)
