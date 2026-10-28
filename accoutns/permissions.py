from rest_framework.permissions import BasePermission
from .models import User, AuditLog


def log_audit_action(
    user, action, entity_type, old_value=None, new_value=None, request=None
):
    ip = None
    if request:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        ip = (
            x_forwarded_for.split(",")[0]
            if x_forwarded_for
            else request.META.get("REMOTE_ADDR")
        )
    AuditLog.objects.create(
        user=user,
        action=action,
        entity_type=entity_type,
        old_value=old_value,
        new_value=new_value,
        ip_address=ip,
    )


class IsAdminRole(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == User.Role.ADMIN
        )


class IsCoordinatorRole(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == User.Role.COORDINATOR
        )


class IsSupervisorRole(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == User.Role.SUPERVISOR
        )


class IsCommitteeRole(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == User.Role.COMMITTEE
        )


class IsStudentRole(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == User.Role.STUDENT
        )
