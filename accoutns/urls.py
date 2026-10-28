from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    StudentRegistrationView,
    StaffAccountInviteView,
    MashrooiLoginView,
    LogoutView,
    ForgotPasswordView,
    ResetPasswordConfirmView,
    ManageProfileView,
    UserAvailabilityViewSet,
    AdminUserManagementViewSet,
    AuditLogListView,
)

router = DefaultRouter()
router.register(r"admin/users", AdminUserManagementViewSet, basename="admin-user")
router.register(
    r"profile/availability", UserAvailabilityViewSet, basename="user-availability"
)

urlpatterns = [
    path(
        "register/student/", StudentRegistrationView.as_view(), name="student-register"
    ),
    path("admin/invite-staff/", StaffAccountInviteView.as_view(), name="staff-invite"),
    path("login/", MashrooiLoginView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path(
        "reset-password/confirm/",
        ResetPasswordConfirmView.as_view(),
        name="reset-password-confirm",
    ),
    path("profile/", ManageProfileView.as_view(), name="manage-profile"),
    path("admin/audit-logs/", AuditLogListView.as_view(), name="audit-logs"),
    path("", include(router.urls)),
]
