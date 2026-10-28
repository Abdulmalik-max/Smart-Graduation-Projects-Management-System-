from rest_framework import generics, status, viewsets, filters
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend
from .models import AuditLog, User, UserAvailability
from .permissions import IsAdminRole, log_audit_action
from .serializers import (
    StudentRegistrationSerializer,
    StaffAccountInviteSerializer,
    MashrooiTokenObtainPairSerializer,
    ForgotPasswordSerializer,
    ResetPasswordConfirmSerializer,
    UserProfileSerializer,
    AdminUserManagementSerializer,
    AuditLogSerializer,
    UserAvailabilitySerializer,
)


# Student Registration
class StudentRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = StudentRegistrationSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        log_audit_action(
            user,
            "STUDENT_REGISTERED",
            "User",
            new_value={"email": user.email, "student_id": user.student_id},
            request=self.request,
        )


# Staff Account Creation
class StaffAccountInviteView(generics.CreateAPIView):
    permission_classes = [IsAdminRole]
    serializer_class = StaffAccountInviteSerializer

    def perform_create(self, serializer):
        staff_user = serializer.save()
        log_audit_action(
            staff_user,
            "STAFF_ACCOUNT_CREATED",
            "USER",
            new_value={"invited_email": staff_user.email, "role": staff_user.role},
            request=self.request,
        )


# login and Logout
class MashrooiLoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = MashrooiTokenObtainPairSerializer


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"detail": "Successfully logged out."}, status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST
            )


# Forgot Password & Reset Confirm
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "Password reset link sent to your email."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        log_audit_action(user, "PASSWORD_RESET_COMPLETED", "User", request=request)
        return Response(
            {"detail": "Password has been updated successfully."},
            status=status.HTTP_200_OK,
        )


# Manage Own Profile & Availability
class ManageProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user


class UserAvailabilityViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = UserAvailabilitySerializer

    def get_queryset(self):
        return UserAvailability.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# Admin Manage User Accounts (Search, Modify Role/Status, Suspend, Delete)
class AdminUserManagementViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminRole]
    queryset = User.objects.all().order_by("-created_at")
    serializer_class = AdminUserManagementSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["role", "status", "department"]
    search_fields = ["full_name", "email", "student_id"]

    def perform_update(self, serializer):
        instance = self.get_object()
        old_data = {"role": instance.role, "status": instance.status}
        updated_user = serializer.save()
        new_data = {"role": updated_user.role, "status": updated_user.status}
        log_audit_action(
            self.request.user,
            "ADMIN_UPDATED_USER",
            "User",
            old_value=old_data,
            new_value=new_data,
            request=self.request,
        )

    def perform_destroy(self, instance):
        old_data = {
            "user_id": str(instance.user_id),
            "email": instance.email,
            "role": instance.role,
        }
        instance.delete()
        log_audit_action(
            self.request.user,
            "ADMIN_DELETED_USER",
            "User",
            old_value=old_data,
            request=self.request,
        )


# Admin View Audit Log
class AuditLogListView(generics.ListAPIView):
    permission_classes = [IsAdminRole]
    queryset = AuditLog.objects.select_related("user").all()
    serializer_class = AuditLogSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["user", "action", "entity_type"]
    search_fields = ["action", "user__email", "user__full_name"]
