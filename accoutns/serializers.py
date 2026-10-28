from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Department, AuditLog, UserAvailability
from .permissions import log_audit_action


# Student Registrations
class StudentRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "full_name",
            "email",
            "student_id",
            "department",
            "phone",
            "password",
            "confirm_password",
        ]
        extra_kwargs = {
            "student_id": {"required": True},
            "department": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        user = User.objects.create_user(
            role=User.Role.STUDENT, status=User.Status.ACTIVE, **validated_data
        )
        return user


# Admin Creates Staff Accounts (Supervisor, Committee, Coordinator, Admin)
class StaffAccountInviteSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "user_id",
            "full_name",
            "email",
            "department",
            "role",
            "specialization",
            "degree",
            "max_load",
        ]

    def validate_role(self, value):
        if value == User.Role.STUDENT:
            raise serializers.ValidationError(
                "Use Student Registration for student accounts"
            )
        return value

    def create(self, validated_data):
        temp_password = User.objects.make_random_password(length=12)
        user = User.objects.create_user(
            password=temp_password,
            status=User.Status.INVITED,
            **validated_data,
        )
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        invite_link = f"{settings.FRONTEND_URL}/set-password/{uid}/{token}/"
        send_mail(
            subject="SGPMS - Staff Account Invitation",
            message=(
                f"Hello {user.full_name}\nAn Account with {user.get_role_display()} has been created for you.\n Temporary Password: {temp_password}\n. Or set your password directly here: {invite_link}"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )
        return user


# User Login with JWT, 3-Attempt Lockout, Role Redirection & Audit Log
class MashrooiTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        request = self.context.get("request")

        user = User.objects.filter(email__iexact=email).first()
        if user:
            if user.is_locked():
                raise AuthenticationFailed(
                    "Account is temporarily locked due to 3 failed login attempts. Try again in 15 minutes."
                )
            if user.status in [User.Status.SUSPENDED, User.Status.PENDING_VERIFICATION]:
                raise AuthenticationFailed(
                    f"Account cannot log in. Current status: {user.get_status_display()}."
                )
            if not user.check_password(password):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 3:
                    user.locked_until = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=["failed_login_attempts", "locked_until"])
                log_audit_action(
                    user,
                    "LOGIN_FAILED",
                    "User",
                    new_value={"failed_attempts": user.failed_login_attempts},
                    request=request,
                )
                raise AuthenticationFailed("Invalid email or password.")
            # Reset lockout counters on valid login
            if user.failed_login_attempts > 0 or user.locked_until:
                user.failed_login_attempts = 0
                user.locked_until = None
                user.save(update_fields=["failed_login_attempts", "locked_until"])
        data = super().validate(attrs)
        dashboard_routes = {
            User.Role.STUDENT: "/dashboard/student",
            User.Role.SUPERVISOR: "/dashboard/supervisor",
            User.Role.COMMITTEE: "/dashboard/committee",
            User.Role.COORDINATOR: "/dashboard/coordinator",
            User.Role.ADMIN: "/dashboard/admin",
        }
        data["user"] = {
            "user_id": str(self.user.user_id),
            "full_name": self.user.full_name,
            "email": self.user.email,
            "role": self.user.role,
            "status": self.user.status,
            "dashboard_url": dashboard_routes.get(self.user.role, "/dashboard"),
        }
        log_audit_action(
            self.user,
            "USER_LOGIN",
            "User",
            new_value={"role": self.user.role},
            request=request,
        )
        return data


# Forgot Password & Reset Confirmation
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "No account found with this registered email."
            )
        return value

    def save(self):
        user = User.objects.get(email__iexact=self.validated_data["email"])
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

        send_mail(
            subject="Mashrooi - Password Reset Request",
            message=f"Click the link below to reset your password:\n{reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )


class ResetPasswordConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        write_only=True, validators=[validate_password]
    )

    def validate(self, attrs):
        try:
            user_id = force_str(urlsafe_base64_decode(attrs["uid"]))
            self.user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": "Invalid user identifier."})

        if not default_token_generator.check_token(self.user, attrs["token"]):
            raise serializers.ValidationError(
                {"token": "Reset link is invalid or has expired."}
            )
        return attrs

    def save(self):
        self.user.set_password(self.validated_data["new_password"])
        if self.user.status == User.Status.INVITED:
            self.user.status = User.Status.ACTIVE
        self.user.save()
        return self.user


# Profile, Availability, Admin Management & Audit Log
class UserAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAvailability
        fields = [
            "availability_id",
            "day_of_week",
            "start_time",
            "end_time",
            "is_available",
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source="department.name", read_only=True)
    availabilities = UserAvailabilitySerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = [
            "user_id",
            "full_name",
            "email",
            "phone",
            "role",
            "status",
            "department",
            "department_name",
            "student_id",
            "specialization",
            "degree",
            "max_load",
            "current_load",
            "availabilities",
        ]
        read_only_fields = [
            "user_id",
            "email",
            "role",
            "status",
            "student_id",
            "current_load",
        ]


class AdminUserManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "user_id",
            "full_name",
            "email",
            "phone",
            "department",
            "role",
            "status",
            "student_id",
            "specialization",
            "degree",
            "max_load",
            "current_load",
            "created_at",
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.CharField(source="user.full_name", read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            "log_id",
            "user",
            "user_name",
            "user_email",
            "action",
            "entity_type",
            "old_value",
            "new_value",
            "ip_address",
            "created_at",
        ]
