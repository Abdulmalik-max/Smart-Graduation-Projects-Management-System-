import uuid
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from django.utils import timezone


class Department(models.Model):
    dept_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class UserManager(BaseUserManager):
    def create_user(self, email, full_name, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, password=None, **extra_fields):
        extra_fields.setdefault("role", User.Role.ADMIN)
        extra_fields.setdefault("status", User.Status.ACTIVE)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, full_name, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        STUDENT = "STUDENT", "Student"
        SUPERVISOR = "SUPERVISOR", "Supervisor"
        COMMITTEE = "COMMITTEE", "Committee Member"
        COORDINATOR = "COORDINATOR", "Coordinator"
        ADMIN = "ADMIN", "Admin"

    class Status(models.TextChoices):
        PENDING_VERIFICATION = "PENDING_VERIFICATION", "Pending Verification"
        PENDING_APPROVAL = "PENDING_APPROVAL", "Pending Approval"
        INVITED = "INVITED", "Invited"
        ACTIVE = "ACTIVE", "Active"
        SUSPENDED = "SUSPENDED", "Suspended"

    class AcademicDegree(models.TextChoices):
        BACHELOR = "BACHELOR", "Bachelor"
        MASTER = "MASTER", "Master"
        PHD = "PHD", "PhD"

    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    full_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True, db_index=True)
    phone = models.CharField(max_length=30, blank=True, null=True)
    department = models.ForeignKey(
        Department,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="users",
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.STUDENT)
    status = models.CharField(
        max_length=25, choices=Status.choices, default=Status.PENDING_VERIFICATION
    )

    # Student-specific field
    student_id = models.CharField(max_length=30, unique=True, null=True, blank=True)

    # Supervisor / Committee AI-matching & workload fields
    specialization = models.TextField(
        blank=True, null=True, help_text="Research areas & keywords for AI matching"
    )
    degree = models.CharField(
        max_length=20, choices=AcademicDegree.choices, blank=True, null=True
    )
    max_load = models.PositiveIntegerField(default=5)
    current_load = models.PositiveIntegerField(default=0)

    # Security & Lockout tracking
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]

    def is_locked(self):
        return bool(self.locked_until and self.locked_until > timezone.now())

    def __str__(self):
        return f"{self.full_name} ({self.role})"


class UserAvailability(models.Model):
    """
        - Stores faculty availability for conflict-free defense scheduling .
    """

    class DayOfWeek(models.TextChoices):
        SATURDAY = "SATURDAY", "Saturday"
        SUNDAY = "SUNDAY", "Sunday"
        MONDAY = "MONDAY", "Monday"
        TUESDAY = "TUESDAY", "Tuesday"
        WEDNESDAY = "WEDNESDAY", "Wednesday"
        THURSDAY = "THURSDAY", "Thursday"

    availability_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="availabilities"
    )
    day_of_week = models.CharField(max_length=15, choices=DayOfWeek.choices)
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_available = models.BooleanField(default=True)


class AuditLog(models.Model):
    """
        - Tracks critical security and administrative actions.
    """

    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=100, db_index=True)
    entity_type = models.CharField(max_length=100)
    old_value = models.JSONField(null=True, blank=True)
    new_value = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
