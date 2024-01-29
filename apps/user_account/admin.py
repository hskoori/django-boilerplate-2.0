from django.conf import settings
from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.contrib.auth import get_user_model, decorators
from django.utils.translation import gettext_lazy as _
from .models import User,LoginHistory

from apps.user_account.forms import UserAdminChangeForm, UserAdminCreationForm

User = get_user_model()

if settings.DJANGO_ADMIN_FORCE_ALLAUTH:
    # Force the `admin` sign in process to go through the `django-allauth` workflow:
    # https://django-allauth.readthedocs.io/en/stable/advanced.html#admin
    admin.site.login = decorators.login_required(admin.site.login)  # type: ignore[method-assign]


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("full_name", "email","phone")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "country_code",
                    "phone_verified",
                    "email_verified",
                    "is_active",
                    "is_staff",
                    "is_admin",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    list_display = ["username", "is_superuser",'pk','full_name','phone','phone_verified','email', 'email_verified','date_joined', 'is_admin','role','is_staff','date_joined','is_active',]
    search_fields = ["username"]


# Register your models here.
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ('id',
    'user',
    'login_date',
    'ip_address',
    'login_method',
    )
admin.site.register(LoginHistory,LoginHistoryAdmin)


