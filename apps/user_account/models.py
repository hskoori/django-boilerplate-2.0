from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin,UserManager
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


from django.apps import apps
from django.contrib import auth
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _



# class UserManager(BaseUserManager):
#     use_in_migrations = True

#     def _create_user(self, username, email, password, **extra_fields):
#         """
#         Create and save a user with the given username, email, and password.
#         """
#         if not username:
#             raise ValueError('The given username must be set')
#         email = self.normalize_email(email)
#         # Lookup the real model class from the global app registry so this
#         # manager method can be used in migrations. This is fine because
#         # managers are by definition working on the real model.
#         GlobalUserModel = apps.get_model(self.model._meta.app_label, self.model._meta.object_name)
#         username = GlobalUserModel.normalize_username(username)
#         user = self.model(username=username, email=email, **extra_fields)
#         user.password = make_password(password)
#         user.save(using=self._db)
#         return user

#     def create_user(self, username, email=None, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', False)
#         extra_fields.setdefault('is_superuser', False)
#         return self._create_user(username, email, password, **extra_fields)

#     def create_superuser(self, username, email=None, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)

#         if extra_fields.get('is_staff') is not True:
#             raise ValueError('Superuser must have is_staff=True.')
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError('Superuser must have is_superuser=True.')

#         return self._create_user(username, email, password, **extra_fields)

#     def with_perm(self, perm, is_active=True, include_superusers=True, backend=None, obj=None):
#         if backend is None:
#             backends = auth._get_backends(return_tuples=True)
#             if len(backends) == 1:
#                 backend, _ = backends[0]
#             else:
#                 raise ValueError(
#                     'You have multiple authentication backends configured and '
#                     'therefore must provide the `backend` argument.'
#                 )
#         elif not isinstance(backend, str):
#             raise TypeError(
#                 'backend must be a dotted import path string (got %r).'
#                 % backend
#             )
#         else:
#             backend = auth.load_backend(backend)
#         if hasattr(backend, 'with_perm'):
#             return backend.with_perm(
#                 perm,
#                 is_active=is_active,
#                 include_superusers=include_superusers,
#                 obj=obj,
#             )
#         return self.none()




class User(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username and password are required. Other fields are optional.
    """
    # username_validator = UnicodeUsernameValidator()


    user_id = models.AutoField(primary_key=True)
    full_name = models.CharField(_("Name of User"), blank=True, max_length=255)
    dob = models.CharField(max_length=30,null=True,blank=True)
    phone = models.CharField(max_length=30,null=True,blank=True)
    phone_verified = models.BooleanField(default=False)
    email = models.EmailField(_('email address'), blank=True)
    email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    role = models.CharField(max_length=30,null=True,blank=True)
    is_admin = models.BooleanField(default=False,null=True,blank=True)
    
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'user_id'
    REQUIRED_FIELDS = ['']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    # def get_full_name(self):
    #     """
    #     Return the first_name plus the last_name, with a space in between.
    #     """
    #     full_name = '%s %s' % (self.first_name, self.last_name)
    #     return full_name.strip()

    # def get_short_name(self):
    #     """Return the short name for the user."""
    #     return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)




# class User(AbstractUser):
#     """
#     Default custom user model for My Awesome Project.
#     If adding fields that need to be filled at user signup,
#     check forms.SignupForm and forms.SocialSignupForms accordingly.
#     """

#     # First and last name do not cover name patterns around the globe
#     first_name = None  # type: ignore
#     last_name = None  # type: ignore

#     user_id = models.AutoField(primary_key=True)
#     full_name = models.CharField(_("Name of User"), blank=True, max_length=255)
#     dob = models.CharField(max_length=30,null=True,blank=True)
#     phone = models.CharField(max_length=30,null=True,blank=True)
#     phone_verified = models.BooleanField(default=False)
#     email = models.EmailField(verbose_name="email", max_length=60, unique=False)
#     email_verified = models.BooleanField(default=False)
#     date_joined = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
#     role = models.CharField(max_length=30,null=True,blank=True)
#     is_admin = models.BooleanField(default=False,null=True,blank=True)
#     is_active = models.BooleanField(default=True,null=True,blank=True)
    

#     def get_absolute_url(self) -> str:
#         return reverse("users:detail", kwargs={"username": self.username})
