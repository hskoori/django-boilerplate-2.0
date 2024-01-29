from django.conf import settings
from django.urls import path
from rest_framework.routers import DefaultRouter, SimpleRouter

from apps.user_account.api_v1.views import ( UserViewSet ,
                                            # registration_view,
                                            registration_email,
                                            registration_phone,
                                            verify_email,
                                            verify_phone,
                                            login_email_pass,
                                            login_phone_pass,
                                            login_user_pass,
                                            login_phone_otp,
                                            verify_login_phone_otp,
                                            login_email_otp,
                                            verify_login_email_otp,
                                            # update_account_view,
                                            logout_view,
                                            forget_password_email,
                                            forget_password_phone,
                                            forget_password_username,
                                            verify_forget_password,
                                            change_password,
                                            phone_verification_otp,verify_phone_verification_otp,
                                            email_verification_otp,verify_email_verification_otp,

                                            LoginHistoryViewSet
                                            )


if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("user-account", UserViewSet)
router.register("login-history",LoginHistoryViewSet)

# router.register("user-profile",UserProfile)


urlpatterns = [
    # path('login-view/',login_view ,name ='login-view'),
    # path('login-otp-view/',login_otp_view ,name ='login-otp-view'),
    # path('register/',registration_view,name='register'),

    path('register-phone/',registration_phone,name='register_phone'),
    path('verify-phone/',verify_phone,name='verify_phone'),

    path('register-email/',registration_email,name='register_mail'),
    path('verify-email/',verify_email,name='verify_email'),

    path('login-user-pass/',login_user_pass,name="login_user_pass"),
    path('login-phone-pass/',login_phone_pass,name="login_phone_pass"),
    path('login-email-pass/',login_email_pass,name="login_email_pass"),

    path('login-phone-otp/',login_phone_otp,name="login_phone_otp"),
    path('verify-phone-otp/',verify_login_phone_otp,name="verify_phone_otp"),

    path('login-email-otp/',login_email_otp,name="login_email_otp"),
    path('verify-email-otp/',verify_login_email_otp,name="verify_email_otp"),

    path('phone-verification-otp/',phone_verification_otp,name="phone_verification_otp"),
    path('verify-phone-verification-otp/',verify_phone_verification_otp,name="verify_phone_verification_otp"),

    path('email-verification-otp/',email_verification_otp,name="email_verification_otp"),
    path('verify-email-verification-otp/',verify_email_verification_otp,name="verify_email_verification_otp"),

    path('logout/',logout_view,name="logout"),
    path('forget-password-username/',forget_password_username,name="forget_password_username"),
    path('forget-password-email/',forget_password_email,name="forget_password_email"),
    path('forget-password-phone/',forget_password_phone,name="forget_password_phone"),
    path('verify-forget-password/',verify_forget_password,name="verify_forget_password"),
    path('change-password/',change_password,name="change_password"),

]

app_name = "api_v1"
urlpatterns += router.urls


