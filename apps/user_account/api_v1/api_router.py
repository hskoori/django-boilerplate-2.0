from django.conf import settings
from django.urls import path
from rest_framework.routers import DefaultRouter, SimpleRouter

from apps.user_account.api_v1.views import ( UserViewSet ,
                                            registration_view,
                                            registration_email,
                                            registration_phone,
                                            verify_email,
                                            verify_phone,
                                            login_view ,
                                            login_phone,
                                            login_email,
                                            login_phone_otp,
                                            verify_login_phone_otp,
                                            login_email_otp,
                                            verify_login_email_otp,
                                            # update_account_view,
                                            logout_view,
                                            forget_password,
                                            password_reset,
                                            change_password,
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
    path('register/',registration_view,name='register'),
    path('register-phone/',registration_phone,name='register-phone'),
    path('verify_phone/',verify_phone,name='verify_phone'),
    path('register-email/',registration_email,name='register-mail'),
    path('verify_email/',verify_email,name='verify_email'),
    path('login/',login_view,name="login-view"),
    path('login_phone/',login_phone,name="login-phone"),
    path('login_email/',login_email,name="login-mail"),
    path('login_phone_otp/',login_phone_otp,name="login_phone_otp"),
    path('verify_phone_otp/',verify_login_phone_otp,name="verify_phone_otp"),
    path('login_email_otp/',login_email_otp,name="login_phone_otp"),
    path('verify_email_otp/',verify_login_email_otp,name="verify_phone_otp"),
    # path('update_account/',update_account_view,name="update_account"),
    path('logout/',logout_view,name="logout"),
    path('forget_password/',forget_password,name="forget_password"),
    path('password_reset/',password_reset,name="password_reset"),
    path('change_password/',change_password,name="change_password"),










]

app_name = "api_v1"
urlpatterns += router.urls
