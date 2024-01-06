from django.conf import settings
from rest_framework.routers import DefaultRouter, SimpleRouter

from apps.user_account.api.views import UserViewSet

from django.urls import include, path


if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()


urlpatterns = [
    # API routes
    path("user/", include("apps.user_account.urls", namespace="user_account")),

]

# router.register("user-account", UserViewSet)


app_name = "api"
urlpatterns = router.urls
