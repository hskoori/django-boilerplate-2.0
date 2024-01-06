from django.conf import settings
from rest_framework.routers import DefaultRouter, SimpleRouter

from apps.user_account.api_v1.views import UserViewSet

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("user-account", UserViewSet)


app_name = "api_v1"
urlpatterns = router.urls
