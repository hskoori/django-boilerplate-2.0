
from django.urls import include, path

urlpatterns = [
    #User_account API routes
    path("users", include("apps.user_account.api_v1.api_router", namespace="user_account_api_v1")),
]

