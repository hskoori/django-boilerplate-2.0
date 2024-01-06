from django.urls import path

from apps.user_account.views import (
    user_detail_view,
    user_redirect_view,
    user_update_view,
)

app_name = "user_account"
urlpatterns = [
    path("~redirect/", view=user_redirect_view, name="redirect"),
    path("~update/", view=user_update_view, name="update"),
    path("<str:username>/", view=user_detail_view, name="detail"),
]
