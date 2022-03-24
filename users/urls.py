from django.urls import path, include

from users.views import SignUpView

urlpatterns = [
    path('/signup',SignUpView.as_view())
]