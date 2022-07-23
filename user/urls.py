from django.contrib import admin
from django.urls import path,re_path
from . import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('register', views.RegisterView.as_view(), name="register"),
    path('login', views.LoginView.as_view(), name="login"),
    path('login/refresh', jwt_views.TokenRefreshView.as_view(), name="refresh-token"),
    path('email-activision',views.EmailActivisionView.as_view(), name="email-verification"),
    path('logout', views.LogoutView.as_view(), name="logout"),
]