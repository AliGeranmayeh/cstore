from dataclasses import is_dataclass
from functools import partial
from typing import Tuple
from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import LoginSerializer, RegisterSerializer, EmailVerificationSerializer, RefreshTokenSerializer
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import CustomUser, EmailValidation
from rest_framework import permissions, status, generics
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.db.models import Q
from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.core.mail import send_mail
from random import seed
from random import randint
from rest_framework.generics import GenericAPIView
from rest_framework import permissions
from rest_framework.parsers import MultiPartParser, FormParser


def randomNumber():
    value = randint(1000, 9999)
    return value


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = CustomUser.objects.get(id=user_data.get('id'))
        user_code = randomNumber()
        print(user_code)
        email_validation = EmailValidation.objects.create(email=user.email, code=user_code)
        # access_tk = str(AccessToken.for_user(user))
        # refresh_tk = str(RefreshToken.for_user(user))
        subject = 'welcome to Reverse96'
        message = f'Hi {user.username}, thank you for registering. please enter this code to our website: {user_code}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        send_mail(subject, message, email_from, recipient_list, fail_silently=False)
        return Response({"message": serializer.data}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get("username")
        password = serializer.validated_data.get("password")
        user = CustomUser.objects.filter(Q(username=username) | Q(email=username)).first()
        # user_obj = CustomUser.objects.get(Q(username=username)|Q(email=username))
        if not user:
            return Response({"message": "invalid username or email"}, status=status.HTTP_404_NOT_FOUND)
        if not check_password(password, user.password):
            return Response({"message": "wrong password"}, status=status.HTTP_404_NOT_FOUND)
        if not user.is_active:
            return Response({"message": "validate your email"}, status=status.HTTP_403_FORBIDDEN)
        access_tk = str(AccessToken.for_user(user))
        refresh_tk = str(RefreshToken.for_user(user))
        return Response(data={"access": access_tk, "refresh": refresh_tk}, status=status.HTTP_200_OK)


class EmailActivisionView(APIView):
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        code = serializer.validated_data.get("code")
        email = serializer.validated_data.get("email")
        user_info = CustomUser.objects.filter(Q(username=email) | Q(email=email)).first()
        if (user_info and user_info.is_active):
            return Response({"message": "your account is already activated"}, status=status.HTTP_208_ALREADY_REPORTED)
        else:
            if (not user_info):
                return Response({"message": "Invalid credentials"}, status=status.HTTP_404_NOT_FOUND)

            user = EmailValidation.objects.get(email=email)
            if user.code != code:
                return Response({"message": "wrong code"}, status=status.HTTP_404_NOT_FOUND)
            user_info.is_active = True
            user_info.save()
            return Response(data={"message": "go to login", f"{user_info.username} is_active": user_info.is_active},
                            status=status.HTTP_200_OK)


class LogoutView(GenericAPIView):
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def post(self, request, *args):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "logout process was successfull"}, status=status.HTTP_204_NO_CONTENT)
