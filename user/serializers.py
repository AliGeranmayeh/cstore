from rest_framework import serializers
from .models import CustomUser, EmailValidation
from django.utils.text import gettext_lazy
from rest_framework_simplejwt.tokens import RefreshToken, TokenError



class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True, allow_null=False, allow_blank=False)
    password = serializers.CharField(style={"input_type": "password"},
                                     required=True, allow_blank=False, allow_null=False)
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'name', 'phone_number', 'address', 'is_active', 'picture','postal_code']


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'name', 'phone_number', 'address', 'is_active', 'picture','postal_code']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class EmailVerificationSerializer(serializers.ModelSerializer):
    code = serializers.IntegerField(required=True, allow_null=False)
    email = serializers.CharField(required=True, allow_null=False, allow_blank=False)
    class Meta:
        model = EmailValidation
        fields = ['id', 'email', 'code']


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': gettext_lazy('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')