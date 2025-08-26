from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'idx', 'username', 'email', 'tel', 'birth', 'team', 'name',
            'date_joined', 'cognito_sub', 'cognito_status', 'is_active', 'last_login'
        ]
        read_only_fields = ['idx', 'date_joined', 'last_login', 'cognito_sub', 'cognito_status']

class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)
    email = serializers.CharField(max_length=254)
    tel = serializers.CharField(max_length=20, required=False, allow_blank=True)
    birth = serializers.CharField(max_length=10, required=False, allow_blank=True)
    team = serializers.CharField(max_length=20, required=False, allow_blank=True)
    name = serializers.CharField(max_length=150, required=False, allow_blank=True)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128)

class ConfirmSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    code = serializers.CharField(max_length=6)