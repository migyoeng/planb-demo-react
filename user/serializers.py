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