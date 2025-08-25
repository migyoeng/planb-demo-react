from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'idx', 'username', 'email', 'tel', 'birth', 'gender', 
            'team', 'create_at', 'updated_at', 'is_staff', 'is_active', 'last_login'
        ]
        read_only_fields = ['idx', 'create_at', 'updated_at', 'last_login']

class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=3)
    userpw = serializers.CharField(max_length=100, write_only=True)
    email = serializers.CharField(max_length=20)
    tel = serializers.IntegerField()
    birth = serializers.DateField()
    gender = serializers.ChoiceField(choices=[(1, '남'), (2, '여')])
    team = serializers.CharField(max_length=10, required=False, allow_blank=True)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=3)
    userpw = serializers.CharField(max_length=100)

class ConfirmSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=3)
    code = serializers.CharField(max_length=6)