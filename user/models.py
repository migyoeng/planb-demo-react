from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class User(AbstractUser):
    # 새로운 DB 스키마에 맞춘 필드들
    idx = models.BigAutoField(primary_key=True)
    cognito_sub = models.CharField(max_length=128, unique=True, null=True, blank=True)
    username = models.CharField(max_length=150, unique=True)
    email = models.CharField(max_length=254)
    password = models.CharField(max_length=128)  # 비밀번호 저장
    date_joined = models.DateTimeField(auto_now_add=True)
    tel = models.CharField(max_length=20, null=True, blank=True)
    birth = models.CharField(max_length=10, null=True, blank=True)
    team = models.CharField(max_length=20, null=True, blank=True)
    name = models.CharField(max_length=150, null=True, blank=True)
    cognito_status = models.CharField(max_length=16, default='UNCONFIRMED')
    
    # Django AbstractUser와 충돌하는 필드들 재정의
    first_name = None
    last_name = None
    last_login = None  # last_login 필드 제거
    is_staff = None    # is_staff 필드 제거
    is_active = None   # is_active 필드 제거  
    # is_superuser는 관리자 구분용으로 유지
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'password']  # password 다시 추가
    
    class Meta:
        db_table = 'user'  # 새로운 테이블명
        verbose_name = '사용자'
        verbose_name_plural = '사용자들'
    
    def __str__(self):
        return self.username

class EmailVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verifications')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'email_verifications'
        verbose_name = '이메일 인증'
        verbose_name_plural = '이메일 인증들'
    
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at