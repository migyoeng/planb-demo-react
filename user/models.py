from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class User(AbstractUser):
    # 기존 DB 스키마에 맞춘 필드들
    idx = models.BigAutoField(primary_key=True)
    token_id = models.BigIntegerField(null=True, blank=True)
    username = models.CharField(max_length=3, unique=True)  # varchar(3)
    userpw = models.CharField(max_length=100)  # varchar(100) - 비밀번호
    email = models.CharField(max_length=20)  # varchar(20)
    tel = models.SmallIntegerField()  # smallint - 전화번호
    birth = models.DateField()  # date - 생년월일
    gender = models.SmallIntegerField(choices=[(1, '남'), (2, '여')])  # tinyint
    team = models.CharField(max_length=10, null=True, blank=True)  # varchar(10), nullable
    create_at = models.DateTimeField(auto_now_add=True)  # datetime, default CURRENT_TIMESTAMP
    updated_at = models.DateTimeField(auto_now=True)  # datetime, default CURRENT_TIMESTAMP
    is_staff = models.SmallIntegerField(choices=[(0, '사용자'), (1, '관리자')], default=0)  # tinyint
    is_active = models.SmallIntegerField(choices=[(0, '비활성'), (1, '활성')], default=1)  # tinyint
    last_login = models.DateTimeField(null=True, blank=True)  # datetime
    
    # Django AbstractUser와 충돌하는 필드들 재정의
    password = None  # userpw 사용
    date_joined = None  # create_at 사용
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['userpw', 'email', 'tel', 'birth', 'gender']
    
    class Meta:
        db_table = 'users'  # 기존 테이블명
        verbose_name = '사용자'
        verbose_name_plural = '사용자들'
    
    def set_password(self, raw_password):
        """비밀번호 설정 (userpw 필드에 저장)"""
        self.userpw = raw_password
    
    def check_password(self, raw_password):
        """비밀번호 확인 (userpw 필드와 비교)"""
        return self.userpw == raw_password

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