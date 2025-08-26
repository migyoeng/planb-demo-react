from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils import timezone
from .models import User, EmailVerification

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ['idx', 'username', 'email', 'tel', 'name', 'team', 'is_staff', 'is_active', 'date_joined', 'cognito_status']
    list_filter = ['is_staff', 'is_active', 'team', 'cognito_status', 'date_joined']
    search_fields = ['username', 'email', 'name']
    ordering = ['-date_joined']
    
    fieldsets = (
        ('기본 정보', {'fields': ('username', 'password', 'email', 'name', 'tel', 'birth')}),
        ('추가 정보', {'fields': ('team', 'cognito_sub', 'cognito_status')}),
        ('권한', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
        ('시간 정보', {'fields': ('date_joined', 'last_login')}),
    )
    
    readonly_fields = ['date_joined', 'last_login', 'cognito_sub', 'cognito_status']
    
    def save_model(self, request, obj, form, change):
        if not change:  # 새로 생성하는 경우
            obj.date_joined = timezone.now()
        super().save_model(request, obj, form, change)

@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'created_at', 'expires_at', 'is_used']
    list_filter = ['is_used', 'created_at']
    search_fields = ['user__username', 'code']
    readonly_fields = ['created_at']