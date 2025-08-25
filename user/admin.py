from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils import timezone
from .models import User, EmailVerification

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ['idx', 'username', 'email', 'tel', 'gender', 'team', 'is_staff', 'is_active', 'create_at']
    list_filter = ['is_staff', 'is_active', 'gender', 'team', 'create_at']
    search_fields = ['username', 'email']
    ordering = ['-create_at']
    
    fieldsets = (
        ('기본 정보', {'fields': ('username', 'userpw', 'email', 'tel', 'birth', 'gender')}),
        ('추가 정보', {'fields': ('team', 'token_id')}),
        ('권한', {'fields': ('is_staff', 'is_active')}),
        ('시간 정보', {'fields': ('create_at', 'updated_at', 'last_login')}),
    )
    
    readonly_fields = ['create_at', 'updated_at', 'last_login']
    
    def save_model(self, request, obj, form, change):
        if not change:  # 새로 생성하는 경우
            obj.create_at = timezone.now()
        obj.updated_at = timezone.now()
        super().save_model(request, obj, form, change)

@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'created_at', 'expires_at', 'is_used']
    list_filter = ['is_used', 'created_at']
    search_fields = ['user__username', 'code']
    readonly_fields = ['created_at']