from django.urls import path
from . import views

urlpatterns = [
    # 사용자 인증 관련 API들 (user 하위로 통일)
    path('user/signup/', views.signup, name='signup'),
    path('user/login/', views.login_view, name='login'),
    path('user/confirm/', views.confirm_registration, name='confirm'),
    
    # 사용자 정보 관련 API들
    path('user/profile/', views.get_user_info, name='user_info'),
    path('user/update/', views.update_user_info, name='update_user_info'),
    path('user/delete/', views.delete_user_account, name='delete_user_account'),
]