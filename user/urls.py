from django.urls import path
from . import views

urlpatterns = [
    # React에서 Cognito와 통신할 수 있는 URL들 (user 하위로 통일)
    path('user/signup/', views.signup, name='signup'),
    path('user/login/', views.login_view, name='login'),
    path('user/confirm/', views.confirm_registration, name='confirm'),
    
    # 사용자 정보 관련 URL들 (Cognito JWT로 인증)
    path('user/profile/', views.get_user_info, name='user'),
    path('user/update/', views.update_user_info, name='update_user_info'),
]