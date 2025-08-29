from django.urls import path
from . import views

urlpatterns = [
    path('user/', views.get_user_info, name='user_info'),
    path('user/update/', views.update_user_info, name='update_user_info'),
    path('user/create/', views.signup, name='create_user'),  # 사용자 생성 API 추가
]