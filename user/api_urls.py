from django.urls import path
from . import views

urlpatterns = [
    path('user/', views.get_user_info, name='user_info'),
]