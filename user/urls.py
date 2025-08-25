from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('confirm/', views.confirm_registration, name='confirm'),
    path('logout/', views.logout_view, name='logout'),
    path('verify/', views.verify_token, name='verify'),
    #path('resend/', views.resend_verification, name='resend'),
]