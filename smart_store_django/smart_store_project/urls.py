"""smart_store_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from smart_store_solution import views
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token, refresh_jwt_token

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # user
    path('user/', views.UserRestfulMain.as_view(), name='User_list'),
    # merchandise
    path('merchandise/', views.MerchandiseRestfulMain.as_view(), name='Merchandise_list'),
    path('merchandise/create/', views.MerchandiseRestfulCreate.as_view(), name='Merchandise_create'),
    path('merchandise/detail/<User_pk>/<id>/', views.MerchandiseRestfulDetail.as_view(), name='Merchandise_detail'),
    path('merchandise/detail/<User_pk>/<id>/update/', views.MerchandiseRestfulUpdate.as_view(), name='Merchandise_update'),
    path('merchandise/detail/<User_pk>/<id>/delete/', views.MerchandiseRestfulDelete.as_view(), name='Merchandise_delete'),
    
    # kakao login & logout, user delete
    path('account/login/kakao/', views.kakao_login, name='kakao_login'),
    path('account/login/kakao/callback/', views.kakao_callback, name='kakao_callback'),
    path('account/logout/kakao/', views.kakao_logout, name='kakao_logout'),
    path('account/delete/', views.User_delete, name='User_delete'),
]
