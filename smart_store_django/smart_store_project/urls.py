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
from django.urls import path
from smart_store_solution import views, test

urlpatterns = [
    path('admin', admin.site.urls),
    
    # user
    path('users', views.UserRestfulMain.as_view(), name='User_list'),
    # merchandise
    path('merchandises', views.MerchandiseRestfulMain.as_view(), name='Merchandise_list'),
    path('merchandises/create', views.MerchandiseRestfulCreate.as_view(), name='Merchandise_create'),
    path('merchandises/detail/<User_pk>/<id>', views.MerchandiseRestfulDetail.as_view(), name='Merchandise_detail'),
    path('merchandises/detail/<User_pk>/<id>/update', views.MerchandiseRestfulUpdate.as_view(), name='Merchandise_update'),
    path('merchandises/detail/<User_pk>/<id>/delete', views.MerchandiseRestfulDelete.as_view(), name='Merchandise_delete'),
    
    # kakao login & logout, user delete
    path('accounts/login/kakao/test', test.kakao_login_test, name='kakao_login_test'),
    path('accounts/login/kakao/callback/test', test.kakao_callback_test, name='kakao_callback_test'),
    path('accounts/login/kakao', views.kakao_login, name='kakao_login'),
    # path('accounts/logout/kakao', views.kakao_logout, name='kakao_logout'),
    path('accounts/delete', views.User_delete, name='User_delete'),
]
