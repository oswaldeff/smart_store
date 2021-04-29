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
# from rest_framework import routers

# router = routers.DefaultRouter()
# router.register('Users', views.UserViewSet)
# router.register('Merchandises', views.MerchandiseViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    #path('rest-auth', include('rest_auth.urls')),
    #path('rest-auth/registration/', include('rest_auth.registration.urls')),
    #path('account/', include('allauth.urls')),
    
    # rest API
    path('user/', views.UserRestfulMain.as_view(), name='Users_list'),
    # path('users/detail/<User_pk>/', views.UserRestfulDetail.as_view(), name='Users_detail'),
    
    path('merchandise/', views.MerchandiseRestfulMain.as_view(), name='Merchandises_list'),
    path('merchandise/create/', views.MerchandiseRestfulCreate.as_view(), name='Merchandises_create'),
    path('merchandise/detail/<User_pk>/<id>/', views.MerchandiseRestfulDetail.as_view(), name='Merchandises_detail'),
    path('merchandise/detail/<User_pk>/<id>/update/', views.MerchandiseRestfulUpdate.as_view(), name='Merchandises_update'),
    path('merchandise/detail/<User_pk>/<id>/delete/', views.MerchandiseRestfulDelete.as_view(), name='Merchandises_delete'),
    
    # kakao login
    path('account/login/kakao/', views.kakao_login, name='kakao_login'),
    path('account/login/kakao/callback/', views.kakao_callback, name='kakao_callback'),
    path('account/logout/kakao/', views.kakao_logout, name='kakao_logout'),
    path('account/delete/', views.User_delete, name='User_delete'),
    
    # jwt
    # path('api/token/', obtain_jwt_token),
    # path('api/token//refresh/', refresh_jwt_token),
    # path('api/token/verify/', verify_jwt_token),
]
