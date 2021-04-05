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
from rest_framework import routers

# router = routers.DefaultRouter()
# router.register('Users', view.UserViewSet)
# router.register('Merchandises', view.MerchandiseViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # auth
    #path('account/', include('rest_auth.urls')),
    path('account/registration/', include('rest_auth.registration.urls')),
    path('account/', include('allauth.urls')),
    # path('', include(router.urls)),
    # kakao login
    path('account/login/kakao/', views.kakao_login, name='kakao_login'),
    path('account/login/kakao/callback/', views.kakao_callback, name='kakao_callback'),
    path('account/logout/kakao/', views.kakao_logout, name='kakao_logout'),
]
