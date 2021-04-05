from django.shortcuts import render, redirect
from smart_store_project import my_settings
import requests
from django.http import JsonResponse
from rest_framework import viewsets
# from .serializers import UserSerializer, MerchandiseSerializer
# from .models import User, Merchandise

# Create your views here.

# class UserViewSet(viewsets.ModelViewSet):
#     queryset = User.objects.all()
#     serializer_class = UserSerializer

# class MerchandiseViewSet(viewsets.ModelViewSet):
#     queryset = Merchandise.objects.all()
#     serialzer_class = MerchandiseSerializer

# source
APP_REST_API_KEY = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
KAKAO_CALLBACK_URI = "http://127.0.0.1:8000/account/login/kakao/callback"

def kakao_login(request):
    api_key = APP_REST_API_KEY
    redirect_uri = KAKAO_CALLBACK_URI
    dest_url = f"https://kauth.kakao.com/oauth/authorize?client_id={api_key}&redirect_uri={redirect_uri}&response_type=code"
    return redirect(dest_url)

def kakao_callback(request):
    api_key = APP_REST_API_KEY
    redirect_uri = KAKAO_CALLBACK_URI
    code = request.GET['code']
    dest_url = f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={api_key}&redirect_uri={redirect_uri}&code={code}'
    response = requests.post(dest_url)
    response_json= response.json()
    # session
    request.session['access_token'] = response_json['access_token']
    request.session.modified = True
    access_token = request.session['access_token']
    profile_request = requests.get("https://kapi.kakao.com/v2/user/me", headers={"Authorization" : f"Bearer {access_token}"})
    profile_json = profile_request.json()
    print(profile_json)
    return JsonResponse(response_json)

def kakao_logout(request):
    access_token = request.session['access_token']
    destination_url = 'https://kapi.kakao.com/v1/user/logout'
    header = {
        'Authorization': f'bearer {access_token}'
    }
    # destination_url = 'https://kapi.kakao.com/v1/user/unlink'
    # header = {
    #     'Authorization': f'bearer {access_token}',
    # }
    response = requests.post(destination_url, headers=header)
    response_json = response.json()
    if response_json.get('id'):
        del request.session['access_token']
        return render(request, 'logoutSuccess.html')
    else:
        return render(request, 'logoutError.html')
