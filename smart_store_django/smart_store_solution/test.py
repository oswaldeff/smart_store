from django.shortcuts import render, redirect
from smart_store_project import my_settings
import requests
from django.http import JsonResponse

# social login(kakao)
## login
def kakao_login_test(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    # for TEST
    redirect_uri = 'http://127.0.0.1:8000/accounts/login/kakao/callback/test'
    dest_url = f'https://kauth.kakao.com/oauth/authorize?client_id={api_key}&redirect_uri={redirect_uri}&response_type=code'
    return redirect(dest_url)

def kakao_callback_test(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    # for TEST
    redirect_uri = 'http://127.0.0.1:8000/accounts/login/kakao/callback/test'
    code = request.GET['code']
    dest_url = f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={api_key}&redirect_uri={redirect_uri}&code={code}'
    # response
    response = requests.get(dest_url)
    response_json = response.json()
    # access_token
    access_token = response_json['access_token']
    return JsonResponse({'access_token': access_token})