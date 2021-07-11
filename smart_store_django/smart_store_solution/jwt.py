import jwt
from requests.api import head
from smart_store_project import my_settings
from django.http import JsonResponse
from .models import User
import json
import datetime

def jwt_publish(kakao_id):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=60*60*6) # error log: if use it from my_settings, it makes error: it doesnt apply server time
    access_jwt = jwt.encode({'exp': expiration, 'kakao_id': kakao_id}, my_settings.JWT_AUTH['JWT_SECRET_KEY'], algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
    access_jwt = access_jwt.decode('utf-8')
    return access_jwt

def jwt_authorization(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            # access_jwt
            try:
                Authorization = request.headers['Authorization']
                if "jwt " in Authorization: 
                    access_jwt = Authorization.split("jwt ")[1]
                else:
                    return JsonResponse({'message': '로그인 해주세요.'},  json_dumps_params={'ensure_ascii': False}, status=400)
            except KeyError:
                return JsonResponse({'message': 'HEADERS JWT KEY ERROR'}, status=400)
            # decode
            payload = jwt.decode(access_jwt, my_settings.JWT_AUTH['JWT_SECRET_KEY'], algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
            login_user = User.objects.get(kakao_id=payload['kakao_id'])
            request.user = login_user
            return func(self, request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'JWTOKEN EXPIRED'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'INVALID JWTOKEN'}, status=401)
    return wrapper