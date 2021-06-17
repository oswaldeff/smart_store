import jwt
from requests.api import head
from smart_store_project import my_settings
from django.http import JsonResponse
from .models import User
import json

def jwt_publish(kakao_id, access_token):
    access_jwt = jwt.encode({'exp': my_settings.JWT_AUTH['JWT_EXPIRATION_DELTA'], 'kakao_id': kakao_id}, my_settings.JWT_AUTH['JWT_SECRET_KEY']+access_token, algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
    access_jwt = access_jwt.decode('utf-8')
    return access_jwt

def jwt_authorization(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            # access_token
            try:
                access_token = request.headers['Tk']
            except KeyError:
                return JsonResponse({"message": "HEADERS TK KEY ERROR"}, status=400)
            # access_jwt
            try:
                Authorization = request.headers['Authorization']
                access_jwt = Authorization.split("jwt ")[1]
            except KeyError:
                return JsonResponse({"message": "HEADERS JWT KEY ERROR"}, status=400)
            # decode
            payload = jwt.decode(access_jwt, my_settings.JWT_AUTH['JWT_SECRET_KEY']+access_token, algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
            login_user = User.objects.get(kakao_id=payload['kakao_id'])
            request.user = login_user
            return func(self, request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'JWTOKEN EXPIRED'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'INVALID JWTOKEN'}, status=401)
    return wrapper