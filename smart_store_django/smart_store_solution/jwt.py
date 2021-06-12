import jwt
from requests.api import head
from smart_store_project import my_settings
from django.http import JsonResponse
from .models import User
import json

def jwt_publish(kakao_id, access_token):
    access_jwt = jwt.encode({'exp': my_settings.JWT_AUTH['JWT_EXPIRATION_DELTA'], 'kakao_id': kakao_id}, my_settings.JWT_AUTH['JWT_SECRET_KEY']+access_token, algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
    access_jwt = access_jwt.decode('utf-8')
    #print("def)jwt_publish -> access_jwt: ", access_jwt)
    return access_jwt

def jwt_authorization(func):
    def wrapper(self, request, *args, **kwargs):
        #print('def)jwt_authorization -> inn')
        try:
            # access_token
            try:
                access_token = request.cookies['access_token']
            except KeyError:
                return JsonResponse({"message": "COOKIES KEY ERROR"}, status=400)
            # access_jwt
            try:
                access_jwt = request.headers['Authorization']
            except KeyError:
                return JsonResponse({"message": "HEADERS KEY ERROR"}, status=400)
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