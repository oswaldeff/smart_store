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
            try:
                headers = request.headers['Authorization']
                headers = json.loads(headers)
                access_token = headers['access_token']
                access_jwt = headers['access_jwt']
            except KeyError:
                return JsonResponse({"message": "AUTHORIZATION KEY ERROR"}, status=400)
            
            payload = jwt.decode(access_jwt, my_settings.JWT_AUTH['JWT_SECRET_KEY']+access_token, algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
            #print('def)jwt_authorization -> payload: ', payload)
            login_user = User.objects.get(kakao_id=payload['kakao_id'])
            #print('def)jwt_authorization -> login_user: ', login_user, ', type: ', type(login_user))
            request.user = login_user
            #print('def)jwt_authorization -> request.user(login_user): ', request.user)
            return func(self, request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message': 'JWTOKEN EXPIRED'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'message': 'INVALID JWTOKEN'}, status=401)
    return wrapper