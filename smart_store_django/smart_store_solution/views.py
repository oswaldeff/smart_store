from django.shortcuts import render, redirect, get_object_or_404
from smart_store_project import my_settings
import requests
from django.http import JsonResponse
from rest_framework.generics import ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView, CreateAPIView
from .serializers import UserSerializer, UserDetailSerializer, MerchandiseSerializer, MerchandiseDetailSerializer, MerchandiseCreateSerializer
from .models import User, Merchandise
import jwt
#from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework import status

# Create your views here.

# jwt
def jwt_publish(kakao_id):
    access_jwt = jwt.encode({'kakao_id': kakao_id}, my_settings.JWT_AUTH['JWT_SECRET_KEY'], algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
    access_jwt = access_jwt.decode('utf-8')
    return access_jwt

def jwt_authorization(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            access_jwt = request.COOKIES.get('access_jwt')
            payload = jwt.decode(access_jwt, my_settings.JWT_AUTH['JWT_SECRET_KEY'], algorithm=my_settings.JWT_AUTH['JWT_ALGORITHM'])
            login_user = User.objects.get(kakao_id=payload['kakao_id'])
            print(login_user)
            request.user = login_user
            return func(self, request, *args, **kwargs)
        except jwt.exceptions.DecodeError:
            return JsonResponse({'message':'INVALID_TOKEN'},status=400)
    return wrapper

# multiple lookup fields
class MultipleFieldLookupMixin:
    """
    Apply this mixin to any view or viewset to get multiple field filtering
    based on a `lookup_fields` attribute, instead of the default single field filtering.
    """
    def get_object(self):
        queryset = self.get_queryset()             # Get the base queryset
        queryset = self.filter_queryset(queryset)  # Apply any filter backends
        filter = {}
        for field in self.lookup_fields:
            if self.kwargs[field]: # Ignore empty fields.
                filter[field] = self.kwargs[field]
        obj = get_object_or_404(queryset, **filter)  # Lookup the object
        self.check_object_permissions(self.request, obj)
        return obj

# User classes
## Read
class UserRestfulMain(ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserRestfulDetail(RetrieveAPIView):
    lookup_field = 'User_pk'
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication]
    @jwt_authorization
    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        print(serializer)
        print('get in....')
        return Response(serializer.data, status=status.HTTP_200_OK)

# Merchandise classes
## Create
class MerchandiseRestfulCreate(CreateAPIView):
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseCreateSerializer

## Read
class MerchandiseRestfulMain(ListAPIView):
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer

class MerchandiseRestfulDetail(MultipleFieldLookupMixin, RetrieveAPIView):
    lookup_fields = ['User_pk', 'id']
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseDetailSerializer

## Update
class MerchandiseRestfulUpdate(UpdateAPIView):
    lookup_field = 'id'
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer

## Delete
class MerchandiseRestfulDelete(DestroyAPIView):
    lookup_field = 'id'
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer

# social login(kakao)
## login
def kakao_login(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    redirect_uri = 'http://127.0.0.1:8000/account/login/kakao/callback'
    dest_url = f'https://kauth.kakao.com/oauth/authorize?client_id={api_key}&redirect_uri={redirect_uri}&response_type=code'
    
    return redirect(dest_url)

def kakao_callback(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    redirect_uri = 'http://127.0.0.1:8000/account/login/kakao/callback'
    code = request.GET['code']
    dest_url = f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={api_key}&redirect_uri={redirect_uri}&code={code}'
    response = requests.get(dest_url)
    response_json= response.json()
    
    # create session
    request.session['access_token'] = response_json['access_token']
    request.session.modified = True
    access_token = request.session['access_token']
    profile_url = 'https://kapi.kakao.com/v2/user/me'
    headers = {'Authorization' : f'Bearer {access_token}'}
    profile_request = requests.get(profile_url, headers=headers)
    profile_json = profile_request.json()
    
    # User
    ## check
    kakao_id = profile_json['id']
    nickname = profile_json['properties']['nickname']
    User_search = User.objects.filter(kakao_id=kakao_id)
    
    ## create
    if len(User_search) == 0:
        User.objects.create(kakao_id=kakao_id, nickname=nickname)
        access_jwt = jwt_publish(kakao_id)
    
    ## login
    if len(User_search) != 0:
        User_search.update(is_active=True)
        access_jwt = jwt_publish(kakao_id)
    
    response_token = JsonResponse(response_json)
    response_token.set_cookie('access_jwt', access_jwt, max_age=None)
    
    return response_token

## logout
def kakao_logout(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    redirect_uri = 'http://127.0.0.1:8000/'
    access_token = request.session['access_token']
    dest_url = f'https://kauth.kakao.com/oauth/logout?client_id={api_key}&logout_redirect_uri={redirect_uri}'
    response = requests.get(dest_url)
    
    profile_url = 'https://kapi.kakao.com/v2/user/me'
    headers = {'Authorization' : f'Bearer {access_token}'}
    profile_request = requests.get(profile_url, headers=headers)
    profile_json = profile_request.json()
    kakao_id = profile_json['id']
    
    # logout User
    User_search = User.objects.filter(kakao_id=kakao_id)
    User_search.update(is_active=False)
    
    # del session
    del request.session['access_token']
    
    token_reset = ''
    response_token = JsonResponse({'success':True})
    response_token.set_cookie('access_jwt', token_reset)
    
    return redirect(dest_url)

## leave service
def User_delete(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    access_token = request.session['access_token']
    profile_url = 'https://kapi.kakao.com/v2/user/me'
    headers = {'Authorization' : f'Bearer {access_token}'}
    profile_request = requests.get(profile_url, headers=headers)
    profile_json = profile_request.json()
    kakao_id = profile_json['id']
    
    dest_url = 'https://kapi.kakao.com/v1/user/unlink'
    response = requests.get(dest_url, headers=headers)
    
    # del User
    User_search = User.objects.filter(kakao_id=kakao_id)
    User_search.delete()
    
    # del session
    del request.session['access_token']
    
    return redirect('https://accounts.kakao.com/login?continue=https%3A%2F%2Fkauth.kakao.com%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3D568c2628fe5c198647460fc4e4243944%26redirect_uri%3Dhttp%253A%252F%252F127.0.0.1%253A8000%252Faccount%252Flogin%252Fkakao%252Fcallback')