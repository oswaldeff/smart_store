from django.shortcuts import render, redirect, get_object_or_404
from smart_store_project import my_settings
import requests
from django.http import JsonResponse, HttpResponse
from rest_framework.generics import ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView, CreateAPIView
from .serializers import UserSerializer, MerchandiseSerializer, MerchandiseDetailSerializer, MerchandiseCreateSerializer
from .models import User, Merchandise
import jwt
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
from .jwt import jwt_publish, jwt_authorization

# Create your views here.


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
    permission_classes = [AllowAny]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    @csrf_exempt
    @jwt_authorization
    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=200)

# Merchandise classes
## Create
class MerchandiseRestfulCreate(CreateAPIView):
    permission_classes = [AllowAny]
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseCreateSerializer
    
    @csrf_exempt
    @jwt_authorization
    def post(self, request, *args, **kwargs):
        request.data['User_pk'] = int(str(request.user))
        self.create(request, *args, **kwargs)
        return JsonResponse({'message': 'MERCHANDISE CREATION SUCCESS'}, status=201)

## Read
class MerchandiseRestfulMain(ListAPIView):
    permission_classes = [AllowAny]
    lookup_field = 'User_pk'
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer
    
    @csrf_exempt
    @jwt_authorization
    def get(self, request, *args, **kwargs):
        datas = []
        for m in Merchandise.objects.filter(User_pk=request.user):
            serializer = self.serializer_class(m)
            datas.append(serializer.data)
        return Response(datas, status=200)

class MerchandiseRestfulDetail(MultipleFieldLookupMixin, RetrieveAPIView):
    permission_classes = [AllowAny]
    lookup_fields = ['User_pk', 'id']
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseDetailSerializer
    
    @csrf_exempt
    @jwt_authorization
    def get(self, request, *args, **kwargs):
        try:
            if MultipleFieldLookupMixin.get_object(self) in Merchandise.objects.filter(User_pk=request.user):
                serializer = self.serializer_class(MultipleFieldLookupMixin.get_object(self))
            return Response(serializer.data, status=200)
        except:
            return JsonResponse({'message': 'NOT FOUND'}, status=404)

## Update
class MerchandiseRestfulUpdate(MultipleFieldLookupMixin, UpdateAPIView):
    permission_classes = [AllowAny]
    lookup_fields = ['User_pk', 'id']
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer
    
    @csrf_exempt
    @jwt_authorization
    def put(self, request, *args, **kwargs):
        request.data['User_pk'] = int(str(request.user))
        self.update(request, *args, **kwargs)
        return JsonResponse({'message': 'MERCHANDISE UPDATE SUCCESS'}, status=201)


## Delete
class MerchandiseRestfulDelete(MultipleFieldLookupMixin, DestroyAPIView):
    permission_classes = [AllowAny]
    lookup_fields = ['User_pk', 'id']
    queryset = Merchandise.objects.all()
    serializer_class = MerchandiseSerializer
    
    @csrf_exempt
    @jwt_authorization
    def delete(self, request, *args, **kwargs):
        request.data['User_pk'] = int(str(request.user))
        self.destroy(request, *args, **kwargs)
        return JsonResponse({'message': 'MERCHANDISE DELETION SUCCESS'}, status=201)

# social login(kakao)
## login
@csrf_exempt
def kakao_login(request):
    if request.method == 'GET':
        # access_token
        print('req header: ', request.headers)
        print('req Authorization: ', request.headers['Authorization'])
        #print('req Cookies: ', request.headers['Cookies'])
        print('req cookie: ', request.COOKIES)
        try:
            access_token = request.headers['tk']
            print('from cookie: ', access_token)
        except:
            return JsonResponse({"message": "COOKIE ERROR"}, status=400)
        
        request.session.modified = True
        profile_url = 'https://kapi.kakao.com/v2/user/me'
        headers = {'Authorization' : f'Bearer {access_token}'}
        # profile
        profile_request = requests.get(profile_url, headers=headers)
        profile_json = profile_request.json()
        # User
        ## field values
        try:
            kakao_id = profile_json['id']
            nickname = profile_json['properties']['nickname']
            User_search = User.objects.filter(kakao_id=kakao_id)
        except KeyError:
            return JsonResponse({"message": "KAKAO PROFILE KEY ERROR"}, status=400)
        ## create
        if len(User_search) == 0:
            User.objects.create(kakao_id=kakao_id, nickname=nickname)
            access_jwt = jwt_publish(kakao_id, access_token)
        ## login
        if len(User_search) != 0:
            access_jwt = jwt_publish(kakao_id, access_token)
        # headers
        #headers = {'message': 'LOGIN SUCCESS','Authorization': f'jwt {access_jwt}'}
        # response
        #response = JsonResponse(headers, status=201)
        response = HttpResponse('LOGIN SUCCESS')
        response.set_cookie('access_jwt', value=access_jwt, max_age=60*60*24*7, expires=None, path='/', domain='http://smartstore-test90.s3-website.ap-northeast-2.amazonaws.com', secure=False, httponly=False, samesite=None)
        #response = HttpResponse.set_cookie('access_jwt', access_jwt)
        #response.headers['Cookies'] = access_jwt
        return response
    else:
        return JsonResponse({'message': 'UNAUTHORIZED HTTP METHOD'}, status=400)

## logout
# @csrf_exempt
# def kakao_logout(request):
#     #api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
#     #redirect_uri = 'http://ec2-3-35-137-239.ap-northeast-2.compute.amazonaws.com'
#     # for TEST
#     #redirect_uri = 'http://127.0.0.1:8000'
#     access_token = access_token
#     #dest_url = f'https://kauth.kakao.com/oauth/logout?client_id={api_key}&logout_redirect_uri={redirect_uri}'
#     #response = requests.get(dest_url)
    
#     profile_url = 'https://kapi.kakao.com/v2/user/me'
#     headers = {'Authorization' : f'Bearer {access_token}'}
#     profile_request = requests.get(profile_url, headers=headers)
#     profile_json = profile_request.json()
#     kakao_id = profile_json['id']
    
#     return JsonResponse({'message': 'LOGOUT SUCCESS'}, status=201)

## leave service
@csrf_exempt
@jwt_authorization
def User_delete(request):
    if request.method == "POST":
        # access_token = request.session['access_token']
        # profile_url = 'https://kapi.kakao.com/v2/user/me'
        # headers = {'Authorization' : f'Bearer {access_token}'}
        # profile_request = requests.get(profile_url, headers=headers)
        # profile_json = profile_request.json()
        # kakao_id = profile_json['id']
        
        # Unlink kakao
        #dest_url = 'https://kapi.kakao.com/v1/user/unlink'
        #response = requests.get(dest_url, headers=headers)
        
        # del User
        User_pk = request.user
        User_search = User.objects.filter(User_pk=User_pk)
        User_search.delete()
        return JsonResponse({'message': 'USER DELETION SUCCESS'}, status=201)
    else:
        return JsonResponse({'message': 'UNAUTHORIZED METHOD'}, status=400)