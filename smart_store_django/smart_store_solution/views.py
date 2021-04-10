from django.shortcuts import render, redirect, get_object_or_404
from smart_store_project import my_settings
import requests
from django.http import JsonResponse
from rest_framework.generics import ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView, CreateAPIView
from .serializers import UserSerializer, UserDetailSerializer, MerchandiseSerializer, MerchandiseDetailSerializer, MerchandiseCreateSerializer
from .models import User, Merchandise

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
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserRestfulDetail(RetrieveAPIView):
    lookup_field = 'User_pk'
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer

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
    response = requests.post(dest_url)
    response_json= response.json()
    
    # create session
    request.session['access_token'] = response_json['access_token']
    request.session.modified = True
    access_token = request.session['access_token']
    profile_request = requests.get(
        'https://kapi.kakao.com/v2/user/me', 
        headers={'Authorization' : f'Bearer {access_token}'}
        )
    profile_json = profile_request.json()
    
    # User
    ## check
    User_search = User.objects.filter(
        kakao_id = profile_json['id']
        )
    ## create
    if len(User_search) == 0:
        User.objects.create(
            kakao_id = profile_json['id'],
            nickname = profile_json['properties']['nickname']
            )
    
    return JsonResponse(response_json)

## logout
def kakao_logout(request):
    api_key = my_settings.SOCIALACCOUNTS['kakao']['app']['client_id']
    redirect_uri = 'http://127.0.0.1:8000/'
    access_token = request.session['access_token']
    dest_url = f'https://kauth.kakao.com/oauth/logout?client_id={api_key}&logout_redirect_uri={redirect_uri}'
    response = requests.get(dest_url)
    
    # del session
    del request.session['access_token']
    
    return redirect(dest_url)

## leave service
def User_delete(request):
    access_token = request.session['access_token']
    profile_request = requests.get(
        'https://kapi.kakao.com/v2/user/me',
        headers={'Authorization' : f'Bearer {access_token}'})
    profile_json = profile_request.json()
    
    dest_url = 'https://kapi.kakao.com/v1/user/unlink'
    response = requests.post(dest_url)
    
    # del User
    User_search = User.objects.filter(
        kakao_id = profile_json['id']
        )
    User_search.delete()
    
    # del session
    del request.session['access_token']
    
    return redirect('http://127.0.0.1:8000/')