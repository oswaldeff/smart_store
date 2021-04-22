from django.contrib import admin
from .models import User, Merchandise
# Register your models here.

class User_admin(admin.ModelAdmin):
    list_display = [
        'User_pk',
        'nickname',
        'kakao_id',
        'is_staff',
        'is_admin',
        'is_active',
        'is_superuser',
        ]

class Merchandise_admin(admin.ModelAdmin):
    list_display = [
        'id',
        'User_pk',
        'item_name',
        ]

admin.site.register(User, User_admin)
admin.site.register(Merchandise, Merchandise_admin)