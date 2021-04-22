from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, kakao_id, nickname, password=None, **extra_fields):
        """
        주어진 카카오아이디값, 닉네임으로 개인정보로 User 인스턴스 생성
        """
        user = self.model(kakao_id=kakao_id, nickname=nickname)
        user.set_unusable_password()
        #user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, kakao_id, nickname, password=None, **extra_fields):
        """
        주어진 카카오아이디값, 비밀번호 등 개인정보로 User 인스턴스 생성
        단, 최상위 사용자이므로 권한을 부여한다. 
        """
        superuser = self.create_user(kakao_id=kakao_id, nickname=nickname, password=password)
        superuser.is_staff= True
        superuser.is_admin = True
        superuser.is_active = True
        superuser.is_superuser = True
        superuser.save()
        return superuser

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, null=True, blank=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    
    User_pk = models.AutoField(primary_key=True)
    kakao_id = models.IntegerField(unique=True)
    nickname = models.CharField(max_length=40, null=True, blank=True)
    
    
    USERNAME_FIELD = 'kakao_id'
    REQUIRED_FIELDS = ['nickname']
    
    objects = UserManager()
    
    def __str__(self):
        return str(self.User_pk)
    
    class Meta:
        db_table = 'Users'

class Merchandise(models.Model):
    id = models.AutoField(primary_key=True)
    User_pk = models.ForeignKey(User, on_delete=models.CASCADE, db_column='User_pk')
    item_name = models.CharField(max_length=255, null=True)
    country_from = models.CharField(max_length=255, null=True)
    item_currency = models.CharField(max_length=255, null=True)
    shipping_currency = models.CharField(max_length=255, null=True)
    etc_currency = models.CharField(max_length=255, null=True)
    shipping_fee_from = models.IntegerField()
    shipping_fee_to = models.IntegerField()
    cost = models.IntegerField()
    price = models.IntegerField()
    last_price = models.IntegerField()
    purchase_price = models.IntegerField()
    etc_price = models.IntegerField()
    smart_sotre_rate = models.IntegerField()
    e_commerce_rate = models.IntegerField()
    credit_card_rate = models.IntegerField()
    settlement_amount = models.IntegerField()
    
    def __str__(self):
        return self.item_name
    
    class Meta:
        db_table = 'Merchandises'

