from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, kakao_id, nickname, password=None):
        """
        주어진 이메일, 닉네임, 비밀번호 등 개인정보로 User 인스턴스 생성
        """
        user = self.model(kakao_id=kakao_id, nickname=nickname)
        user.set_unusable_password()
        user.save(using=self._db)
        return user
    
    def create_superuser(self, kakao_id, password):
        """
        주어진 이메일, 닉네임, 비밀번호 등 개인정보로 User 인스턴스 생성
        단, 최상위 사용자이므로 권한을 부여한다. 
        """
        user = self.model(kakao_id=kakao_id, password=password)
        user.is_superuser = True
        return user

class User(AbstractBaseUser, PermissionsMixin):
    User_pk = models.AutoField(primary_key=True)
    kakao_id = models.IntegerField(unique=True)
    nickname = models.CharField(max_length=40, null=True, blank=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'kakao_id'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return str(self.kakao_id)
    
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

