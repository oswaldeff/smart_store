from django.db import models

# Create your models here.

class User(models.Model):
    id = models.AutoField(primary_key=True)
    kakao_id = models.IntegerField()
    nickname = models.CharField(max_length=40, null=True)
    
    def __str__(self):
        return self.nickname
    
    class Meta:
        db_table = 'Users'

class Merchandise(models.Model):
    id = models.AutoField(primary_key=True)
    User_id = models.ForeignKey(User, on_delete=models.CASCADE, db_column='User_id')
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

