from rest_framework import serializers
from .models import User, Merchandise

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id',
            'kakao_id',
            'nickname'
            )

class MerchandiseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchandise
        fields = (
            'User_id',
            'item_name',
            'country_from',
            'item_currency',
            'shipping_currency',
            'etc_currency',
            'shipping_fee_from',
            'shipping_fee_to',
            'cost',
            'price',
            'last_price',
            'purchase_price',
            'etc_price',
            'smart_sotre_rate',
            'e_commerce_rate',
            'credit_card_rate',
            'settlement_amount'
            )