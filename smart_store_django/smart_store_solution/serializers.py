from rest_framework import serializers
from .models import User, Merchandise

# User classes
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'User_pk',
            'kakao_id',
            'nickname'
            )

# Merchandise classes
class MerchandiseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchandise
        fields = (
            'id',
            'User_pk',
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

class MerchandiseDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchandise
        fields = (
            'id',
            'User_pk',
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

class MerchandiseCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchandise
        fields = (
            'id',
            'User_pk',
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