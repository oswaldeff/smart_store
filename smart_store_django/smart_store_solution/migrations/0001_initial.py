# Generated by Django 3.2 on 2021-04-21 15:52

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(blank=True, max_length=255, null=True)),
                ('username', models.CharField(blank=True, max_length=255, null=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('User_pk', models.AutoField(primary_key=True, serialize=False)),
                ('kakao_id', models.IntegerField(unique=True)),
                ('nickname', models.CharField(blank=True, max_length=40, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'db_table': 'Users',
            },
        ),
        migrations.CreateModel(
            name='Merchandise',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('item_name', models.CharField(max_length=255, null=True)),
                ('country_from', models.CharField(max_length=255, null=True)),
                ('item_currency', models.CharField(max_length=255, null=True)),
                ('shipping_currency', models.CharField(max_length=255, null=True)),
                ('etc_currency', models.CharField(max_length=255, null=True)),
                ('shipping_fee_from', models.IntegerField()),
                ('shipping_fee_to', models.IntegerField()),
                ('cost', models.IntegerField()),
                ('price', models.IntegerField()),
                ('last_price', models.IntegerField()),
                ('purchase_price', models.IntegerField()),
                ('etc_price', models.IntegerField()),
                ('smart_sotre_rate', models.IntegerField()),
                ('e_commerce_rate', models.IntegerField()),
                ('credit_card_rate', models.IntegerField()),
                ('settlement_amount', models.IntegerField()),
                ('User_pk', models.ForeignKey(db_column='User_pk', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'Merchandises',
            },
        ),
    ]
