# Generated by Django 3.1.7 on 2021-03-31 12:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('smart_store_solution', '0002_auto_20210331_1243'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userwithkakao',
            name='user',
        ),
    ]
