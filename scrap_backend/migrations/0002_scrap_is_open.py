# Generated by Django 3.1 on 2020-11-10 19:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scrap_backend', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scrap',
            name='is_open',
            field=models.BooleanField(default=True),
        ),
    ]