# Generated by Django 3.1 on 2020-11-12 16:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scrap_backend', '0002_scrap_is_open'),
    ]

    operations = [
        migrations.AddField(
            model_name='scrap',
            name='lot_id',
            field=models.CharField(default='p00000', max_length=32),
        ),
    ]