# Generated by Django 2.0.7 on 2018-09-07 14:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_sendfile'),
    ]

    operations = [
        migrations.AddField(
            model_name='sendfile',
            name='file_name',
            field=models.CharField(default='', max_length=250),
            preserve_default=False,
        ),
    ]
