# Generated by Django 2.0.7 on 2018-09-20 13:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0008_mailpassword'),
    ]

    operations = [
        migrations.CreateModel(
            name='BlockColleague',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user1', models.CharField(max_length=250)),
                ('user2', models.CharField(max_length=250)),
            ],
        ),
    ]
