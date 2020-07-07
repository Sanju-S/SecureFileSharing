from django.db import models
from django.contrib.auth.models import User
from .validators import validate_file_size


class Folder(models.Model):
    user = models.ForeignKey(User, default=1, on_delete=models.CASCADE)
    folder_title = models.CharField(max_length=250)
    folder_type = models.CharField(max_length=50)

    def __str__(self):
        return self.folder_title


class File(models.Model):
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
    owner = models.ForeignKey(User, default=1, on_delete=models.CASCADE)
    file_title = models.CharField(max_length=250)
    file_upload = models.FileField(default='', verbose_name='', validators=[validate_file_size])
    file_key = models.CharField(max_length=250, default='')
    file_size = models.CharField(max_length=15)
    file_ext = models.CharField(max_length=15)

    def __str__(self):
        return self.file_title


class Colleague(models.Model):
    user = models.CharField(max_length=250)
    coll = models.CharField(max_length=250)


class SendFile(models.Model):
    sender = models.CharField(max_length=250)
    receiver = models.CharField(max_length=250)
    status = models.IntegerField(default=0)
    file_id = models.IntegerField(default=0)
    file_name = models.CharField(max_length=250)

    def __str__(self):
        return self.sender + ' - ' + self.receiver


class MailPassword(models.Model):
    passwd = models.CharField(max_length=50)


class BlockColleague(models.Model):
    user1 = models.CharField(max_length=250)
    user2 = models.CharField(max_length=250)

    def __str__(self):
        return self.user1 + ' - ' + self.user2




