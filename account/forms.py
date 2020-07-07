from django import forms
from django.contrib.auth.models import User
from .models import Folder, File


class FolderForm(forms.ModelForm):

    class Meta:
        model = Folder
        fields = ['folder_title', 'folder_type']


class FileForm(forms.ModelForm):

    class Meta:
        model = File
        fields = ['file_title', 'file_upload']


class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

