from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from django.conf import settings
from django.http import HttpResponse
from django.utils.encoding import smart_str
from django.contrib.auth.models import User
from wsgiref.util import FileWrapper
from .forms import FolderForm, FileForm, UserForm
from .models import Folder, File, Colleague, SendFile, MailPassword, BlockColleague
from . import AES
from . import crypt
from . import mail
import hashlib
import datetime
import mimetypes
import os
import re
import math


def home(request):
    if not request.user.is_authenticated:
        return render(request, 'account/index.html')
    else:
        folders = Folder.objects.filter(user=request.user)
        files_results = File.objects.filter(owner=request.user)
        query = request.GET.get('q')
        if query:
            folders = folders.filter(
                Q(folder_title__icontains=query)
            ).distinct()
            files_results = files_results.filter(
                Q(file_title__icontains=query)
            ).distinct()
            return render(request, 'account/home.html', {
                'folders': folders,
                'files': files_results,
            })
        else:
            return render(request, 'account/home.html', {'folders': folders})


def register(request):
    form = UserForm(request.POST or None)
    if form.is_valid():
        user = form.save(commit=False)
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user.set_password(password)
        user.save()
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                folders = Folder.objects.filter(user=request.user)
                return render(request, 'account/home.html', {'folders': folders})
    context = {
        "form": form,
    }
    return render(request, 'account/register.html', context)


def login_user(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                folders = Folder.objects.filter(user=request.user)
                return render(request, 'account/home.html', {'folders': folders})
            else:
                return render(request, 'account/login.html', {'error_message': 'Your account has been disabled'})
        else:
            return render(request, 'account/login.html', {'error_message': 'Invalid login'})
    return render(request, 'account/login.html')


def logout_user(request):
    logout(request)
    form = UserForm(request.POST or None)
    context = {
        "form": form,
    }
    return render(request, 'account/index.html', context)


def create_folder(request):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    else:
        form = FolderForm(request.POST or None, request.FILES or None)
        if form.is_valid():
            folder = form.save(commit=False)
            folder.user = request.user
            folder.save()
            return render(request, 'account/detail.html', {'folder': folder})
        context = {
            'form': form
        }
        return render(request, 'account/create_folder.html', context)


def delete_folder(request, folder_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    files = File.objects.filter(folder=folder_id)
    for file in files:
        file_path = settings.MEDIA_ROOT + '/' + str(file.file_upload.url).split('/')[-1]
        os.remove(file_path)
    folder = Folder.objects.get(pk=folder_id)
    folder.delete()
    folders = Folder.objects.filter(user=request.user)
    return render(request, 'account/home.html', {'folders': folders})


def detail(request, folder_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    else:
        user = request.user
        folder = get_object_or_404(Folder, pk=folder_id)
        return render(request, 'account/detail.html', {'folder': folder, 'user': user})


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, 2)
    s = round(size_bytes / p, 2)
    return "%s %s" %(s, size_name[i])



def create_file(request, folder_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    form = FileForm(request.POST or None, request.FILES or None)
    folder = get_object_or_404(Folder, pk=folder_id)
    if form.is_valid():
        folder_files = folder.file_set.all()
        for f in folder_files:
            if f.file_title == form.cleaned_data.get("file_title"):
                context = {
                    'folder': folder,
                    'form': form,
                    'message': 'You have already added the file',
                }
                return render(request, 'account/create_file.html', context)
        file = form.save(commit=False)
        file.owner = request.user
        file.folder = folder
        passwd = str(datetime.datetime.now())
        key = hashlib.sha256(bytes(passwd, 'utf-8')).digest()
        file.file_upload = request.FILES['file_upload']
        file.file_key = crypt.encrypt(str(request.user.username)[::-1], passwd)
        file.save()
        file_id = File.objects.latest('pk')
        file_path = settings.MEDIA_ROOT + '/' + str(file_id.file_upload.url).split('/')[-1]
        file_rec = File.objects.get(pk=file_id.id)
        file_rec.file_size = convert_size(os.path.getsize(file_path))
        ext = str(file_path).split('.')[-1]
        file_rec.file_ext = ext
        file_rec.save()
        AES.encrypt_file(file_path, key)
        return render(request, 'account/detail.html', {'folder': folder})
    context = {
        'folder': folder,
        'form': form,
    }
    return render(request, 'account/create_file.html', context)


def delete_file(request, folder_id, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    folder = get_object_or_404(Folder, pk=folder_id)
    file = File.objects.get(pk=file_id)
    file.delete()
    file_path = settings.MEDIA_ROOT + '/' + str(file.file_upload.url).split('/')[-1]
    os.remove(file_path)
    return render(request, 'account/detail.html', {'folder': folder})


def download_file(request, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    file = get_object_or_404(File, pk=file_id)
    file_path = settings.MEDIA_ROOT + '/' + str(file.file_upload.url).split('/')[-1]
    with open(file_path, 'rb') as fo:
        file_text = fo.read()
    fo.close()
    passwd = crypt.decrypt(str(file.owner)[::-1], file.file_key)
    key = hashlib.sha256(bytes(passwd, 'utf-8')).digest()
    AES.decrypt_file(file_path, key)
    file_wrapper = FileWrapper(open(file_path, 'rb+'))
    file_mimetype = mimetypes.guess_type(file_path)
    response = HttpResponse(file_wrapper, content_type=file_mimetype)
    response['X-SendFile'] = file_path
    response['Content-Length'] = os.stat(file_path).st_size
    response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(str(file.file_upload.url).split('/')[-1])
    with open(file_path, 'wb') as fo:
        fo.write(file_text)
    fo.close()
    return response


def mail_me(request, folder_id, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    file = get_object_or_404(File, pk=file_id)
    user = request.user
    enc_key = file.file_key
    ho = hashlib.sha256(bytes(enc_key, 'utf-8'))
    key = ho.hexdigest()
    mail.send_mail(user, file_id, key)
    folder = get_object_or_404(Folder, pk=folder_id)
    return render(request, 'account/detail.html', {'folder':folder})


def mail_other(request, folder_id, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    if request.method == 'POST':
        if 'email' in request.POST:
            email = request.POST['email']
            match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
            if match is None:
                return render(request, 'account/mail_other.html', {'error_message': 'Provide appropriate E-Mail ID', 'folder_id': folder_id, 'file_id': file_id})
            else:
                file_id = file_id
                file = get_object_or_404(File, pk=file_id)
                enc_key = file.file_key
                ho = hashlib.sha256(bytes(enc_key, 'utf-8'))
                key = ho.hexdigest()
                pw = hashlib.sha1(bytes(request.POST['passwd'], 'utf-8'))
                pwd = MailPassword(passwd=pw.hexdigest())
                pwd.save()
                pwd_id = MailPassword.objects.latest('id')
                key = str(key) + str(pwd_id.id)
                mail.send_mail_other(request.user.username, email, file.file_title, file_id, key)
                folder = get_object_or_404(Folder, pk=folder_id)
                return render(request, 'account/detail.html', {'folder': folder})
    return render(request, 'account/mail_other.html', {'folder_id': folder_id, 'file_id': file_id})


def down(request, file_id, hash_key):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    file = get_object_or_404(File, pk=file_id)
    enc_key = file.file_key
    ho = hashlib.sha256(bytes(enc_key, 'utf-8'))
    file_key = ho.hexdigest()
    username = file.owner
    file_name = file.file_title
    if request.method == 'POST':
        if 'passwd' in request.POST:
            pw = hashlib.sha1(bytes(request.POST['passwd'], 'utf-8')).hexdigest()
            passwd = MailPassword.objects.get(id=int(hash_key[64:]))
            passwd = passwd.passwd
            if str(pw) == str(passwd):
                file_path = settings.MEDIA_ROOT + '/' + str(file.file_upload.url).split('/')[-1]
                with open(file_path, 'rb') as fo:
                    file_text = fo.read()
                fo.close()
                passwd = crypt.decrypt(str(username)[::-1], file.file_key)
                key = hashlib.sha256(bytes(passwd, 'utf-8')).digest()
                AES.decrypt_file(file_path, key)
                file_wrapper = FileWrapper(open(file_path, 'rb+'))
                file_mimetype = mimetypes.guess_type(file_path)
                response = HttpResponse(file_wrapper, content_type=file_mimetype)
                response['X-SendFile'] = file_path
                response['Content-Length'] = os.stat(file_path).st_size
                response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(
                    str(file.file_upload.url).split('/')[-1])
                with open(file_path, 'wb') as fo:
                    fo.write(file_text)
                fo.close()
                return response
            else:
                return render(request, 'account/down.html', {
                    'incorrect_pw': True,
                    'file_id': file_id,
                    'hash_key': hash_key,
                })
    if file_key == hash_key[:64]:
        return render(request, 'account/down.html', {
            'file_id': file_id,
            'hash_key': hash_key,
            'owner': username,
            'file_name': file_name,
        })
    else:
        return render(request, 'account/down.html', {
            'error_msg': 'The link is broken or has been tampered with, please request the sender to send the link once again.',
            'file_id': file_id,
            'hash_key': hash_key,
            'owner': username,
            'file_name': file_name,
        })


def add_colleague(request):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    if request.method == 'POST':
        name = request.POST['name']
        if name:
            usr = User.objects.filter(username=name)
            if usr:
                is_blocked = BlockColleague.objects.filter(user1=request.user.username, user2=name) | BlockColleague.objects.filter(user1=name, user2=request.user.username)
                if is_blocked:
                    return render(request, 'account/add_colleague.html', {'name': name, 'is_blocked': True})
                else:
                    return render(request, 'account/add_colleague.html', {'name': name})
            else:
                return render(request, 'account/add_colleague.html', {'no_user': True})
        else:
            return render(request, 'account/add_colleague.html', {'no_name': True})
    return render(request, 'account/add_colleague.html')


def add_coll(request, name):
    colleague = Colleague(user=request.user.username, coll=name)
    colleague.save()
    return render(request, 'account/add_colleague.html')


def show_colleague(request):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    coll = Colleague.objects.filter(user=request.user.username) | Colleague.objects.filter(coll=request.user.username)
    blocked = BlockColleague.objects.filter(user1=request.user.username)
    return render(request, 'account/show_colleague.html', {'colls': coll, 'blocked': blocked})


def delete_coll(request, iden):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    coll = Colleague.objects.filter(pk=iden)
    coll.delete()
    coll = Colleague.objects.filter(user=request.user.username)
    if coll:
        return render(request, 'account/show_colleague.html', {'colls': coll})
    else:
        return render(request, 'account/show_colleague.html', {'no_coll': True})


def block_coll(request, coll_name):
    block = BlockColleague(user1=request.user.username, user2=coll_name)
    block.save()
    file = SendFile.objects.filter(sender=request.user.username, receiver=coll_name) | SendFile.objects.filter(receiver=request.user.username, sender=coll_name)
    file.delete()
    coll = Colleague.objects.filter(user=request.user.username, coll=coll_name) | Colleague.objects.filter(user=coll_name, coll=request.user.username)
    coll.delete()
    col = SendFile.objects.filter(receiver=request.user.username)
    if col:
        col = col.all()[::-1]
        return render(request, 'account/rec_file.html', {'col': col})
    else:
        return render(request, 'account/rec_file.html', {'no_file': True})


def send_colleague(request, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    coll = Colleague.objects.filter(user=request.user.username)
    if request.method == 'POST':
      if 'coll' in request.POST:
        if request.POST['coll']:
            coll = request.POST.getlist('coll')
            f = File.objects.get(pk=file_id)
            file_name = f.file_title
            sf = SendFile()
            folder_id = f.folder_id
            for c in coll:
                sf.sender = request.user.username
                sf.receiver = c
                sf.status = 1
                sf.file_id = file_id
                sf.file_name = file_name
                sf.save()
            return render(request, 'account/home.html')
        else:
            return render(request, 'account/send_colleague.html', {'no_select': True})
    if coll:
        return render(request, 'account/send_colleague.html', {'colls': coll, 'file_id': file_id})
    else:
        return render(request, 'account/send_colleague.html', {'no_coll': True})


def rec_file(request):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    col = SendFile.objects.filter(receiver=request.user.username)
    if col:
        col = col.all()[::-1]
        return render(request, 'account/rec_file.html', {'col': col})
    else:
        return render(request, 'account/rec_file.html', {'no_file': True})


def ignore(request, file_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    f = SendFile.objects.get(pk=file_id)
    f.status = 3
    f.save()
    return render(request, 'account/rec_file.html')

def down_rec(request, file_id, rec_id):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    f = SendFile.objects.get(pk=rec_id)
    f.status = 0
    f.save()
    file = get_object_or_404(File, pk=file_id)
    file_path = settings.MEDIA_ROOT + '/' + str(file.file_upload.url).split('/')[-1]
    with open(file_path, 'rb') as fo:
        file_text = fo.read()
    fo.close()
    passwd = crypt.decrypt(str(file.owner)[::-1], file.file_key)
    key = hashlib.sha256(bytes(passwd, 'utf-8')).digest()
    AES.decrypt_file(file_path, key)
    file_wrapper = FileWrapper(open(file_path, 'rb+'))
    file_mimetype = mimetypes.guess_type(file_path)
    response = HttpResponse(file_wrapper, content_type=file_mimetype)
    response['X-SendFile'] = file_path
    response['Content-Length'] = os.stat(file_path).st_size
    response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(str(file.file_upload.url).split('/')[-1])
    with open(file_path, 'wb') as fo:
        fo.write(file_text)
    fo.close()
    return response


def sent_file(request):
    if not request.user.is_authenticated:
        return render(request, 'account/login.html')
    col = SendFile.objects.filter(sender=request.user.username)
    col = col.all()[::-1]
    if col:
        return render(request, 'account/sent_file.html', {'col': col})
    else:
        return render(request, 'account/sent_file.html', {'no_file': True})


def unblock_user(request, username):
    user = BlockColleague.objects.get(user1=request.user.username, user2=username)
    user.delete()
    return render(request, 'account/show_colleague.html')





