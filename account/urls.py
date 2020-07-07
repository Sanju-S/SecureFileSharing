from django.conf.urls import url
from . import views

app_name = 'account'

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^register/$', views.register, name='register'),
    url(r'^login_user/$', views.login_user, name='login_user'),
    url(r'^logout_user/$', views.logout_user, name='logout_user'),
    url(r'^create_folder/$', views.create_folder, name='create_folder'),
    url(r'^(?P<folder_id>[0-9]+)/delete_folder/$', views.delete_folder, name='delete_folder'),
    url(r'^(?P<folder_id>[0-9]+)/detail/$', views.detail, name='detail'),
    url(r'^(?P<folder_id>[0-9]+)/create_file/$', views.create_file, name='create_file'),
    url(r'^(?P<folder_id>[0-9]+)/delete_file/(?P<file_id>[0-9]+)/$', views.delete_file, name='delete_file'),
    url(r'^(?P<file_id>[0-9]+)/download/$', views.download_file, name='download_file'),
    url(r'^(?P<folder_id>[0-9]+)/(?P<file_id>[0-9]+)/mail/me/$', views.mail_me, name='mail_to_me'),
    url(r'^(?P<folder_id>[0-9]+)/(?P<file_id>[0-9]+)/mail/other/$', views.mail_other, name='mail_other'),
    url(r'^get/(?P<file_id>[0-9]+)/(?P<hash_key>[a-z0-9]+)/$', views.down, name='down'),
    url(r'^add_colleague/$', views.add_colleague, name='add_colleague'),
    url(r'^show_colleague/$', views.show_colleague, name='show_colleague'),
    url(r'^(?P<name>[a-zA-Z]+)/add_colleague/$', views.add_coll, name='add_coll'),
    url(r'^(?P<iden>[0-9]+)/delete_colleague/$', views.delete_coll, name='delete_coll'),
    url(r'^(?P<file_id>[0-9]+)/send_colleague/$', views.send_colleague, name='send_colleague'),
    url(r'^rec_file/$', views.rec_file, name='rec_file'),
    url(r'^(?P<file_id>[0-9]+)/ignore/$', views.ignore, name='ignore'),
    url(r'^(?P<file_id>[0-9]+)/(?P<rec_id>[0-9]+)/down_rec/$', views.down_rec, name='down_rec'),
    url(r'^sent_file/$', views.sent_file, name='sent_file'),
    url(r'^(?P<coll_name>[a-zA-Z]+)/block_colleague/$', views.block_coll, name='block_coll'),
    url(r'^(?P<username>[a-zA-Z]+)/unblock_user/$', views.unblock_user, name='unblock_user'),
]

