from django.contrib import admin
from .models import Folder, File, SendFile, BlockColleague

admin.site.register(Folder)
admin.site.register(File)
admin.site.register(SendFile)
admin.site.register(BlockColleague)
