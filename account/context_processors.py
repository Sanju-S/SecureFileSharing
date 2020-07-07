from .models import SendFile, BlockColleague


def categories_processor(request):
    collg = SendFile.objects.filter(receiver=request.user.username, status=1)
    return {'collg': collg}
