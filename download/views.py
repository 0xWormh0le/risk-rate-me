import os
from django.views import View
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from mimetypes import guess_type


def serve_file(request, name):
    if not request.user.is_authenticated or not request.user.profile:
        return HttpResponse('Unauthorized', status=401)
    if request.user.profile.on_trial_or_free_account:
        return HttpResponse('Unauthorized', status=401)

    start = len('download/') + 1
    end = request.path.rfind('/')
    subpath = request.path[start:end]
    
    if not subpath in ['incident-response', 'policies', 'bite-sized']:
        return HttpResponse('No file', status=400)
    
    file_path = os.path.join('download', 'storage', subpath, name)
    
    try:
        with open(file_path, 'rb') as f:
            response = HttpResponse(f, content_type=guess_type(file_path)[0])
            response['Content-Length'] = len(response.content)
            return response
    except IOError:
        return HttpResponse('No file', status=400)
