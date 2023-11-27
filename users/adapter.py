import logging

from django.conf import settings
from django.forms import ValidationError

from allauth.account.adapter import DefaultAccountAdapter
from quickemailverification import Client

import urllib.request
import urllib.parse
import json


logger = logging.getLogger(__name__)


class RestrictEmailAdapter(DefaultAccountAdapter):

    def clean_email(self, email):
        """
        Validates an email value. You can hook into this if you want to
        (dynamically) restrict what email addresses can be chosen.


        if settings.DEBUG:
            return email
         """
        
        url = 'https://neutrinoapi.com/email-validate'
        params = {
            'user-id': settings.API_NEUTRINO_USER,
            'api-key': settings.API_NEUTRINO_KEY,
            'email': email
        }

        req = urllib.request.Request(url)
        data = urllib.parse.urlencode(params).encode('utf-8')

        with urllib.request.urlopen(req, data) as response:
            result = json.loads(response.read())
            if not result['valid'] or result['is-freemail'] or result['is-disposable']:
                raise ValidationError(
                    "We could not validate your email. Please use a private email domain."
                    " Free webmail providers are not accepted."
                )

        return email
