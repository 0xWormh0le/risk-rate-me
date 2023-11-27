import json
import logging
import requests
import validators

import deepcheck.exceptions

DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1

# User-agent string to use for external requests
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"

# Headers to send for external requests
REQUEST_HEADERS = {
    "Accept-Charset": "utf-8",
    "User-Agent": UA_FIREFOX,
    "Cache-Control": "no-cache",
    "Pragma": "no-cache"
}

logger = logging.getLogger(__name__)


def query_ip_blocklist_from_neutrino(_ip, _userid, _key, _timeout=DEFAULT_TIMEOUT, _retries=DEFAULT_RETRIES):
    """
    Queries the Neutrino API for the given IP to assess if it is blacklisted or otherwise
    known to be related to malicious activities.

    Example of a response:

    {
        'is-hijacked':False,
        'is-spider':False,
        'is-tor':False,
        'is-dshield':False,
        'is-vpn':False,
        'ip':'8.8.8.8',
        'is-spyware':False,
        'is-spam-bot':False,
        'blocklists':[

        ],
        'last-seen':0,
        'is-bot':False,
        'list-count':0,
        'is-proxy':False,
        'is-malware':False,
        'is-listed':False,
        'is-exploit-bot':False
    }
    :param _ip: The IP address to verify.
    :param _userid: The user ID required to use the API
    :param _key: The API key to query the Neutrino API
    :param _timeout: Timeout, in seconds, to stop connection attempts
    :param _retries: Number of connection attemps before giving up
    :return:
    """
    assert validators.ipv4(_ip) or validators.ipv6(_ip)
    assert _userid is not None
    assert _key is not None

    # Endpoint to call
    url = 'https://neutrinoapi.com/ip-blocklist'
    # Parames needed to query the endpoint
    params = {
        'user-id': _userid,
        'api-key': _key,
        'ip': _ip.strip()
    }
    headers = REQUEST_HEADERS
    headers['Content-Type'] = "application/json"

    response = requests.post(url, headers=headers, data=json.dumps(params), timeout=_timeout)
    # Ensure we have received a response
    if response is not None and response.status_code == requests.codes.ok:
        # Capture the response in JSON format
        data = response.json()
        return data
    else:
        # An error occured. Most likely this will be cause by reaching limits on calls.
        data = response.text
        logger.debug(str(data))
        if "api-error" in data or response.status_code >= 400:
            raise deepcheck.exceptions.ThirdPartyApiException(
                _url=url,
                _message=response.text
            )
        else:
            raise deepcheck.exceptions.InvalidResponseException(
                _url=url,
                _code=response.status_code
            )


def query_host_reputation_from_neutrino(_host, _userid, _key, _timeout=DEFAULT_TIMEOUT, _retries=DEFAULT_RETRIES):
    """

    {
        'lists':[
            {
                'list-host':'uribl.zeustracker.abuse.ch',
                'list-rating':3,
                'response-time':1267,
                'is-listed':False,
                'list-name':'abuse.ch ZeuS Tracker Domain',
                'txt-record':''
            },
            ...
        ],
        'list-count':0,
        'host':'google.com',
        'is-listed':False
    }

    :param _host:
    :param _userid:
    :param _key:
    :param _timeout:
    :param _retries:
    :return:
    """
    assert validators.domain(_host) or validators.ipv4(_host) or validators.ipv6(_host)
    assert _userid is not None
    assert _key is not None

    url = 'https://neutrinoapi.com/host-reputation'
    params = {
        'user-id': _userid,
        'api-key': _key,
        'host': _host.strip()
    }
    headers = REQUEST_HEADERS
    headers['Content-Type'] = "application/json"

    response = requests.post(url, headers=headers, data=json.dumps(params), timeout=_timeout)
    if response is not None and response.status_code == requests.codes.ok:
        logger.debug(str(response.json()))
        data = response.json()
        return data
    elif response.status_code >= 400 or "api-error" in response.text:
        logger.error(response.text)
        raise deepcheck.exceptions.ThirdPartyApiException(
            _url=url,
            _message=response.text
        )
    else:
        logger.error(response.text)
        raise deepcheck.exceptions.InvalidResponseException(
            _url=url,
            _code="failed to connect"
        )

    """
def query_emails_leak_from_be(_domain, _key, _timeout=DEFAULT_TIMEOUT, _retries=DEFAULT_RETRIES):
    """
    """
    Queries the BinaryEdge API to retrieve information about potential email
    leaks relating to the domain.

    Note that this function requires an API key to a paid-subscription to BinaryEdge.

    Query example:
    curl 'https://api.binaryedge.io/v2/query/dataleaks/organization/example.com' -H 'X-Key:API_KEY'

    Response Example:
    {
       "total":192656,
       "groups":[
            {"leak":"antipublic", "count":44489},
            {"leak":"exploitin", "count":19995},
            {"leak":"badoo", "count":13028},
            {"leak":"myspace", "count":26266},
            {"leak":"vk", "count":2132},
            {"leak":"imesh", "count":7549},
      ...
    }

    For example, searching for the domain 'example.com' returns
    {"leak":"linkedin", "count":805}, this means there are 805 accounts with an
    example.com email on the Linkedin dump.

    Reference:
    https://docs.binaryedge.io/api-v2/#v2querydataleaksorganizationdomain

    :param _domain: The domain to look for
    :param _key: API key to query the BinaryEdge API
    :param _timeout: Network timeout before giving up
    :param _retries: Connection attempts before giving up
    :return:
    """
    """
    assert validators.domain(_domain)
    assert _key is not None

    url = 'https://api.binaryedge.io/v2/query/dataleaks/organization/{domain:s}'.format(domain=_domain)
    headers = {'X-Key': _key}

    response = requests.get(url, headers=headers, timeout=_timeout)
    if response is not None and response.status_code == requests.codes.ok:
        data = response.json()
        logger.debug(str(data))
        return data
    elif response.status_code == 400 and "error" in response.text:
        logger.error(response.text)
        raise deepcheck.exceptions.ThirdPartyApiException(
            _url=url,
            _message=response.text
        )
    else:
        logger.error(response.text)
        raise deepcheck.exceptions.InvalidResponseException(
            _url=url,
            _code="failed to connect"
        )
    """
