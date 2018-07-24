# -*- coding: utf-8 -*-

from util import elastalert_logger
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.exceptions import RetryError
import json

class BaseResolver(object):
    """ Base class for types of alerts.

    :param rule: The rule configuration.
    """
    required_options = frozenset([])

    def __init__(self, rule):
        self.rule = rule

    def resolve(self):
        """ Send an alert. Match is a dictionary of information about the alert.

        :param match: A dictionary of relevant information to the alert.
        """
        raise NotImplementedError()


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class HTTPResolver(BaseResolver):
    """ HTTP Resolver.

    :param rule: The rule configuration.
    """
    required_options = frozenset(['resolve_http_post_url', 'resolve_http_post_static_payload'])

    def __init__(self, rule):
        super(HTTPResolver, self).__init__(rule)

        post_url = self.rule.get('resolve_http_post_url')
        if isinstance(post_url, basestring):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('resolve_http_post_proxy')
        self.post_static_payload = self.rule.get('resolve_http_post_static_payload', {})
        self.post_http_headers = self.rule.get('resolve_http_post_headers', {})
        self.timeout = self.rule.get('resolve_http_post_timeout', 10)

    def _requests_retry_session(
        retries=5,
        backoff_factor=3,
        status_forcelist=(500, 502, 504),
        session=None,
        method_whitelist=frozenset(['GET', 'POST'])
    ):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            method_whitelist=method_whitelist
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session
        

    def resolve(self):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        }
        headers.update(self.post_http_headers)
        proxies = {'https': self.post_proxy} if self.post_proxy else None
        
        for url in self.post_url:
            try:
                _requests_retry_session().post(url, data=json.dumps(self.post_static_payload, cls=DateTimeEncoder),
                                         headers=headers, proxies=proxies, timeout=self.timeout)
            except RetryError as e:
                raise EAException("Error posting HTTP Post alert: %s" % e)

        elastalert_logger.info("HTTP Post alert sent.")
