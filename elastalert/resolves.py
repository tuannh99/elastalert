# -*- coding: utf-8 -*-

from util import elastalert_logger

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


class MyResolver(BaseResolver):
    def resolve(self):
        elastalert_logger.info('Yay! Resolving!!!')
