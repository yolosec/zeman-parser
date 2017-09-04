__author__ = 'yolosec'


class Error(Exception):
    """Generic EB client error."""


class InvalidResponse(Error):
    """Invalid server response"""


class InvalidStatus(Error):
    """Invalid server response"""


class RequestFailed(Error):
    """API request failed"""

