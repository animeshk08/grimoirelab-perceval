# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2019 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Valerio Cosentino <valcos@bitergia.com>
#

import json
import logging
import datetime
import requests
from grimoirelab_toolkit.datetime import (datetime_to_utc,
                                          datetime_utcnow,
                                          str_to_datetime)
from grimoirelab_toolkit.uris import urijoin

from ...backend import (Backend,
                        BackendCommand,
                        BackendCommandArgumentParser,
                        DEFAULT_SEARCH_FIELD)
from ...client import HttpClient, RateLimitHandler
from ...utils import DEFAULT_DATETIME, DEFAULT_LAST_DATETIME
from datetime import datetime

CATEGORY_ISSUE = "issue"

PAGURE_URL = "https://pagure.io/"
PAGURE_API_URL = "https://pagure.io/api/0"

# Range before sleeping until rate limit reset
MIN_RATE_LIMIT = 10
MAX_RATE_LIMIT = 500

MAX_CATEGORY_ITEMS_PER_PAGE = 100
PER_PAGE = 100

# Default sleep time and retries to deal with connection/server problems
DEFAULT_SLEEP_TIME = 1
MAX_RETRIES = 5

TARGET_ISSUE_FIELDS = ['user', 'assignee']

logger = logging.getLogger(__name__)


class Pagure(Backend):
    """Pagure backend for Perceval.

    This class allows the fetch the issues stored in Pagure
    repository. Note that api token is needed to perform
    certain API calls

    :param namespace: Pagure namespace
    :param repository: Pagure repository; in case the repository is within a namespace
    :param api_token: Pagure API token to access the API
    :param base_url: when no value is set the backend will be fetch
     the data from the Pagure public site.
    :param tag: label used to mark the data
    :param archive: archive to store/retrieve items
    :param sleep_for_rate: sleep until rate limit is reset
    :param min_rate_to_sleep: minimum rate needed to sleep until
         it will be reset
    :param max_retries: number of max retries to a data source
        before raising a RetryError exception
    :param max_items: max number of category items (e.g., issues,
        pull requests) per query
    :param sleep_time: time to sleep in case
        of connection problems
    """
    version = '0.29'

    CATEGORIES = [CATEGORY_ISSUE]
    CLASSIFIED_FIELDS = [
        ['user_data'],
        ['assignee_data']
    ]

    def __init__(self, namespace=None, repository=None,
                 api_token=None, base_url=None,
                 tag=None, archive=None,
                 sleep_for_rate=False, min_rate_to_sleep=MIN_RATE_LIMIT,
                 max_retries=MAX_RETRIES, sleep_time=DEFAULT_SLEEP_TIME,
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE):
        if api_token is None:
            api_token = []
        origin = base_url if base_url else PAGURE_URL
        origin = urijoin(origin, namespace, repository)

        super().__init__(origin, tag=tag, archive=archive)

        self.namespace = namespace
        self.repository = repository
        self.api_token = api_token
        self.base_url = base_url

        self.sleep_for_rate = sleep_for_rate
        self.min_rate_to_sleep = min_rate_to_sleep
        self.max_retries = max_retries
        self.sleep_time = sleep_time
        self.max_items = max_items

        self.client = None
        self.exclude_user_data = False
        self._users = {}  # internal users cache

    def search_fields(self, item):
        """Add search fields to an item.

        It adds the values of `metadata_id` plus the `namespace` and `repo`.

        :param item: the item to extract the search fields values

        :returns: a dict of search fields
        """
        search_fields = {
            DEFAULT_SEARCH_FIELD: self.metadata_id(item),
            'namespace': self.namespace,
            'repo': self.repository
        }

        return search_fields

    def fetch(self, category=CATEGORY_ISSUE, from_date=DEFAULT_DATETIME, to_date=DEFAULT_LAST_DATETIME,
              filter_classified=False):
        """Fetch the issues from the repository.

        The method retrieves, from a Pagure repository, the issues
        updated since the given date.

        :param category: the category of items to fetch
        :param from_date: obtain issues updated since this date
        :param to_date: obtain issues until a until a specific date (included)
        :param filter_classified: remove classified fields from the resulting items

        :returns: a generator of issues
        """
        self.exclude_user_data = filter_classified

        if self.exclude_user_data:
            logger.info("Excluding user data. Personal user information won't be collected from the API.")

        if not from_date:
            from_date = DEFAULT_DATETIME

        if not to_date:
            to_date = DEFAULT_LAST_DATETIME

        from_date = from_date.strftime('%Y-%m-%d')
        to_date = to_date.strftime('%Y-%m-%d')
        kwargs = {
            'from_date': from_date,
            'to_date': to_date
        }
        items = super().fetch(category,
                              filter_classified=filter_classified,
                              **kwargs)

        return items

    def fetch_items(self, category, **kwargs):
        """Fetch the items (issues)

        :param category: the category of items to fetch
        :param kwargs: backend arguments

        :returns: a generator of items
        """
        from_date = kwargs['from_date']
        to_date = kwargs['to_date']
        items = self.__fetch_issues(from_date, to_date)
        return items

    @classmethod
    def has_archiving(cls):
        """Returns whether it supports archiving items on the fetch process.

        :returns: this backend supports items archive
        """
        return True

    @classmethod
    def has_resuming(cls):
        """Returns whether it supports to resume the fetch process.

        :returns: this backend supports items resuming
        """
        return True

    @staticmethod
    def metadata_id(item):
        """Extracts the identifier from a Pagure item."""

        return str(item['id'])

    @staticmethod
    def metadata_updated_on(item):
        """Extracts the update time from a Pagure item.

        The timestamp used is extracted from 'last_updated' field.
        This date is converted to UNIX timestamp format. As Pagure
        dates are in timestamp format the conversion is straightforward.

        :param item: item generated by the backend

        :returns: a UNIX timestamp
        """
        if "forks_count" in item:
            return item['fetched_on']
        else:
            ts = int(item['last_updated'])
            ts = datetime.fromtimestamp(ts).timestamp()

            return ts

    @staticmethod
    def metadata_category(item):
        """Extracts the category from a Pagure item.

        This backend generates one type of item which is
        'issue'.
        """

        category = CATEGORY_ISSUE

        return category

    def _init_client(self, from_archive=False):
        """Init client"""

        return PagureClient(self.namespace, self.repository, self.api_token, self.base_url,
                            self.sleep_for_rate, self.min_rate_to_sleep,
                            self.sleep_time, self.max_retries, self.max_items,
                            self.archive, from_archive)

    def __fetch_issues(self, from_date, to_date):
        """Fetch the issues
        :param from_date: starting date from which issues are fetched
        :param to_date: ending date till which issues are fetched

        :returns: an issue object
        """

        issues_groups = self.client.issues(from_date=from_date)

        for raw_issues in issues_groups:
            issues = json.loads(raw_issues)
            issues = issues['issues']
            for issue in issues:

                if int(issue['last_updated']) > str_to_datetime(to_date).timestamp():
                    return

                self.__init_extra_issue_fields(issue)
                for field in TARGET_ISSUE_FIELDS:

                    if not issue[field]:
                        continue

                    if field == 'user':
                        issue[field + '_data'] = self.__get_user(issue[field]['name'])
                    elif field == 'assignee':
                        issue[field + '_data'] = self.__get_issue_assignee(issue[field])

                yield issue

    def __get_issue_assignee(self, raw_assignee):
        """Get issue assignee"""
        if not raw_assignee:
            return None
        assignee = self.__get_user(raw_assignee['name'])

        return assignee

    def __get_user(self, login):
        """Get user data for the login"""

        if not login or self.exclude_user_data:
            return None

        user_raw = self.client.user(login)
        user = json.loads(user_raw)

        return user

    def __init_extra_issue_fields(self, issue):
        """Add fields to an issue"""

        issue['user_data'] = {}
        issue['assignee_data'] = {}


class PagureClient(HttpClient, RateLimitHandler):
    """Client for retieving information from Pagure API

    :param namespace: Pagure namespace
    :param repository: Pagure repository; incase the repository is within a namespace
    :param tokens: Pagure API token to access the API
    :param base_url: When no value is set the backend will be fetch the data
        from the Pagure public site.
    :param sleep_for_rate: sleep until rate limit is reset
    :param min_rate_to_sleep: minimun rate needed to sleep until
         it will be reset
    :param sleep_time: time to sleep in case
        of connection problems
    :param max_retries: number of max retries to a data source
        before raising a RetryError exception
    :param max_items: max number of category items (e.g., issues,
        pull requests) per query
    :param archive: collect issues already retrieved from an archive
    :param from_archive: it tells whether to write/read the archive
    """
    EXTRA_STATUS_FORCELIST = [403, 500, 502, 503]

    _users = {}  # users cache

    def __init__(self, namespace, repository, tokens,
                 base_url=None, sleep_for_rate=False, min_rate_to_sleep=MIN_RATE_LIMIT,
                 sleep_time=DEFAULT_SLEEP_TIME, max_retries=MAX_RETRIES,
                 max_items=MAX_CATEGORY_ITEMS_PER_PAGE, archive=None, from_archive=False):
        self.namespace = namespace
        self.repository = repository
        self.tokens = tokens
        self.n_tokens = len(self.tokens)
        self.current_token = None
        self.last_rate_limit_checked = None
        self.max_items = max_items

        base_url = PAGURE_API_URL

        super().__init__(base_url, sleep_time=sleep_time, max_retries=max_retries,
                         extra_headers=self._set_extra_headers(),
                         extra_status_forcelist=self.EXTRA_STATUS_FORCELIST,
                         archive=archive, from_archive=from_archive)
        super().setup_rate_limit_handler(sleep_for_rate=sleep_for_rate, min_rate_to_sleep=min_rate_to_sleep)

    def calculate_time_to_reset(self):
        """Calculate the seconds to reset the token requests, by obtaining the different
        between the current date and the next date when the token is fully regenerated.
        """

        time_to_reset = self.rate_limit_reset_ts - (datetime_utcnow().replace(microsecond=0).timestamp() + 1)
        time_to_reset = 0 if time_to_reset < 0 else time_to_reset

        return time_to_reset

    def issues(self, from_date=None):
        """Fetch the issues from the repository.

        The method retrieves, from a Pagure repository, the issues
        updated since the given date.

        :param from_date: obtain issues updated since this date

        :returns: a generator of issues
        """
        payload = {
            'status': 'all',
            'per_page': self.max_items,
            'order': 'asc',
        }

        if from_date:
            payload['since'] = from_date

        path = urijoin("issues")
        return self.fetch_items(path, payload)

    def user(self, name):
        """Get the user information and update the user cache

        :param name: username of the user

        :returns: a user object
        """
        user = None

        if name in self._users:
            return self._users[name]

        url_user = urijoin(self.base_url, 'user', name)

        logger.debug("Getting info for %s" % url_user)

        r = self.fetch(url_user)
        user = r.text
        self._users[name] = user

        return user

    def fetch(self, url, payload=None, headers=None, method=HttpClient.GET, stream=False, auth=True):
        """Fetch the data from a given URL.

        :param url: link to the resource
        :param payload: payload of the request
        :param headers: headers of the request
        :param method: type of request call (GET or POST)
        :param stream: defer downloading the response body until the response content is available
        :param auth: auth of the request

        :returns a response object
        """
        if not self.from_archive:
            self.sleep_for_rate_limit()

        # In case the issue tracker is disabled for a repository
        # an HTTP 404 response is returned
        try:
            response = super().fetch(url, payload, headers, method, stream, auth)
        except requests.exceptions.HTTPError:
            print("The issue tracker is disabled please enable the feature for the repository")
            exit(1)
            return

        if not self.from_archive:
            self.update_rate_limit(response)

        return response

    def fetch_items(self, path, payload):
        """Return the items from Pagure API using links pagination

        :param path: Path from which the item is to be fetched
        :param payload: Payload to be added to the request

        :returns: an item object
        """

        page = 0  # current page
        last_page = None  # last page
        if self.namespace:  # if project is under a namspace
            url_next = urijoin(self.base_url, self.namespace, self.repository, path)
        else:  # if project is created without a namespace
            url_next = urijoin(self.base_url, self.repository, path)
        logger.debug("Get Pagure paginated items from " + url_next)

        response = self.fetch(url_next, payload=payload)

        items = response.text
        page += 1

        if 'last' in response.links:
            last_url = response.links['last']['url']
            last_page = last_url.split('&page=')[1].split('&')[0]
            last_page = int(last_page)
            logger.debug("Page: %i/%i" % (page, last_page))

        while items:
            yield items

            items = None

            if 'next' in response.links:
                url_next = response.links['next']['url']
                response = self.fetch(url_next, payload=payload)
                page += 1

                items = response.text
                logger.debug("Page: %i/%i" % (page, last_page))

    def _set_extra_headers(self):
        """Set extra headers for session"""

        headers = {}
        if self.current_token:
            headers = {'Authorization': "token %s" % self.tokens}

        return headers


class PagureCommand(BackendCommand):
    """Class to run Pagure backend from the command line."""

    BACKEND = Pagure

    @classmethod
    def setup_cmd_parser(cls):
        """Returns the Pagure argument parser."""

        parser = BackendCommandArgumentParser(cls.BACKEND,
                                              from_date=True,
                                              to_date=True,
                                              token_auth=False,
                                              archive=True)

        # Pagure authorisation token
        group = parser.parser.add_argument_group('Pagure arguments')
        group.add_argument('--api-token', dest='api-token',
                           type=str,
                           help="Set when using API token")

        # Generic client options
        group.add_argument('--max-items', dest='max_items',
                           default=MAX_CATEGORY_ITEMS_PER_PAGE, type=int,
                           help="Max number of category items per query.")
        group.add_argument('--max-retries', dest='max_retries',
                           default=MAX_RETRIES, type=int,
                           help="number of API call retries")
        group.add_argument('--sleep-time', dest='sleep_time',
                           default=DEFAULT_SLEEP_TIME, type=int,
                           help="sleeping time between API call retries")

        # Positional arguments

        # A project be created directly or within a namespace
        # hence API call supports the access based on usecase. e.g.
        # GET /api/0/<repo>/issues
        # GET /api/0/<namespace>/<repo>/issues

        parser.parser.add_argument('namespace', nargs='?',
                                   help="Pagure namespace")
        parser.parser.add_argument('repository',
                                   help="Pagure repository; in case the repository is within a namespace")

        return parser