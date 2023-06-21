# File: opswatfilescan_consts.py
#
# Copyright (c) OPSWAT, 2023
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#

# Endpoints
OPSWAT_FILESCAN_ENDPOINT_USERINFO = '/api/users/me'
OPSWAT_FILESCAN_ENDPOINT_SCAN_FILE = '/api/scan/file'
OPSWAT_FILESCAN_ENDPOINT_SCAN_URL = '/api/scan/url'
OPSWAT_FILESCAN_ENDPOINT_SCAN_POLL = '/api/scan/{id}/report?{filters}'
OPSWAT_FILESCAN_ENDPOINT_SERACH = '/api/reports/search'
OPSWAT_FILESCAN_ENDPOINT_REPUTATION = '/api/reputation'

OPSWAT_FILESCAN_POLL_INTERVAL_MIN = 1
OPSWAT_FILESCAN_TIMEOUT_MIN = 30
OPSWAT_FILESCAN_POLL_INTERVAL_MAX = 30
OPSWAT_FILESCAN_TIMEOUT_MAX = 300
