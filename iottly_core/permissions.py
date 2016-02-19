"""

Copyright 2015 Stefano Terna

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""
from functools import wraps
from tornado.web import HTTPError
from iottly_core.settings import settings

def admin_only(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        user = self.current_user
        if not user or not user in settings.ADMINS:
            raise HTTPError(403)
        return method(self, *args, **kwargs)
    return wrapper
