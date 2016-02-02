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
import re
from inspect import ismodule
import logging

def module_to_dict(module):
    return { k : v for k, v in module.__dict__.iteritems() if k[0] != '_' and not ismodule(v)} 

def extract_request_dict(request, dict_name):
    d = {}
    for k, v in request.arguments.iteritems():
        m = re.match('{}\[([^\]]*)\]'.format(dict_name), k)
        if m:
          d[m.group(1)] = v[0]
    return d


def checkdictionary(checkdict, refdict):
    #if lists have to be checked within dictionary, 
    #refdict must contain only 1 ref element in the list

    if isinstance(checkdict, dict):
        if isinstance(refdict, dict):
            return (sorted(checkdict.keys()) == sorted(refdict.keys()) and
                    all(checkdictionary(checkdict[k], refdict[k]) for k in checkdict.keys()))
        else:
            return False
    elif isinstance(checkdict, list):
        if isinstance(refdict, list):
            return all(checkdictionary(d, refdict[0]) for d in checkdict)
        else:
            return False
    else:
        return re.match(refdict, checkdict)