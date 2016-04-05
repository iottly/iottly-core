# 
# Copyright 2015 Stefano Terna
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

FROM ubuntu:latest
MAINTAINER iottly

EXPOSE 8520

RUN apt-get update -y

RUN apt-get install -y tar git curl nano wget dialog net-tools build-essential
RUN apt-get install -y python python-dev python-distribute python-pip

RUN mkdir /iottly-core

#RUN mkdir /var/iottly-core/
#RUN mkdir /var/iottly-core/uploads/
#RUN mkdir /var/iottly-core/uploads/fw/

ADD requirements.txt /iottly-core/requirements.txt
RUN pip install -r /iottly-core/requirements.txt

ADD run_script.sh /iottly-core/run_script.sh
ADD /iottly_core /iottly-core/iottly_core

ENV TERM xterm

WORKDIR /iottly-core
CMD ["./run_script.sh", "iottly_core/main.py"] 