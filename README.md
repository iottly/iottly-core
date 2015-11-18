# License

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

# iottly-core
The *iottly-core* repository hosts the core iottly backend.
*iottly-core* runs on Python / [Tornado](https://github.com/tornadoweb/tornado).

It performs the following main functions:
- it receives incoming messages from devices, on `/msg` handler, via the [iottly-httpforward](https://github.com/iottly/iottly-httpforward) plugin installed in [iottly-xmpp-broker](https://github.com/iottly/iottly-xmpp-broker).
- it sends messages messages to devices, via the [SleekXMPP](https://github.com/fritzy/SleekXMPP) python library, which in turn is connected to the [iottly-xmpp-broker](https://github.com/iottly/iottly-xmpp-broker)
- it persists incoming messages to the Iottly database which runs on [Mongo](https://github.com/mongodb/mongo).
- it provides an admin console to the user, to remotely control the devices: [iottly-console](https://github.com/iottly/iottly-console)
- it pushes messages to the [iottly-console](https://github.com/iottly/iottly-console) in real-time, via websockets
- it accepts messages from the [iottly-console](https://github.com/iottly/iottly-console), via the `/command` handler and forwards them to remote devices
- it forwards incoming messages to a client service, [iottly-client-core](https://github.com/iottly/iottly-client-core) , via a client callback url configured in `settings.py`.

# Setup instructions

Please refer to [Iottly docker](https://github.com/iottly/iottly-docker) for prerequisites and full Iottly setup.
