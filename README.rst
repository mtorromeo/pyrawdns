pyrawdns
========

This is a proof-of-concept library to speak directly with DNS servers/clients. It should allow to build DNS clients or servers.

It basically handles the encoding and decoding process of the DNS communications.

I wrote this library to try out the idea of having a python script configured as a "stealth slave" in BIND to receive live notifications of zone updates and it worked remarkably well.

Requirements
------------
Since this is an incomplete implementation, I'm not going to publish this on PyPI in this state.

Only python >= 3.4 is required but it can run on python >= 3.2 by also installing enum34 which backports the enum module.

LICENSE
-------
Copyright (c) 2014 Massimiliano Torromeo

pyrawdns is free software released under the terms of the BSD license.

See the LICENSE file provided with the source distribution for full details.

Contacts
--------

* Massimiliano Torromeo <massimiliano.torromeo@gmail.com>
