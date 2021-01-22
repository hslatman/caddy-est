# caddy-est

A [Caddy](https://caddyserver.com/) module for serving [EST](https://tools.ietf.org/html/rfc7030)

## Description

...

## Usage

...

## TODO

* Add tests
* Add auditing of (re)enrollments
* Add example with user provided public/private key pair
* Add example usage of client cert authenticating to (different) Caddy server
* Authenticate client in a different way (currently using a fixed HTTP Basic Auth). 
This needs something like a list of users (IDs) + passwords, a more generic approach to authentication (i.e. Caddy auth, but that's not in the RFC) or the shared secret approach (although a single shared secret is also not nice ...). 
Something like a single use token retrieved in some out-of-band way and sent in a HTTP header is probably what we want, although that wouldn't be entirely according to the RFC.
* Test HTTP Basic Authentication with an EST client that supports it.
* Work with actual TPM/HSM? Also see this [commit](https://github.com/globalsign/est/commit/4f0fac33feb82749209342878df1608691ff991c)

...