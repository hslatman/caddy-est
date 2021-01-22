# caddy-est

A [Caddy](https://caddyserver.com/) module for issuing certificates using Enrollment over Secure Transport (EST, [RFC7030](https://tools.ietf.org/html/rfc7030)).

## Description

This is a POC Caddy module implementation for issuing certificates using the Enrollment over Secure Transport [(EST)](https://tools.ietf.org/html/rfc7030) protocol.
EST can be used to (automatically) issue certificates to devices and end users and can be seen as a successor to [SCEP](https://tools.ietf.org/html/rfc8894).
Its goal is similar as the [ACME](https://tools.ietf.org/html/rfc8555) protocol, which is used for Web PKI, but is applied to devices that are generally not available publicly on the web and can thus not perform the active challenge-response protocol that ACME uses. 

This module uses [globalsign/est](https://github.com/globalsign/est) for providing the EST functionality. 
Caddy is the host for the endpoints served by the `est` library and also provides PKI maintenance functionality. 
We provide Caddy with the configuration for the `pki` app, which results in Caddy controlling the CA that is used for issueing certificates.
It is thus advisable to create a `ca` configuration for the `pki` app that is used specifically for the EST module.
An example configuration is available in `config.json`.

__Please note that the module currently does not provide much in terms of initial authentication except for a rudimentary HTTP Basic Authentication implementation__

## Usage

The simplest way to use the EST module is by using [xcaddy](https://github.com/caddyserver/xcaddy) to build your custom Caddy instance:

```bash
$ xcaddy build v2.3.0 --with github.com/hslatman/caddy-est/pkg/est
```

Alternatively, the HTTP handler can be included as a Caddy module as follows:

```golang
import (
	_ "github.com/hslatman/caddy-est/pkg/est"
)
```

Below is an excerpt of the configuration for (just) the EST module:

```json
...
    "handle": [
        {
            "handler": "est",
            "ca": "est-example",
            "allowed_hosts": [
                "estserver.local.example.com"
            ],
            "rate_limit": 0,
            "enable_basic_auth": false,
            "basic_auth_username": "username",
            "basic_auth_password": "password"
        }
    ]
...
```

The EST handler expects a Caddy PKI instance to be available called `est-example`, which you'll have to configure manually.
A more complete configuration, including examples for the PKI, TLS and HTTP is available in `config.json`.

## Things That Can Be Done

* Add tests.
* Add auditing of (re)enrollments (e.g. log, store, others); storage could work similar as the `acmeserver` handler.
* Add example with user provided public/private key pair.
* Add example usage of client cert authenticating to (different) Caddy server.
* Authenticate client in a different way (currently using a fixed HTTP Basic Auth) during initial enrollment. 
This needs something like a list of users (IDs) + passwords, a more generic approach to authentication (i.e. Caddy auth, but that's not in the RFC) or the shared secret approach (although a single shared secret is also not nice ...). 
Something like a single use token retrieved in some out-of-band way and sent in a HTTP header is probably what we want, although that wouldn't be entirely according to the RFC.
* Test HTTP Basic Authentication with an EST client that supports it.
* Have a look at the [Extensions](https://tools.ietf.org/html/rfc8295) for EST?
* Implement ServerKeyGen and TPMEnroll?
* Work with actual TPM/HSM? Also see this [commit](https://github.com/globalsign/est/commit/4f0fac33feb82749209342878df1608691ff991c).
* Refactor into using our own endpoints instead of going through the Chi router provided by `globalsign/est`.

...