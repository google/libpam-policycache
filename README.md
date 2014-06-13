# Overview

Caches passwords from other PAM modules and bypasses those modules based on a
configurable policy.

Why use libpam-policycache?

* Allows users to login when network is down.
* Reduces latency and load on remote login services.
* Restricts cache usage to specific users and groups.
* Enforces policies like cached password lifetime and rotation.


# Module Configuration

Arguments:

* `action=check`: Prompt the user for a password and check it against the cache.
* `action=update`: Set the user's cached password to the last successful
  password in the stack.
* `try_first_pass`: Try to use the password from a previous module (check only).
* `use_first_pass`: Only use the password from a previous module (check only).
* `policy=<path-glob>`: Default path-glob is
  `/etc/libpam-policycache.d/*.policy`.
* `storage=<path>`: Default path is `/var/cache/libpam-policycache`.

## Example

```
auth [success=2 new_authtok_reqd=ok default=ignore] pam_policycache.so action=check
auth [success=ok new_authtok_reqd=ok default=die] pam_krb5.so use_first_pass
auth [default=ignore] pam_policycache.so action=update
```


# Policy Configuration

Each policy file is INI-style with one section for each potential policy. The
first of the most specific matching sections is chosen.


The section's name describes who the policy applies to:

* `user:<name>`
* `group:<name>`
* `netgroup:<name>`


Each section has a combination of attributes:

* `tries`: Maximum number of failed attempts before entry is invalid.
* `refresh`: Duration (1h, 5d, 3w) an entry stays valid between successful uses
  (action=check).
* `renew`: Duration after the last update (action=update) when a successful use
  (action=check) will return `new_authtok_req` instead of `success`. Used when
  a password should be tried against another module opportunistically before the
  entry expires.
* `expire`: Duration after the last update (action=update) when the cache entry
  is marked invalid.

## TODO

* Add a `backoff` timer to rate-limit renew attempts.
* Add a `reset-tries` timer to reset the try count on an entry.
* Choose between "best-match" and "first-match" for the preferred policy.

## Example

In the following example policy, user "janedoe" may be the owner of the machine
and her login experience is similar to having a password in /etc/shadow. Her
password only needs to be checked by another module once a year.

Others in the "users" group may also use the cache, but only for a short time.
Their entries are evicted from the cache after an hour without use or two days
without being verified again using another module.

```
# /etc/libpam-policycache.d/foo.policy

[user:janedoe]
renew: 1w
expire: 52w

[group:users]
tries: 3
refresh: 1h
renew: 1d
expire: 2d
```


# Cache Storage

Policy entries are stored in /var/cache/libpam-policycache by default. Each
entry is stored in a file for the user it belongs to.

The cache entry format is human-readable for easier debugging:
```
{'version': <1>, 'tries': <0>, 'algorithm': <'SHA256'>, 'salt': <'0B8BAA809CDCA339910EE8F6F9FE22A5'>, 'hash': <'14BABCBC943B302EFDCC137419F7D3FB736602D77CF42975A6778A5B7F2D63CD'>, 'last_verified': <'2014-03-28T23:14:21Z'>, 'last_used': <'2014-03-28T23:14:21Z'>, 'last_tried': <'2014-03-28T23:14:21Z'>}
```


# Building

Built with autotools and includes an autogen.sh script:

1. ./autogen.sh (not needed when using source tarball)
2. ./configure
3. make
4. make check
5. sudo make install


Dependencies:

* GLib
* Linux-PAM
* Autoconf, Automake, Libtool
