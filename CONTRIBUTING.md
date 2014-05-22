# Contributing

Contact [Nikki VonHollen](mailto:vonhollen@google.com) with any patches you'd
like pulled. Google does require an
[individual](https://developers.google.com/open-source/cla/individual)
or [corporate](https://developers.google.com/open-source/cla/corporate)
Contributor License Agreement, but it doesn't transfer any copyright for the
patch.


# Code Style

This project uses GLib very heavily and copies many patterns from it like memory
management, macro use, data-type names, and unit testing. Code style, mostly
layout and naming, is adapted from
[Google's C++ style](google-styleguide.googlecode.com).


The style TL;DR is:

* Use `g_new`, `g_malloc`, etc. for managing memory. They never return NULL.
* Use heap memory aggressively whenever it makes code more simple.
* Function names use UpperCamelCase.
* Structs always use typedef and have UperCamelCase names too.
* A new type `Foo` should have FooNew, FooRef, and FooUnref functions for
  managing its lifecycle. It would be implemented in `foo.h`/`foo.c` and tested
  in `foo_test.c`.


Source is divided up into the following pieces:

* module: Contains the exported `pam_sm_*` methods and their helpers.
* policy: Parses policy files and enforces the policy on cache entries.
* storage: Loads cache entries from files in a directory, where each file is a
  serialized cache entry for one user.
* entry: Holds the per-user cache information (hashed password, last used time,
  etc.), checks passwords, and handles serialization.
* util: Extra functions for things like encoding/decoding values (dates,
  byte-arrays, etc.), gettings lists of groups for a user, and manipulating
  strings.
