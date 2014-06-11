# Contributing

Contact [Nikki VonHollen](mailto:vonhollen@google.com) with any patches you'd
like pulled. Google does require an
[individual](https://developers.google.com/open-source/cla/individual)
or [corporate](https://developers.google.com/open-source/cla/corporate)
Contributor License Agreement, but it doesn't transfer any copyright for the
patch.


## Style

This project uses [GLib](https://developer.gnome.org/glib/stable/) very heavily
and copies many patterns from it like memory management, macro use, data-type
names, and unit testing. Layout and naming style is adapted from
[Google's C++ style](google-styleguide.googlecode.com).

The combined style TL;DR is:

* Use `g_new`, `g_malloc`, etc. for managing memory. They never return NULL.
* Use heap memory aggressively whenever it makes code more simple.
* Function names use UpperCamelCase.
* Structs always use typedef and have UperCamelCase names too.
* A new type `Foo` should have `FooNew()`, `FooRef()`, and `FooUnref()`
  functions for managing its lifecycle. It would be implemented in
  `foo.h`/`foo.c` and tested in `foo_test.c`.


## Sources

Each of the following names has three source files `${name}.h`, `${name}.c`, and
`${name}_test.c`:

* module: Contains the exported `pam_sm_*()` functions and their helpers.
* policy: Parses policy files and enforces the policy on cache entries.
* storage: Loads cache entries from files in a directory, where each file is a
  serialized cache entry for one user.
* entry: Holds the per-user cache information (hashed password, last used time,
  etc.), checks passwords, and handles serialization.
* util: Extra functions for things like encoding/decoding values (dates,
  byte-arrays, etc.), gettings lists of groups for a user, and manipulating
  strings.


## Testing

Unit tests are paired with source files at `src/*_test.c` and become executables
named `src/*_test`.

When developing, test with:

```shell
make check
``` 

Before sending a pull request, please run the tests again with valgrind:

```shell
make check
cd src
for FILENAME in ./*_test; do
  echo "Running $NAME"
  G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind \
      --leak-check=full --show-possibly-lost=yes --track-origins=yes \
      --leak-resolution=high --num-callers=40 --quiet $FILENAME \
      && echo PASS || echo FAIL
  echo
  echo
done
```

When making a release tarball, use:

```shell
make distcheck
```

### Mocks

Test utility and mock functions live in `src/test.h` and `src/test.c`.

Mock functions are implemented using the --wrap flag for ld (man 1 ld). To mock
a function `int foo()` in another shared library add `-Wl,--wrap,foo` to
`MOCK_FLAGS = ...` in `src/Makefile.am` and implement `int __wrap_foo() { ... }`
in `test.c`.
