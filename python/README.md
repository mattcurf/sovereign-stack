# Hash-locked Python HTTP hello world

The builder and runtime both derive from `ARG BASE_IMAGE`, default
`sovereign-stack/base-container:local`. Debian's Python **3.13.5-1** metapackage
selects patched interpreter **3.13.5-2+deb13u3** from the fixed signed snapshot.
The build stage installs Debian pip **25.1.1+dfsg-1** and installs Waitress
**3.0.2** using `--require-hashes --only-binary=:all:` into `/opt/python`.
`requirements.lock` pins the reviewed PyPI wheel SHA-256. No sdist execution,
unbounded resolution, venv bootstrapping download, or runtime pip is needed.

The application uses Waitress rather than Python's development-only http.server.
It listens on **8080**, with two WSGI threads, 8 KiB request headers and a 1 MiB
body limit, and returns `Hello, world! From Python.`. Its small WSGI function
does not persist or process request data. Bytecode writes are disabled.

Runtime **65532:65532** is compatible with read-only rootfs, only `/tmp` writable,
all caps dropped and no-new-privileges. The final image includes the normal Debian
Python standard library and Waitress, but not pip, compiler or development
headers. Debian packages/copyright and Waitress's `.dist-info` including license
metadata remain discoverable. `/usr/share/sovereign-stack/python/` retains the
requirements lock and build Debian package/version/doc records. The complete
`dependencies` stage is tagged `sovereign-stack/python-builder:local` for genuine
builder scans; a TSV alone is not a Trivy package inventory.

To update, review the [PyPI release metadata](https://pypi.org/pypi/waitress/json),
download/hash the selected wheel, update the version/hash together and rerun
build, smoke and Trivy scans under the shared fixable HIGH/CRITICAL policy.
A downloaded hash is trusted only
after review and committing it; asking the live index for a hash during every
build would defeat the lock. Wheel-only installation deliberately fails if no
approved wheel exists. Snapshots and package pins must be updated together; see
[base policy and reproducibility limitations](../base-container/README.md).

References:

* [pip secure installs: hash checking and binary-only artifacts](https://pip.pypa.io/en/stable/topics/secure-installs/)
* [Waitress serve parameters and request limits](https://docs.pylonsproject.org/projects/waitress/en/stable/arguments.html)
* [Python http.server security warning](https://docs.python.org/3/library/http.server.html)
