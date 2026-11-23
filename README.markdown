README
======

This project was first conceived to manipulate Apple's software restore
packages (IPSWs) and hence much of it is geared specifically toward that
format. Useful tools to read and manipulate the internal data structures of
those files have been created to that end, and with minor changes, more
generality can be achieved in the general utility. An inexhaustive list of
such changes would be selectively enabling folder counts in HFS+, switching
between case sensitivity and non-sensitivity, and more fine-grained control
over the layout of created dmgs.

**THE CODE HEREIN SHOULD BE CONSIDERED HIGHLY EXPERIMENTAL**

Extensive testing have not been done, but comparatively simple tasks like
adding and removing files from a mostly contiguous filesystem are well
proven.

Please note that these tools and routines are currently only suitable to be
accessed by other programs that know what they're doing. I.e., doing
something you "shouldn't" be able to do, like removing non-existent files is
probably not a very good idea.

LICENSE
-------

This work is released under the terms of the GNU General Public License,
version 3. The full text of the license can be found in the LICENSE file.

DEPENDENCIES
------------

The HFS portion will work on any platform that supports GNU C and POSIX
conventions. The dmg portion has dependencies on zlib and optionally on
libcrypto from openssl. If libcrypto is not available, then all FileVault
related actions will fail, but everything else should still work. To
deliberately disable FileVault support, use `CFLAGS=-UHAVE_CRYPT`.

The checked HFS+ manifest CLI additionally requires json-c and OpenSSL's
libcrypto. These dependencies do not change the core library API.

USING
-----

The targets of the current repository are three command-line utilities that
demonstrate the usage of the library functions. The dmg portion of the code
has dependencies on the HFS+ portion of the code. The "hdutil" section
contains a version of the HFS+ utility that supports directly reading from
dmgs. It is separate from the HFS+ utility in order that the hfs directory
does not have dependencies on the dmg directory.

To build everything:

    cmake -S . -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build build

After running cmake, individual projects can also be built like:

    cmake --build build --target hfsplus
    cmake --build build --target dmg-bin
    cmake --build build --target hdutil

Create a fresh bare HFS+ or HFSX filesystem, check it, and convert it to a DMG:

    hfsplus root.raw create 2g -n Root -s -b 4096
    hfsplus root.raw verify
    dmg dmg root.raw root.dmg

`create` refuses existing paths and creates a sparse, unjournaled image. Sizes
accept k/m/g/t suffixes, must be at least 16 MiB and must be block aligned.
Block sizes are powers of two from 512 through 1048576 bytes. The default is
case-insensitive HFS+ with 4096-byte blocks. Use `-s` for case-sensitive HFSX
or `-i` for HFS+. Volume names accept printable ASCII except slash and colon.
`verify` checks geometry, B-trees, catalog counts, fork allocation and clean
internal journals. It opens the image read-only and does not repair it.

Native manifest interchange preserves Apple metadata without applying host
ownership or xattrs:

    hfsplus source.raw extractall tree --manifest manifest.json
    hfsplus source.raw inventory inventory.json [--metadata-only]
    hfsplus source.raw extractfiles tree --request request.json  # - reads JSON lines and returns file hashes
    hfsplus - validateall tree --manifest manifest.json
    hfsplus empty.raw addall tree / --manifest manifest.json
    hfsplus empty.raw verify
    hfsplus smaller.raw fit tree --manifest manifest.json [--size N] [--reserve N] [--maximum N]
    hfsplus root.raw shrink 64m

Export paths must be new. Keep `manifest.json.files/` beside the JSON file.
Import requires a fresh empty volume with matching case mode and block size.
The `apple-firmware.hfs-native/1` schema retains names, CNIDs, catalog timestamps,
BSD flags, FinderInfo, native file hardlinks, ASCII-named inline xattrs and fork
data. Allocation layout and volume UUIDs are rebuilt. Validation checks paths,
links and hashes, and decodes original compressed storage before import.
Supported decmpfs types are 1, 3/4, 7/8, 9/10 and 11/12.

Clean internal journals retain their data with relocated allocation addresses.
External journals, pending transactions and unsupported metadata fail explicitly.
These commands need no mount, driver, system formatter or root privileges.
