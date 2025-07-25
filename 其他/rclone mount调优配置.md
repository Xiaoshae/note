# rclone mount调优配置

### 🧑‍💻 User



rclone mount 配置如何调优？例如我想要这样的效果，在挂载成功后，自动获取整个目录结构，目录结构 10s 更新一次，客户端每次访问直接返回本次缓存的目录结构。

使用 rclone 将远程 webdav 挂载到本地，然后使用在本地搭建 webdav 服务在将这个提供服务出去。

root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone# rclone mount --help 

rclone mount allows Linux, FreeBSD, macOS and Windows to
mount any of Rclone's cloud storage systems as a file system with
FUSE.

First set up your remote using `rclone config`.  Check it works with `rclone ls` etc.

On Linux and macOS, you can run mount in either foreground or background (aka
daemon) mode. Mount runs in foreground mode by default. Use the `--daemon` flag
to force background mode. On Windows you can run mount in foreground only,
the flag is ignored.

In background mode rclone acts as a generic Unix mount program: the main
program starts, spawns background rclone process to setup and maintain the
mount, waits until success or timeout and exits with appropriate code
(killing the child process if it fails).

On Linux/macOS/FreeBSD start the mount like this, where `/path/to/local/mount`
is an **empty** **existing** directory:

    rclone mount remote:path/to/files /path/to/local/mount

On Windows you can start a mount in different ways. See [below](#mounting-modes-on-windows)
for details. If foreground mount is used interactively from a console window,
rclone will serve the mount and occupy the console so another window should be
used to work with the mount until rclone is interrupted e.g. by pressing Ctrl-C.

The following examples will mount to an automatically assigned drive,
to specific drive letter `X:`, to path `C:\path\parent\mount`
(where parent directory or drive must exist, and mount must **not** exist,
and is not supported when [mounting as a network drive](#mounting-modes-on-windows)), and
the last example will mount as network share `\\cloud\remote` and map it to an
automatically assigned drive:

    rclone mount remote:path/to/files *
    rclone mount remote:path/to/files X:
    rclone mount remote:path/to/files C:\path\parent\mount
    rclone mount remote:path/to/files \\cloud\remote

When the program ends while in foreground mode, either via Ctrl+C or receiving
a SIGINT or SIGTERM signal, the mount should be automatically stopped.

When running in background mode the user will have to stop the mount manually:

    # Linux
    fusermount -u /path/to/local/mount
    # OS X
    umount /path/to/local/mount

The umount operation can fail, for example when the mountpoint is busy.
When that happens, it is the user's responsibility to stop the mount manually.

The size of the mounted file system will be set according to information retrieved
from the remote, the same as returned by the [rclone about](https://rclone.org/commands/rclone_about/)
command. Remotes with unlimited storage may report the used size only,
then an additional 1 PiB of free space is assumed. If the remote does not
[support](https://rclone.org/overview/#optional-features) the about feature
at all, then 1 PiB is set as both the total and the free size.

### Installing on Windows

To run rclone mount on Windows, you will need to
download and install [WinFsp](http://www.secfs.net/winfsp/).

[WinFsp](https://github.com/winfsp/winfsp) is an open-source
Windows File System Proxy which makes it easy to write user space file
systems for Windows.  It provides a FUSE emulation layer which rclone
uses combination with [cgofuse](https://github.com/winfsp/cgofuse).
Both of these packages are by Bill Zissimopoulos who was very helpful
during the implementation of rclone mount for Windows.

#### Mounting modes on windows

Unlike other operating systems, Microsoft Windows provides a different filesystem
type for network and fixed drives. It optimises access on the assumption fixed
disk drives are fast and reliable, while network drives have relatively high latency
and less reliability. Some settings can also be differentiated between the two types,
for example that Windows Explorer should just display icons and not create preview
thumbnails for image and video files on network drives.

In most cases, rclone will mount the remote as a normal, fixed disk drive by default.
However, you can also choose to mount it as a remote network drive, often described
as a network share. If you mount an rclone remote using the default, fixed drive mode
and experience unexpected program errors, freezes or other issues, consider mounting
as a network drive instead.

When mounting as a fixed disk drive you can either mount to an unused drive letter,
or to a path representing a **nonexistent** subdirectory of an **existing** parent
directory or drive. Using the special value `*` will tell rclone to
automatically assign the next available drive letter, starting with Z: and moving backward.
Examples:

    rclone mount remote:path/to/files *
    rclone mount remote:path/to/files X:
    rclone mount remote:path/to/files C:\path\parent\mount
    rclone mount remote:path/to/files X:

Option `--volname` can be used to set a custom volume name for the mounted
file system. The default is to use the remote name and path.

To mount as network drive, you can add option `--network-mode`
to your mount command. Mounting to a directory path is not supported in
this mode, it is a limitation Windows imposes on junctions, so the remote must always
be mounted to a drive letter.

    rclone mount remote:path/to/files X: --network-mode

A volume name specified with `--volname` will be used to create the network share path.
A complete UNC path, such as `\\cloud\remote`, optionally with path
`\\cloud\remote\madeup\path`, will be used as is. Any other
string will be used as the share part, after a default prefix `\\server\`.
If no volume name is specified then `\\server\share` will be used.
You must make sure the volume name is unique when you are mounting more than one drive,
or else the mount command will fail. The share name will treated as the volume label for
the mapped drive, shown in Windows Explorer etc, while the complete
`\\server\share` will be reported as the remote UNC path by
`net use` etc, just like a normal network drive mapping.

If you specify a full network share UNC path with `--volname`, this will implicitly
set the `--network-mode` option, so the following two examples have same result:

    rclone mount remote:path/to/files X: --network-mode
    rclone mount remote:path/to/files X: --volname \\server\share

You may also specify the network share UNC path as the mountpoint itself. Then rclone
will automatically assign a drive letter, same as with `*` and use that as
mountpoint, and instead use the UNC path specified as the volume name, as if it were
specified with the `--volname` option. This will also implicitly set
the `--network-mode` option. This means the following two examples have same result:

    rclone mount remote:path/to/files \\cloud\remote
    rclone mount remote:path/to/files * --volname \\cloud\remote

There is yet another way to enable network mode, and to set the share path,
and that is to pass the "native" libfuse/WinFsp option directly:
`--fuse-flag --VolumePrefix=\server\share`. Note that the path
must be with just a single backslash prefix in this case.


*Note:* In previous versions of rclone this was the only supported method.

[Read more about drive mapping](https://en.wikipedia.org/wiki/Drive_mapping)

See also [Limitations](#limitations) section below.

#### Windows filesystem permissions

The FUSE emulation layer on Windows must convert between the POSIX-based
permission model used in FUSE, and the permission model used in Windows,
based on access-control lists (ACL).

The mounted filesystem will normally get three entries in its access-control list (ACL),
representing permissions for the POSIX permission scopes: Owner, group and others.
By default, the owner and group will be taken from the current user, and the built-in
group "Everyone" will be used to represent others. The user/group can be customized
with FUSE options "UserName" and "GroupName",
e.g. `-o UserName=user123 -o GroupName="Authenticated Users"`.
The permissions on each entry will be set according to [options](#options)
`--dir-perms` and `--file-perms`, which takes a value in traditional
[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).

The default permissions corresponds to `--file-perms 0666 --dir-perms 0777`,
i.e. read and write permissions to everyone. This means you will not be able
to start any programs from the mount. To be able to do that you must add
execute permissions, e.g. `--file-perms 0777 --dir-perms 0777` to add it
to everyone. If the program needs to write files, chances are you will have
to enable [VFS File Caching](#vfs-file-caching) as well (see also [limitations](#limitations)).

Note that the mapping of permissions is not always trivial, and the result
you see in Windows Explorer may not be exactly like you expected.
For example, when setting a value that includes write access, this will be
mapped to individual permissions "write attributes", "write data" and "append data",
but not "write extended attributes". Windows will then show this as basic
permission "Special" instead of "Write", because "Write" includes the
"write extended attributes" permission.

If you set POSIX permissions for only allowing access to the owner, using
`--file-perms 0600 --dir-perms 0700`, the user group and the built-in "Everyone"
group will still be given some special permissions, such as "read attributes"
and "read permissions", in Windows. This is done for compatibility reasons,
e.g. to allow users without additional permissions to be able to read basic
metadata about files like in UNIX. One case that may arise is that other programs
(incorrectly) interprets this as the file being accessible by everyone. For example
an SSH client may warn about "unprotected private key file".

WinFsp 2021 (version 1.9) introduces a new FUSE option "FileSecurity",
that allows the complete specification of file security descriptors using
[SDDL](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).
With this you can work around issues such as the mentioned "unprotected private key file"
by specifying `-o FileSecurity="D:P(A;;FA;;;OW)"`, for file all access (FA) to the owner (OW).

#### Windows caveats

Drives created as Administrator are not visible to other accounts,
not even an account that was elevated to Administrator with the
User Account Control (UAC) feature. A result of this is that if you mount
to a drive letter from a Command Prompt run as Administrator, and then try
to access the same drive from Windows Explorer (which does not run as
Administrator), you will not be able to see the mounted drive.

If you don't need to access the drive from applications running with
administrative privileges, the easiest way around this is to always
create the mount from a non-elevated command prompt.

To make mapped drives available to the user account that created them
regardless if elevated or not, there is a special Windows setting called
[linked connections](https://docs.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command#detail-to-configure-the-enablelinkedconnections-registry-entry)
that can be enabled.

It is also possible to make a drive mount available to everyone on the system,
by running the process creating it as the built-in SYSTEM account.
There are several ways to do this: One is to use the command-line
utility [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec),
from Microsoft's Sysinternals suite, which has option `-s` to start
processes as the SYSTEM account. Another alternative is to run the mount
command from a Windows Scheduled Task, or a Windows Service, configured
to run as the SYSTEM account. A third alternative is to use the
[WinFsp.Launcher infrastructure](https://github.com/winfsp/winfsp/wiki/WinFsp-Service-Architecture)).
Note that when running rclone as another user, it will not use
the configuration file from your profile unless you tell it to
with the [`--config`](https://rclone.org/docs/#config-config-file) option.
Read more in the [install documentation](https://rclone.org/install/).

Note that mapping to a directory path, instead of a drive letter,
does not suffer from the same limitations.

### Limitations

Without the use of `--vfs-cache-mode` this can only write files
sequentially, it can only seek when reading.  This means that many
applications won't work with their files on an rclone mount without
`--vfs-cache-mode writes` or `--vfs-cache-mode full`.
See the [VFS File Caching](#vfs-file-caching) section for more info.

The bucket-based remotes (e.g. Swift, S3, Google Compute Storage, B2)
do not support the concept of empty directories, so empty
directories will have a tendency to disappear once they fall out of
the directory cache.

When `rclone mount` is invoked on Unix with `--daemon` flag, the main rclone
program will wait for the background mount to become ready or until the timeout
specified by the `--daemon-wait` flag. On Linux it can check mount status using
ProcFS so the flag in fact sets **maximum** time to wait, while the real wait
can be less. On macOS / BSD the time to wait is constant and the check is
performed only at the end. We advise you to set wait time on macOS reasonably.

Only supported on Linux, FreeBSD, OS X and Windows at the moment.

### rclone mount vs rclone sync/copy

File systems expect things to be 100% reliable, whereas cloud storage
systems are a long way from 100% reliable. The rclone sync/copy
commands cope with this with lots of retries.  However rclone mount
can't use retries in the same way without making local copies of the
uploads. Look at the [VFS File Caching](#vfs-file-caching)
for solutions to make mount more reliable.

### Attribute caching

You can use the flag `--attr-timeout` to set the time the kernel caches
the attributes (size, modification time, etc.) for directory entries.

The default is `1s` which caches files just long enough to avoid
too many callbacks to rclone from the kernel.

In theory 0s should be the correct value for filesystems which can
change outside the control of the kernel. However this causes quite a
few problems such as
[rclone using too much memory](https://github.com/rclone/rclone/issues/2157),
[rclone not serving files to samba](https://forum.rclone.org/t/rclone-1-39-vs-1-40-mount-issue/5112)
and [excessive time listing directories](https://github.com/rclone/rclone/issues/2095#issuecomment-371141147).

The kernel can cache the info about a file for the time given by
`--attr-timeout`. You may see corruption if the remote file changes
length during this window.  It will show up as either a truncated file
or a file with garbage on the end.  With `--attr-timeout 1s` this is
very unlikely but not impossible.  The higher you set `--attr-timeout`
the more likely it is.  The default setting of "1s" is the lowest
setting which mitigates the problems above.

If you set it higher (`10s` or `1m` say) then the kernel will call
back to rclone less often making it more efficient, however there is
more chance of the corruption issue above.

If files don't change on the remote outside of the control of rclone
then there is no chance of corruption.

This is the same as setting the attr_timeout option in mount.fuse.

### Filters

Note that all the rclone filters can be used to select a subset of the
files to be visible in the mount.

### systemd

When running rclone mount as a systemd service, it is possible
to use Type=notify. In this case the service will enter the started state
after the mountpoint has been successfully set up.
Units having the rclone mount service specified as a requirement
will see all files and folders immediately in this mode.

Note that systemd runs mount units without any environment variables including
`PATH` or `HOME`. This means that tilde (`~`) expansion will not work
and you should provide `--config` and `--cache-dir` explicitly as absolute
paths via rclone arguments.
Since mounting requires the `fusermount` program, rclone will use the fallback
PATH of `/bin:/usr/bin` in this scenario. Please ensure that `fusermount`
is present on this PATH.

### Rclone as Unix mount helper

The core Unix program `/bin/mount` normally takes the `-t FSTYPE` argument
then runs the `/sbin/mount.FSTYPE` helper program passing it mount options
as `-o key=val,...` or `--opt=...`. Automount (classic or systemd) behaves
in a similar way.

rclone by default expects GNU-style flags `--key val`. To run it as a mount
helper you should symlink rclone binary to `/sbin/mount.rclone` and optionally
`/usr/bin/rclonefs`, e.g. `ln -s /usr/bin/rclone /sbin/mount.rclone`.
rclone will detect it and translate command-line arguments appropriately.

Now you can run classic mounts like this:
```
mount sftp1:subdir /mnt/data -t rclone -o vfs_cache_mode=writes,sftp_key_file=/path/to/pem
```

or create systemd mount units:
```
# /etc/systemd/system/mnt-data.mount
[Unit]
After=network-online.target
[Mount]
Type=rclone
What=sftp1:subdir
Where=/mnt/data
Options=rw,allow_other,args2env,vfs-cache-mode=writes,config=/etc/rclone.conf,cache-dir=/var/rclone
```

optionally accompanied by systemd automount unit
```
# /etc/systemd/system/mnt-data.automount
[Unit]
After=network-online.target
Before=remote-fs.target
[Automount]
Where=/mnt/data
TimeoutIdleSec=600
[Install]
WantedBy=multi-user.target
```

or add in `/etc/fstab` a line like
```
sftp1:subdir /mnt/data rclone rw,noauto,nofail,_netdev,x-systemd.automount,args2env,vfs_cache_mode=writes,config=/etc/rclone.conf,cache_dir=/var/cache/rclone 0 0
```

or use classic Automountd.
Remember to provide explicit `config=...,cache-dir=...` as a workaround for
mount units being run without `HOME`.

Rclone in the mount helper mode will split `-o` argument(s) by comma, replace `_`
by `-` and prepend `--` to get the command-line flags. Options containing commas
or spaces can be wrapped in single or double quotes. Any inner quotes inside outer
quotes of the same type should be doubled.

Mount option syntax includes a few extra options treated specially:

- `env.NAME=VALUE` will set an environment variable for the mount process.
  This helps with Automountd and Systemd.mount which don't allow setting
  custom environment for mount helpers.
  Typically you will use `env.HTTPS_PROXY=proxy.host:3128` or `env.HOME=/root`
- `command=cmount` can be used to run `cmount` or any other rclone command
  rather than the default `mount`.
- `args2env` will pass mount options to the mount helper running in background
  via environment variables instead of command line arguments. This allows to
  hide secrets from such commands as `ps` or `pgrep`.
- `vv...` will be transformed into appropriate `--verbose=N`
- standard mount options like `x-systemd.automount`, `_netdev`, `nosuid` and alike
  are intended only for Automountd and ignored by rclone.

### VFS - Virtual File System

This command uses the VFS layer. This adapts the cloud storage objects
that rclone uses into something which looks much more like a disk
filing system.

Cloud storage objects have lots of properties which aren't like disk
files - you can't extend them or write to the middle of them, so the
VFS layer has to deal with that. Because there is no one right way of
doing this there are various options explained below.

The VFS layer also implements a directory cache - this caches info
about files and directories (but not the data) in memory.

### VFS Directory Cache

Using the `--dir-cache-time` flag, you can control how long a
directory should be considered up to date and not refreshed from the
backend. Changes made through the VFS will appear immediately or
invalidate the cache.

    --dir-cache-time duration   Time to cache directory entries for (default 5m0s)
    --poll-interval duration    Time to wait between polling for changes. Must be smaller than dir-cache-time. Only on supported remotes. Set to 0 to disable (default 1m0s)

However, changes made directly on the cloud storage by the web
interface or a different copy of rclone will only be picked up once
the directory cache expires if the backend configured does not support
polling for changes. If the backend supports polling, changes will be
picked up within the polling interval.

You can send a `SIGHUP` signal to rclone for it to flush all
directory caches, regardless of how old they are.  Assuming only one
rclone instance is running, you can reset the cache like this:

    kill -SIGHUP $(pidof rclone)

If you configure rclone with a [remote control](/rc) then you can use
rclone rc to flush the whole directory cache:

    rclone rc vfs/forget

Or individual files or directories:

    rclone rc vfs/forget file=path/to/file dir=path/to/dir

### VFS File Buffering

The `--buffer-size` flag determines the amount of memory,
that will be used to buffer data in advance.

Each open file will try to keep the specified amount of data in memory
at all times. The buffered data is bound to one open file and won't be
shared.

This flag is a upper limit for the used memory per open file.  The
buffer will only use memory for data that is downloaded but not not
yet read. If the buffer is empty, only a small amount of memory will
be used.

The maximum memory used by rclone for buffering can be up to
`--buffer-size * open files`.

### VFS File Caching

These flags control the VFS file caching options. File caching is
necessary to make the VFS layer appear compatible with a normal file
system. It can be disabled at the cost of some compatibility.

For example you'll need to enable VFS caching if you want to read and
write simultaneously to a file.  See below for more details.

Note that the VFS cache is separate from the cache backend and you may
find that you need one or the other or both.

    --cache-dir string                   Directory rclone will use for caching.
    --vfs-cache-mode CacheMode           Cache mode off|minimal|writes|full (default off)
    --vfs-cache-max-age duration         Max age of objects in the cache (default 1h0m0s)
    --vfs-cache-max-size SizeSuffix      Max total size of objects in the cache (default off)
    --vfs-cache-poll-interval duration   Interval to poll the cache for stale objects (default 1m0s)
    --vfs-write-back duration            Time to writeback files after last use when using cache (default 5s)

If run with `-vv` rclone will print the location of the file cache.  The
files are stored in the user cache file area which is OS dependent but
can be controlled with `--cache-dir` or setting the appropriate
environment variable.

The cache has 4 different modes selected by `--vfs-cache-mode`.
The higher the cache mode the more compatible rclone becomes at the
cost of using disk space.

Note that files are written back to the remote only when they are
closed and if they haven't been accessed for `--vfs-write-back`
seconds. If rclone is quit or dies with files that haven't been
uploaded, these will be uploaded next time rclone is run with the same
flags.

If using `--vfs-cache-max-size` note that the cache may exceed this size
for two reasons.  Firstly because it is only checked every
`--vfs-cache-poll-interval`.  Secondly because open files cannot be
evicted from the cache.

You **should not** run two copies of rclone using the same VFS cache
with the same or overlapping remotes if using `--vfs-cache-mode > off`.
This can potentially cause data corruption if you do. You can work
around this by giving each rclone its own cache hierarchy with
`--cache-dir`. You don't need to worry about this if the remotes in
use don't overlap.

#### --vfs-cache-mode off

In this mode (the default) the cache will read directly from the remote and write
directly to the remote without caching anything on disk.

This will mean some operations are not possible

  * Files can't be opened for both read AND write
  * Files opened for write can't be seeked
  * Existing files opened for write must have O_TRUNC set
  * Files open for read with O_TRUNC will be opened write only
  * Files open for write only will behave as if O_TRUNC was supplied
  * Open modes O_APPEND, O_TRUNC are ignored
  * If an upload fails it can't be retried

#### --vfs-cache-mode minimal

This is very similar to "off" except that files opened for read AND
write will be buffered to disk.  This means that files opened for
write will be a lot more compatible, but uses the minimal disk space.

These operations are not possible

  * Files opened for write only can't be seeked
  * Existing files opened for write must have O_TRUNC set
  * Files opened for write only will ignore O_APPEND, O_TRUNC
  * If an upload fails it can't be retried

#### --vfs-cache-mode writes

In this mode files opened for read only are still read directly from
the remote, write only and read/write files are buffered to disk
first.

This mode should support all normal file system operations.

If an upload fails it will be retried at exponentially increasing
intervals up to 1 minute.

#### --vfs-cache-mode full

In this mode all reads and writes are buffered to and from disk. When
data is read from the remote this is buffered to disk as well.

In this mode the files in the cache will be sparse files and rclone
will keep track of which bits of the files it has downloaded.

So if an application only reads the starts of each file, then rclone
will only buffer the start of the file. These files will appear to be
their full size in the cache, but they will be sparse files with only
the data that has been downloaded present in them.

This mode should support all normal file system operations and is
otherwise identical to `--vfs-cache-mode` writes.

When reading a file rclone will read `--buffer-size` plus
`--vfs-read-ahead` bytes ahead.  The `--buffer-size` is buffered in memory
whereas the `--vfs-read-ahead` is buffered on disk.

When using this mode it is recommended that `--buffer-size` is not set
too large and `--vfs-read-ahead` is set large if required.

**IMPORTANT** not all file systems support sparse files. In particular
FAT/exFAT do not. Rclone will perform very badly if the cache
directory is on a filesystem which doesn't support sparse files and it
will log an ERROR message if one is detected.

#### Fingerprinting

Various parts of the VFS use fingerprinting to see if a local file
copy has changed relative to a remote file. Fingerprints are made
from:

- size
- modification time
- hash

where available on an object.

On some backends some of these attributes are slow to read (they take
an extra API call per object, or extra work per object).

For example `hash` is slow with the `local` and `sftp` backends as
they have to read the entire file and hash it, and `modtime` is slow
with the `s3`, `swift`, `ftp` and `qinqstor` backends because they
need to do an extra API call to fetch it.

If you use the `--vfs-fast-fingerprint` flag then rclone will not
include the slow operations in the fingerprint. This makes the
fingerprinting less accurate but much faster and will improve the
opening time of cached files.

If you are running a vfs cache over `local`, `s3` or `swift` backends
then using this flag is recommended.

Note that if you change the value of this flag, the fingerprints of
the files in the cache may be invalidated and the files will need to
be downloaded again.

### VFS Chunked Reading

When rclone reads files from a remote it reads them in chunks. This
means that rather than requesting the whole file rclone reads the
chunk specified.  This can reduce the used download quota for some
remotes by requesting only chunks from the remote that are actually
read, at the cost of an increased number of requests.

These flags control the chunking:

    --vfs-read-chunk-size SizeSuffix        Read the source objects in chunks (default 128M)
    --vfs-read-chunk-size-limit SizeSuffix  Max chunk doubling size (default off)

Rclone will start reading a chunk of size `--vfs-read-chunk-size`,
and then double the size for each read. When `--vfs-read-chunk-size-limit` is
specified, and greater than `--vfs-read-chunk-size`, the chunk size for each
open file will get doubled only until the specified value is reached. If the
value is "off", which is the default, the limit is disabled and the chunk size
will grow indefinitely.

With `--vfs-read-chunk-size 100M` and `--vfs-read-chunk-size-limit 0`
the following parts will be downloaded: 0-100M, 100M-200M, 200M-300M, 300M-400M and so on.
When `--vfs-read-chunk-size-limit 500M` is specified, the result would be
0-100M, 100M-300M, 300M-700M, 700M-1200M, 1200M-1700M and so on.

Setting `--vfs-read-chunk-size` to `0` or "off" disables chunked reading.

### VFS Performance

These flags may be used to enable/disable features of the VFS for
performance or other reasons. See also the [chunked reading](#vfs-chunked-reading)
feature.

In particular S3 and Swift benefit hugely from the `--no-modtime` flag
(or use `--use-server-modtime` for a slightly different effect) as each
read of the modification time takes a transaction.

    --no-checksum     Don't compare checksums on up/download.
    --no-modtime      Don't read/write the modification time (can speed things up).
    --no-seek         Don't allow seeking in files.
    --read-only       Only allow read-only access.

Sometimes rclone is delivered reads or writes out of order. Rather
than seeking rclone will wait a short time for the in sequence read or
write to come in. These flags only come into effect when not using an
on disk cache file.

    --vfs-read-wait duration   Time to wait for in-sequence read before seeking (default 20ms)
    --vfs-write-wait duration  Time to wait for in-sequence write before giving error (default 1s)

When using VFS write caching (`--vfs-cache-mode` with value writes or full),
the global flag `--transfers` can be set to adjust the number of parallel uploads of
modified files from the cache (the related global flag `--checkers` has no effect on the VFS).

    --transfers int  Number of file transfers to run in parallel (default 4)

### VFS Case Sensitivity

Linux file systems are case-sensitive: two files can differ only
by case, and the exact case must be used when opening a file.

File systems in modern Windows are case-insensitive but case-preserving:
although existing files can be opened using any case, the exact case used
to create the file is preserved and available for programs to query.
It is not allowed for two files in the same directory to differ only by case.

Usually file systems on macOS are case-insensitive. It is possible to make macOS
file systems case-sensitive but that is not the default.

The `--vfs-case-insensitive` VFS flag controls how rclone handles these
two cases. If its value is "false", rclone passes file names to the remote
as-is. If the flag is "true" (or appears without a value on the
command line), rclone may perform a "fixup" as explained below.

The user may specify a file name to open/delete/rename/etc with a case
different than what is stored on the remote. If an argument refers
to an existing file with exactly the same name, then the case of the existing
file on the disk will be used. However, if a file name with exactly the same
name is not found but a name differing only by case exists, rclone will
transparently fixup the name. This fixup happens only when an existing file
is requested. Case sensitivity of file names created anew by rclone is
controlled by the underlying remote.

Note that case sensitivity of the operating system running rclone (the target)
may differ from case sensitivity of a file system presented by rclone (the source).
The flag controls whether "fixup" is performed to satisfy the target.

If the flag is not provided on the command line, then its default value depends
on the operating system where rclone runs: "true" on Windows and macOS, "false"
otherwise. If the flag is provided without a value, then it is "true".

### VFS Disk Options

This flag allows you to manually set the statistics about the filing system.
It can be useful when those statistics cannot be read correctly automatically.

    --vfs-disk-space-total-size    Manually set the total disk space size (example: 256G, default: -1)

### Alternate report of used bytes

Some backends, most notably S3, do not report the amount of bytes used.
If you need this information to be available when running `df` on the
filesystem, then pass the flag `--vfs-used-is-size` to rclone.
With this flag set, instead of relying on the backend to report this
information, rclone will scan the whole remote similar to `rclone size`
and compute the total used space itself.

_WARNING._ Contrary to `rclone size`, this flag ignores filters so that the
result is accurate. However, this is very inefficient and may cost lots of API
calls resulting in extra charges. Use it as a last resort and only with caching.

Usage:
  rclone mount remote:path /path/to/mountpoint [flags]

Flags:
      --allow-non-empty                        Allow mounting over a non-empty directory (not supported on Windows)
      --allow-other                            Allow access to other users (not supported on Windows)
      --allow-root                             Allow access to root user (not supported on Windows)
      --async-read                             Use asynchronous reads (not supported on Windows) (default true)
      --attr-timeout duration                  Time for which file/directory attributes are cached (default 1s)
      --daemon                                 Run mount in background and exit parent process (as background output is suppressed, use --log-file with --log-format=pid,... to monitor) (not supported on Windows)
      --daemon-timeout duration                Time limit for rclone to respond to kernel (not supported on Windows)
      --daemon-wait duration                   Time to wait for ready mount from daemon (maximum time on Linux, constant sleep time on OSX/BSD) (not supported on Windows) (default 1m0s)
      --debug-fuse                             Debug the FUSE internals - needs -v
      --default-permissions                    Makes kernel enforce access control based on the file mode (not supported on Windows)
      --devname string                         Set the device name - default is remote:path
      --dir-cache-time duration                Time to cache directory entries for (default 5m0s)
      --dir-perms FileMode                     Directory permissions (default 0777)
      --file-perms FileMode                    File permissions (default 0666)
      --fuse-flag stringArray                  Flags or arguments to be passed direct to libfuse/WinFsp (repeat if required)
      --gid uint32                             Override the gid field set by the filesystem (not supported on Windows)
  -h, --help                                   help for mount
      --max-read-ahead SizeSuffix              The number of bytes that can be prefetched for sequential reads (not supported on Windows) (default 128Ki)
      --network-mode                           Mount as remote network drive, instead of fixed disk drive (supported on Windows only)
      --no-checksum                            Don't compare checksums on up/download
      --no-modtime                             Don't read/write the modification time (can speed things up)
      --no-seek                                Don't allow seeking in files
      --noappledouble                          Ignore Apple Double (._) and .DS_Store files (supported on OSX only) (default true)
      --noapplexattr                           Ignore all "com.apple.*" extended attributes (supported on OSX only)
  -o, --option stringArray                     Option for libfuse/WinFsp (repeat if required)
      --poll-interval duration                 Time to wait between polling for changes, must be smaller than dir-cache-time and only on supported remotes (set 0 to disable) (default 1m0s)
      --read-only                              Only allow read-only access
      --uid uint32                             Override the uid field set by the filesystem (not supported on Windows)
      --umask int                              Override the permission bits set by the filesystem (not supported on Windows) (default 18)
      --vfs-cache-max-age duration             Max age of objects in the cache (default 1h0m0s)
      --vfs-cache-max-size SizeSuffix          Max total size of objects in the cache (default off)
      --vfs-cache-mode CacheMode               Cache mode off|minimal|writes|full (default off)
      --vfs-cache-poll-interval duration       Interval to poll the cache for stale objects (default 1m0s)
      --vfs-case-insensitive                   If a file name not found, find a case insensitive match
      --vfs-disk-space-total-size SizeSuffix   Specify the total space of disk (default off)
      --vfs-fast-fingerprint                   Use fast (less accurate) fingerprints for change detection
      --vfs-read-ahead SizeSuffix              Extra read ahead over --buffer-size when using cache-mode full
      --vfs-read-chunk-size SizeSuffix         Read the source objects in chunks (default 128Mi)
      --vfs-read-chunk-size-limit SizeSuffix   If greater than --vfs-read-chunk-size, double the chunk size after each chunk read, until the limit is reached ('off' is unlimited) (default off)
      --vfs-read-wait duration                 Time to wait for in-sequence read before seeking (default 20ms)
      --vfs-used-is-size rclone size           Use the rclone size algorithm for Used size
      --vfs-write-back duration                Time to writeback files after last use when using cache (default 5s)
      --vfs-write-wait duration                Time to wait for in-sequence write before giving error (default 1s)
      --volname string                         Set the volume name (supported on Windows and OSX only)
      --write-back-cache                       Makes kernel buffer writes before sending them to rclone (without this, writethrough caching is used) (not supported on Windows)

Use "rclone [command] --help" for more information about a command.
Use "rclone help flags" for to see the global flags.
Use "rclone help backends" for a list of supported services.
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone# 







---

### 🤖 Assistant



好的，你想要实现一个 rclone mount 的调优配置，具体需求是：

1.  **挂载成功后自动获取整个目录结构：** 这样客户端访问时可以直接返回缓存数据，提高响应速度。
2.  **目录结构 10s 更新一次：** 保持目录结构的相对新鲜度。
3.  **客户端每次访问直接返回本次缓存的目录结构：** 确保客户端操作的即时性，避免频繁的远程查询。
4.  **将远程 WebDAV 挂载到本地，再通过本地 WebDAV 服务提供出去。**

根据你的需求和 `rclone mount --help` 的输出，我们可以构建一个优化的 rclone mount 命令。

### 核心概念和参数解读

为了实现你的需求，我们需要关注以下 rclone VFS (Virtual File System) 相关的参数：

*   **`--dir-cache-time duration`**: 目录条目的缓存时间。当目录缓存过期后，rclone 会重新从远程后端获取目录结构。
*   **`--poll-interval duration`**: 轮询间隔。对于支持轮询的远程后端，rclone 会在这个间隔内检查远程文件的变化并更新缓存。如果设置为 0，则禁用轮询。
*   **`--vfs-cache-mode CacheMode`**: VFS 缓存模式。这是实现本地缓存目录结构和文件数据的关键。
    *   `off`: 不缓存任何文件到本地磁盘。
    *   `minimal`: 仅将读写文件缓存到本地。
    *   `writes`: 读文件直接从远程读取，写文件和读写文件缓存到本地。
    *   `full`: 所有读写都通过本地缓存进行，并且文件以稀疏文件形式存储。
*   **`--cache-dir string`**: 指定 rclone 缓存目录的路径。
*   **`--vfs-cache-max-age duration`**: 缓存中对象的最大年龄。超过这个时间的缓存对象可能会被清理。
*   **`--vfs-cache-max-size SizeSuffix`**: 缓存的总大小限制。
*   **`--vfs-cache-poll-interval duration`**: 检查缓存中过期对象的间隔。
*   **`--vfs-fast-fingerprint`**: 使用更快的指纹识别方式，适用于 S3、Swift 等后端，可以提高缓存文件打开速度。WebDAV 可能也适用，因为它通常不支持高效的哈希获取。

### 实现你的需求

#### 1. 挂载成功后自动获取整个目录结构 + 客户端每次访问直接返回本次缓存的目录结构

为了实现这个，你需要一个足够长的 `dir-cache-time`，并且结合 `vfs-cache-mode full` 来确保所有数据（包括目录结构和文件内容）都通过本地缓存。

同时，为了在挂载后立即“预热”缓存，rclone mount 本身并没有一个直接的参数来“自动获取整个目录结构”。通常，目录结构是在第一次访问时按需加载的。但是，你可以通过在 rclone mount 命令启动后，**立即执行一个 `ls -R /path/to/mountpoint` 命令**来强制遍历整个目录，从而将目录结构加载到 VFS 目录缓存中。

#### 2. 目录结构 10s 更新一次

这可以通过设置 `dir-cache-time` 和 `poll-interval` 来实现。

*   `--dir-cache-time 10s`: 明确设置目录缓存时间为 10 秒。这样，每隔 10 秒，rclone 就会检查并更新目录结构。
*   `--poll-interval 10s`: 对于支持轮询的后端（WebDAV 通常不支持，但可以尝试设置），这会使得 rclone 每 10 秒主动检查远程变化。即使 WebDAV 不支持轮询，`dir-cache-time` 也会确保目录信息在 10 秒后刷新。

#### 3. 将远程 WebDAV 挂载到本地，再通过本地 WebDAV 服务提供出去。

这个是操作流程，不是 rclone 的参数。你需要：
1.  使用 rclone mount 将远程 WebDAV 挂载到本地 `/mnt/webdav_rclone` (举例)。
2.  在本地启动一个 WebDAV 服务器，将其根目录设置为 `/mnt/webdav_rclone`。

### 推荐的 rclone mount 参数

结合上述分析，以下是一个推荐的 rclone mount 命令，用于你的 WebDAV 场景：

```bash
# 假设你的 rclone 配置中远程 WebDAV 的名称是 "mywebdav"
# 假设你希望挂载到本地的 /mnt/mywebdav 目录
# 假设你的缓存目录是 /tmp/rclone_cache/vfs_data

rclone mount mywebdav: /mnt/mywebdav \
    --daemon \                                  # 在后台运行
    --allow-other \                             # 允许其他用户访问挂载点
    --vfs-cache-mode full \                     # 启用完整VFS缓存模式，所有读写都通过本地缓存
    --cache-dir /tmp/rclone_cache/vfs_data \    # 指定VFS缓存目录
    --dir-cache-time 10s \                      # 目录缓存时间为10秒
    --poll-interval 10s \                       # 轮询间隔为10秒（WebDAV可能不支持，但设置无害）
    --vfs-cache-max-age 24h \                   # 缓存文件在本地保留24小时（根据需求调整）
    --vfs-cache-max-size 50G \                  # 缓存总大小限制为50GB（根据可用空间调整）
    --vfs-read-chunk-size 128M \                # 每次读取的块大小
    --vfs-read-chunk-size-limit 2G \            # 块大小增长限制
    --buffer-size 128M \                        # 内存缓冲区大小
    --vfs-fast-fingerprint \                    # 使用快速指纹（推荐WebDAV）
    --log-file /var/log/rclone_mywebdav.log \   # 日志文件，方便调试
    --log-level INFO                            # 日志级别
```

**重要说明：**

1.  **替换占位符**：
    *   `mywebdav:` 替换为你的远程 WebDAV 配置名。
    *   `/mnt/mywebdav` 替换为你实际的本地挂载点（确保该目录已存在且为空）。
    *   `/tmp/rclone_cache/vfs_data` 替换为你实际的 VFS 缓存目录路径（确保有足够的磁盘空间）。
    *   `/var/log/rclone_mywebdav.log` 替换为你实际的日志文件路径。
2.  **`--allow-other`**: 如果你希望其他用户（包括你本地的 WebDAV 服务）可以访问这个挂载点，这个参数是必须的。
3.  **`--daemon`**: 让 rclone 在后台运行，释放终端。
4.  **`--vfs-cache-mode full`**: 这是实现“客户端每次访问直接返回本次缓存的目录结构”的关键，因为它会将所有读取的数据也缓存到本地。
5.  **`--vfs-cache-max-size`**: **请务必根据你本地磁盘的可用空间和需求来设置这个值。** 如果不设置或者设置过大，可能会耗尽你的磁盘空间。
6.  **预热缓存（可选但推荐）**:
    在 rclone mount 命令启动成功后（例如在你的启动脚本中），立即执行以下命令来强制遍历整个目录，从而预加载目录结构到 VFS 缓存：
    ```bash
    ls -R /mnt/mywebdav > /dev/null 2>&1 &
    # 或者对于更复杂的场景，你可以使用 find 命令
    # find /mnt/mywebdav -print > /dev/null 2>&1 &
    ```
    将这个命令放在后台运行 (`&`)，以免阻塞你的启动流程。

### 本地 WebDAV 服务

你可以使用任何支持 WebDAV 的服务器软件。以下是一些常见的选择：

*   **Caddy (推荐)**: 简单易用，配置灵活，自带HTTPS支持。
    示例 Caddyfile 配置：
    ```caddyfile
    :8080 {
        root * /mnt/mywebdav
        handle / {
            webdav
        }
    }
    ```
    然后运行 `caddy run`。
*   **Nginx (带 ngx_http_dav_module)**: 功能强大，但配置相对复杂。
*   **Apache (带 mod_dav)**: 也是一个成熟的选择。
*   **Python 的 `wsgidav`**: 如果你熟悉 Python，这是一个轻量级的选择。

### 启动脚本示例 (Bash)

你可以创建一个简单的 shell 脚本来自动化这个过程：

```bash
#!/bin/bash

# 定义变量
RCLONE_CONFIG_NAME="mywebdav"
MOUNT_POINT="/mnt/mywebdav"
VFS_CACHE_DIR="/tmp/rclone_cache/vfs_data"
LOG_FILE="/var/log/rclone_mywebdav.log"

# 确保挂载点存在且为空
mkdir -p "$MOUNT_POINT"
if [ -n "$(ls -A "$MOUNT_POINT")" ]; then
    echo "Warning: Mount point $MOUNT_POINT is not empty. Rclone mount might fail or hide existing files."
    # 可以选择在这里添加 umount 或清理逻辑
fi

# 确保缓存目录存在
mkdir -p "$VFS_CACHE_DIR"

# 启动 rclone mount
echo "Starting rclone mount..."
rclone mount "$RCLONE_CONFIG_NAME:" "$MOUNT_POINT" \
    --daemon \
    --allow-other \
    --vfs-cache-mode full \
    --cache-dir "$VFS_CACHE_DIR" \
    --dir-cache-time 10s \
    --poll-interval 10s \
    --vfs-cache-max-age 24h \
    --vfs-cache-max-size 50G \
    --vfs-read-chunk-size 128M \
    --vfs-read-chunk-size-limit 2G \
    --buffer-size 128M \
    --vfs-fast-fingerprint \
    --log-file "$LOG_FILE" \
    --log-level INFO

# 检查 rclone mount 是否成功启动
sleep 5 # 等待rclone daemon启动
if mountpoint -q "$MOUNT_POINT"; then
    echo "Rclone mount started successfully on $MOUNT_POINT."

    # 预热目录缓存
    echo "Pre-fetching directory structure..."
    ls -R "$MOUNT_POINT" > /dev/null 2>&1 &
    echo "Directory pre-fetch initiated in background."

    # 在这里添加启动本地WebDAV服务的命令，例如：
    # caddy run --config /etc/caddy/Caddyfile &
    # 或 systemctl start my-local-webdav-service
    echo "Please start your local WebDAV service, pointing to $MOUNT_POINT."

else
    echo "Rclone mount failed to start. Check logs in $LOG_FILE."
    exit 1
fi

echo "Script finished."
```

将上述脚本保存为 `start_webdav_proxy.sh` 并赋予执行权限 (`chmod +x start_webdav_proxy.sh`)。

### 进一步调优和注意事项

*   **日志监控**: 密切关注 `rclone` 的日志文件 (`--log-file`)，查看是否有错误或警告信息，特别是关于缓存、性能或连接的问题。
*   **缓存大小和清理**:
    *   `--vfs-cache-max-size` 和 `--vfs-cache-max-age` 需要根据你的磁盘空间和数据访问模式仔细调整。如果缓存满了，旧的文件会被清理。
    *   如果 rclone 意外停止，缓存中的未上传文件会在下次启动时继续上传。
*   **WebDAV 后端特性**: 某些 WebDAV 服务器可能不支持所有文件系统操作（例如，移动或重命名操作可能需要下载和重新上传）。`rclone` 会尽力模拟这些操作。
*   **并发访问**: 如果有多个客户端同时访问，确保你的本地 WebDAV 服务器和 rclone mount 配置能够处理并发。`--transfers` 参数可以控制并行上传的数量，但主要影响写操作。
*   **系统资源**: `full` 模式的 VFS 缓存会占用本地磁盘空间和一定的内存。确保你的系统有足够的资源。
*   **SIGHUP 信号**: 如果你需要立即刷新目录缓存，可以在 rclone 运行期间发送 `SIGHUP` 信号给 rclone 进程 ID。
    `kill -SIGHUP $(pidof rclone)` (如果只有一个 rclone 进程)
    或者使用 rc 命令：`rclone rc vfs/forget`
*   **WebDAV 的 `dir-cache-time` 和 `poll-interval`**: WebDAV 协议本身通常不提供文件变化的通知机制（即不支持轮询）。因此，`--poll-interval` 在 WebDAV 后端上可能效果不明显。`--dir-cache-time` 仍然是主要的目录刷新机制。如果远程 WebDAV 内容变化频繁，且你希望立即看到变化，可能需要缩短 `dir-cache-time`，但这会增加对远程的请求次数。
*   **文件权限**: `--file-perms` 和 `--dir-perms` 可以调整挂载点文件的默认权限。默认值 `0666` 和 `0777` 意味着文件和目录对所有用户可读写执行。如果你的本地 WebDAV 服务在特定用户下运行，并且遇到权限问题，你可能需要调整这些权限或使用 `--uid`/`--gid`。

通过上述配置和建议，你应该能够实现一个高效且响应迅速的 rclone WebDAV 代理方案。



---

### 🧑‍💻 User



    --vfs-read-chunk-size-limit 2G  的作用是什么？



---

### 🤖 Assistant



`--vfs-read-chunk-size-limit SizeSuffix` 参数的作用是 **限制 VFS 层在分块读取远程文件时，每次读取的块大小的最大值**。

让我们结合 `rclone mount --help` 中的解释来理解它：

> Rclone will start reading a chunk of size `--vfs-read-chunk-size`, and then double the size for each read. When `--vfs-read-chunk-size-limit` is specified, and greater than `--vfs-read-chunk-size`, the chunk size for each open file will get doubled only until the specified value is reached. If the value is "off", which is the default, the limit is disabled and the chunk size will grow indefinitely.
>
> With `--vfs-read-chunk-size 100M` and `--vfs-read-chunk-size-limit 0`
> the following parts will be downloaded: 0-100M, 100M-200M, 200M-300M, 300M-400M and so on.
> When `--vfs-read-chunk-size-limit 500M` is specified, the result would be
> 0-100M, 100M-300M, 300M-700M, 700M-1200M, 1200M-1700M and so on.

### 详细解释：

1.  **分块读取 (Chunked Reading)**: 当 rclone 从远程后端读取一个文件时，它不会一次性下载整个文件（特别是对于大文件）。它会根据需要，以“块”的形式请求文件的一部分。这有助于减少不必要的流量和 API 请求，尤其是在只读取文件某一部分时。

2.  **初始块大小 (`--vfs-read-chunk-size`)**: rclone 会从一个初始的块大小开始读取，这个大小由 `--vfs-read-chunk-size` 指定（默认 128MiB）。

3.  **块大小翻倍增长**: 随着文件的继续读取，rclone 会尝试优化读取效率。它会**将后续的读取块大小翻倍**。例如，如果初始块是 128MiB，那么下一个请求的块可能是 256MiB，再下一个是 512MiB，以此类推。这种增长策略旨在减少 API 请求的数量，同时保持较好的吞吐量。

4.  **`--vfs-read-chunk-size-limit` 的作用**:
    *   这个参数设定了**块大小翻倍增长的上限**。
    *   一旦块大小达到了 `vfs-read-chunk-size-limit` 指定的值，后续的读取块大小将不再翻倍，而是**保持在这个上限值**。
    *   如果设置为 `off` (默认值)，则表示没有上限，块大小会一直翻倍增长，直到达到文件的末尾。

### 为什么需要这个限制？

*   **内存使用控制**: 每次读取一个大块数据，都需要在内存中分配相应的缓冲区。如果块大小无限增长，可能会导致内存消耗过大，尤其是在同时打开多个大文件时。设置一个上限可以有效控制内存使用。
*   **网络带宽利用率**: 虽然更大的块通常意味着更高的吞吐量，但过大的块可能并不总是最优的。在某些网络环境下，或者对于某些后端存储，单个非常大的请求可能会导致超时、效率下降或资源分配问题。设置一个合适的上限可以平衡吞吐量和请求的稳定性。
*   **后端 API 限制**: 某些云存储服务可能对单个 API 请求的最大数据量有限制。虽然 rclone 通常会处理这些限制，但通过 `vfs-read-chunk-size-limit` 可以在更细粒度上进行控制。
*   **缓存效率**: 在 `--vfs-cache-mode full` 模式下，读取的数据会写入本地稀疏文件。如果块过大，可能导致写入本地缓存的效率下降或碎片化问题。

### 示例解释：

如果你设置：
*   `--vfs-read-chunk-size 128M`
*   `--vfs-read-chunk-size-limit 2G`

读取一个大文件时，块大小会是这样：
1.  第一个块：128M
2.  第二个块：256M
3.  第三个块：512M
4.  第四个块：1024M (1G)
5.  第五个块：2048M (2G)
6.  第六个块及以后：**2048M (2G)** (达到上限，不再翻倍)

如果没有 `vfs-read-chunk-size-limit` 或者设置为 `off`，那么块大小会继续翻倍：128M, 256M, 512M, 1G, 2G, 4G, 8G... 直到文件结束。

### 总结：

`--vfs-read-chunk-size-limit` 是一个重要的调优参数，它允许你控制 rclone 在读取大文件时，每次从远程请求的最大数据量。合理设置它可以帮助你平衡内存使用、网络效率和后端兼容性。对于大多数情况，默认的 `off` 可能是可以接受的，但如果你遇到内存问题或特定后端性能瓶颈，可以尝试设置一个合理的上限。



---

### 🧑‍💻 User



缓存到硬盘中的文件，默认会缓存整个文件吗？



---

### 🤖 Assistant



关于缓存到硬盘中的文件，是否默认会缓存整个文件，这取决于你使用的 `rclone mount` 的 `VFS Cache Mode`。

`rclone` 的 VFS (Virtual File System) 缓存有四种模式，通过 `--vfs-cache-mode` 参数设置：

1.  **`--vfs-cache-mode off` (默认模式)**
    *   **不会**将文件缓存到硬盘。
    *   读操作直接从远程后端读取数据，写操作直接写入远程后端。
    *   不适合需要随机读写、追加写入或文件内部 seek 的应用。

2.  **`--vfs-cache-mode minimal`**
    *   **只有**当文件被打开用于 **读写 (read AND write)** 时，文件内容才会被缓存到硬盘。
    *   读文件和写文件（只写）仍然直接操作远程。
    *   缓存的文件通常是整个文件，因为读写操作可能在文件任意位置发生。

3.  **`--vfs-cache-mode writes`**
    *   当文件被打开用于 **写 (write only)** 或 **读写 (read/write)** 时，文件内容会被缓存到硬盘。
    *   **读文件 (read only)** 仍然直接从远程后端读取，**不会**缓存到硬盘。
    *   缓存的文件通常是整个文件，因为写操作可能在文件任意位置发生。

4.  **`--vfs-cache-mode full`**
    *   **所有**读写操作都会通过本地硬盘缓存。
    *   当数据从远程读取时，它会被缓存到本地硬盘。
    *   当数据写入时，它首先写入本地硬盘缓存，然后异步上传到远程。
    *   **重点：在这种模式下，缓存到硬盘的文件是“稀疏文件 (sparse files)”**。
        *   这意味着，如果应用程序只读取文件的开头部分，那么 rclone 只会将开头部分的数据下载并存储到本地硬盘。
        *   虽然文件在缓存目录中会显示为其完整大小（例如，一个 10GB 的文件），但实际上只有被访问过的部分才会在磁盘上占用实际空间。
        *   如果文件被完整读取，那么整个文件的数据最终都会被缓存到本地硬盘。

### 总结：

*   **默认情况下 (`--vfs-cache-mode off`)，文件不会缓存到硬盘。**
*   如果你想让文件（或至少是其被读取/写入的部分）缓存到硬盘，你需要使用 `minimal`、`writes` 或 `full` 模式。
*   **在 `--vfs-cache-mode full` 模式下，文件在硬盘上是稀疏的。只有被实际读取/写入的部分才占用磁盘空间。** 如果一个文件被完整读取，那么它也会被完整地缓存到本地。

所以，如果你想要实现“自动获取整个目录结构，客户端每次访问直接返回本次缓存的目录结构”的效果，并希望文件内容也能尽可能地通过本地缓存提供，那么 `--vfs-cache-mode full` 是最适合的模式。它会根据实际访问情况逐步填充缓存，而不是一开始就下载整个文件。



---

### 🧑‍💻 User




root@qinglinag:/tmp/rclone_cache/vfs/123pan# tree 
.
└── rclone
    └── iso
        └── windows
            └── 26100.1.240331-1435.ge_release_CLIENT_ENTERPRISES_OEM_x64FRE_en-us.iso

4 directories, 1 file
root@qinglinag:/tmp/rclone_cache/vfs/123pan# cd rclone/iso/windows/
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# du -sh 
224M	.
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# du -sh 
224M	.
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# du -sh 
224M	.
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# 
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# 
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# du -sh 
224M	.
root@qinglinag:/tmp/rclone_cache/vfs/123pan/rclone/iso/windows# 






---

### 🤖 Assistant



你提供的 `tree` 命令输出显示了文件在本地缓存目录中的结构，以及 `du -sh` 命令显示了该目录的大小。

`tree` 命令的输出：
```
.
└── rclone
    └── iso
        └── windows
            └── 26100.1.240331-1435.ge_release_CLIENT_ENTERPRISES_OEM_x64FRE_en-us.iso

4 directories, 1 file
```
这表明在 `/tmp/rclone_cache/vfs/123pan/rclone/iso/windows/` 目录下有一个名为 `26100.1.240331-1435.ge_release_CLIENT_ENTERPRISES_OEM_x64FRE_en-us.iso` 的文件。

`du -sh` 命令的输出：
```
224M	.
```
这表示当前目录（即 `rclone/iso/windows/`）占用的磁盘空间是 224MB。

**结合你之前的问题和截图，我们可以分析：**

1.  **文件大小不匹配：**
    *   `du -sh` 显示缓存文件占用了 **224MB**。
    *   你的截图（浏览器下载界面）显示原始文件大小是 **4.2GB**。
    *   这正是 `--vfs-cache-mode full` 模式下**稀疏文件 (sparse files)** 的典型表现。

2.  **稀疏文件行为：**
    *   当你使用 `--vfs-cache-mode full` 模式时，rclone 不会立即下载整个文件到本地缓存。
    *   它会在本地创建一个与远程文件相同大小的**稀疏文件**。这个稀疏文件在文件系统层面看起来是完整大小，但实际上只有数据被实际写入的部分才占用磁盘空间。
    *   只有当有应用（例如你通过本地 WebDAV 服务下载文件时）实际读取了文件的某个部分，rclone 才会从远程下载这部分数据并将其写入本地稀疏文件的对应位置。
    *   因此，`du -sh` 命令报告的是稀疏文件在磁盘上实际占用的空间（即已下载的数据量），而不是文件的逻辑大小。224MB 的大小表明你可能只下载了文件的开头部分，或者只是读取了文件的一些元数据。

3.  **浏览器下载状态：**
    *   截图显示下载进度为 `0 B/s - 221 MB/4.2 GB`。
    *   `221 MB` 这个数字与 `du -sh` 显示的 `224M` 非常接近（MB 和 M 可能存在细微差异或四舍五入）。
    *   这进一步证实了：浏览器开始下载文件时，rclone 已经从远程下载了大约 221MB 的数据到本地缓存，并将其提供给浏览器。浏览器显示的总大小 4.2GB 是文件的真实大小，而 221MB 是当前已经缓存/下载的部分。

**结论：**

你的 `rclone mount` 配置 (`--vfs-cache-mode full`) 正在按预期工作。它利用了稀疏文件来节省本地磁盘空间，只缓存了实际被访问的文件数据。当你通过本地 WebDAV 服务下载文件时，rclone 会按需从远程 WebDAV 下载数据到本地缓存，然后再将这些数据传递给你的浏览器。`du -sh` 命令准确地反映了目前文件在缓存目录中实际占用的磁盘空间。



---

### 🧑‍💻 User



root@qinglinag:/mnt# rclone mount 123pan: /mnt/123pan/   --allow-other   --dir-cache-time 24h   --poll-interval 10s   --vfs-cache-mode full --cache-dir /tmp/rclone_cache/   --vfs-cache-max-size 20G   --vfs-cache-max-age 24h --vfs-read-ahead 64M  --vfs-read-chunk-size 64M   --vfs-read-chunk-size-limit 64M   --vfs-fast-fingerprint   --buffer-size 64M   --daemon


到了 224M 之后就停止增长了。浏览器在 0B 持续一段时间后就因为网络问题停止下载了。





---

### 🤖 Assistant



你遇到的问题是文件下载到 224MB 后就停止增长，并且浏览器提示“无法下载 - 网络问题”。这表明 rclone 在从远程 WebDAV 后端下载数据时遇到了问题。

虽然你配置了 `--vfs-cache-mode full` 来缓存数据，但如果 rclone 无法从远程成功获取到数据，即使有缓存模式也无济于事。

要诊断这个问题，我们需要查看 rclone 的日志。你之前在 `rclone mount` 命令中使用了 `--log-file /var/log/rclone_mywebdav.log` 和 `--log-level INFO`。现在，请将 `--log-level` 调整为 `DEBUG` 或 `NOTICE`，以便获取更详细的错误信息。

**第一步：修改 rclone mount 命令，增加日志级别**

请停止当前的 rclone mount 进程，然后使用以下命令重新启动，并将日志级别设置为 `DEBUG`：

```bash
# 假设你的 rclone 配置中远程 WebDAV 的名称是 "123pan"
# 假设你希望挂载到本地的 /mnt/123pan 目录
# 假设你的缓存目录是 /tmp/rclone_cache/

rclone mount 123pan: /mnt/123pan/ \
    --daemon \
    --allow-other \
    --dir-cache-time 24h \
    --poll-interval 10s \
    --vfs-cache-mode full \
    --cache-dir /tmp/rclone_cache/ \
    --vfs-cache-max-size 20G \
    --vfs-cache-max-age 24h \
    --vfs-read-ahead 64M \
    --vfs-read-chunk-size 64M \
    --vfs-read-chunk-size-limit 64M \
    --vfs-fast-fingerprint \
    --buffer-size 64M \
    --log-file /var/log/rclone_123pan.log \
    --log-level DEBUG                              # 将日志级别设置为 DEBUG
```

**第二步：复现问题并检查日志**

1.  启动上述 rclone mount 命令。
2.  通过你的本地 WebDAV 服务尝试下载那个 4.2GB 的 ISO 文件，直到它在 224MB 处停止。
3.  立即查看 `/var/log/rclone_123pan.log` 文件。你可以使用 `tail -f /var/log/rclone_123pan.log` 命令实时查看日志输出，或者在问题发生后打开文件查看。

**在日志中需要重点关注的关键字和信息：**

*   **Error / Failed / Timeout**: 查找任何错误消息，例如网络超时、连接中断、认证失败、文件读取错误等。
*   **WebDAV / HTTP 状态码**: rclone 在与 WebDAV 服务器通信时会收到 HTTP 状态码。常见的错误状态码包括：
    *   `401 Unauthorized` / `403 Forbidden`: 认证或权限问题。
    *   `404 Not Found`: 文件在远程不存在。
    *   `5xx` 系列（`500 Internal Server Error`, `502 Bad Gateway`, `503 Service Unavailable`, `504 Gateway Timeout`）：远程服务器端问题。
    *   `408 Request Timeout`: 请求超时。
*   **Retry / Backoff**: rclone 会自动重试失败的操作。查看是否有大量的重试，以及最终是否重试失败。
*   **Context canceled / Broken pipe**: 这些通常表示连接被关闭。
*   **文件路径**: 确认错误信息与你正在下载的 ISO 文件相关。

**可能的原因和初步排查方向：**

1.  **远程 WebDAV 服务本身的问题：**
    *   你的 WebDAV 服务可能对单个连接的持续时间、下载速度或并发连接数有限制。
    *   WebDAV 服务器可能在传输到一定大小后断开连接，或者在长时间无活动后超时。
    *   服务器端可能存在临时的网络波动或负载过高。
    *   **解决方案：** 尝试直接用 rclone copy/sync 命令从远程 WebDAV 下载这个文件到本地，看是否能成功下载完整文件。如果直接下载也失败，那么问题很可能在远程 WebDAV 服务端。

2.  **网络连接问题：**
    *   你的服务器到远程 WebDAV 服务之间的网络连接不稳定或存在防火墙/代理限制。
    *   长时间的连接可能会被中间网络设备（如路由器、防火墙）断开。
    *   **解决方案：** 检查你的服务器网络连接质量。尝试 ping 或 traceroute 远程 WebDAV 的地址。

3.  **rclone 配置参数问题：**
    *   你设置的 `--vfs-read-chunk-size` 和 `--vfs-read-chunk-size-limit` 都为 `64M`。这意味着 rclone 每次从远程读取文件时，最大只会请求 64MB 的块。这本身不应该导致下载中断，但如果远程 WebDAV 对这种分块读取有特殊限制，或者每次请求的开销较大，可能会导致效率低下。
    *   `--buffer-size 64M` 内存缓冲区大小，也可能影响读写效率。
    *   `--vfs-read-ahead 64M` 是在 `full` 模式下，预读到磁盘的额外数据量。
    *   **解决方案：** 尝试调整这些参数，例如将 `--vfs-read-chunk-size-limit` 设为 `off`（即不限制），或设为更大的值（例如 512M 或 1G），让 rclone 可以使用更大的块进行传输。同时可以尝试增大 `--buffer-size`。
        ```bash
        # 尝试将 chunk limit 设置为 off，并增大 buffer
        rclone mount 123pan: /mnt/123pan/ \
            --daemon \
            --allow-other \
            --dir-cache-time 24h \
            --poll-interval 10s \
            --vfs-cache-mode full \
            --cache-dir /tmp/rclone_cache/ \
            --vfs-cache-max-size 20G \
            --vfs-cache-max-age 24h \
            --vfs-read-ahead 128M \
            --vfs-read-chunk-size 128M \
            --vfs-read-chunk-size-limit off \ # 允许 chunk size 增长
            --buffer-size 128M \              # 增大内存缓冲区
            --vfs-fast-fingerprint \
            --log-file /var/log/rclone_123pan.log \
            --log-level DEBUG
        ```
    *   另外，虽然 WebDAV 通常支持 `Range` 请求（用于分块下载和续传），但某些实现可能存在 bug 或限制。

4.  **本地磁盘空间不足（可能性较低，因为只下了 224M）：**
    *   虽然你设置了 `--vfs-cache-max-size 20G`，但如果 `/tmp/rclone_cache/` 所在的磁盘分区实际可用空间不足 224MB，那也会停止。不过根据你的描述，这不太可能。

请将 `DEBUG` 级别的日志信息提供出来，这将是诊断问题的关键。

