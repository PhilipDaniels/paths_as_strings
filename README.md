# paths_as_strings

A Rust crate to unambiguously and universally encode Paths as UTF-8 strings.

Rust paths are not always convertible to UTF-8 strings because they are OS-compatible,
and neither Unix or Windows uses UTF-8 to represent paths. This presents a problem
if you want to convert a path to a string form, for example to store it in an `MRU.txt`
file. I wrote this crate to get around this problem.

This crate exports two functions, `encode_path` which converts a path to UTF-8 and its
inverse, `decode_path`, which can be used to do reverse the encoding.

Usage:

```
let encoded: String = paths_as_strings.encode_path(&the_path);
let decoded: PathBuf = paths_as_strings.decode_path(&encoded).unwrap();
```

In the (very, very) common case of a path that actually **is** a UTF-8 string this
is equivalent to calling [Path.to_str()](https://doc.rust-lang.org/std/path/struct.Path.html#method.to_str)
to encode and [PathBuf::from()](https://doc.rust-lang.org/std/path/struct.PathBuf.html#impl-From%3CString%3E) to
decode. In other words, it's no more expensive than calling the two methods you
would normally use.

In the (very, very) rare case of a path that is not valid UTF-8 - or that contains
a control character such as `\n` - then the path will be encoded as base64 and
prepended with a special prefix that signifies that the path is encoded.

The decoding can fail if the encoded string is tampered with, so `decode_path` returns
a `Result<PathBuf, base64::DecodeError>`.

# The clever bit

The clever bit it how `decode_path` is able to recognise a path that has been base64-encoded
vs. one that hasn't. For example, the string 'b478dn3hgi' may represent an encoded filename
or it may be an actual valid filename. Some way therefore has to be found to represent
encoded paths in a namespace distinct from non-encoded paths. This is done by having
`encode_path` - only when encoding is needed - return a string that cannot be a valid filename.

On Windows, there are [many](https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file)
characters that cannot be used in filenames, furthermore when using the drive-letter
syntax such as "A:\", the first character can only be A-Z. The scheme this crate uses is
to prefix base64-encoded paths with "::\\_".

On Linux, it's harder because any character other than '/' and '\0' is valid in any place in
a filename, which means that all the characters that base64 encoding uses are also valid in real
filenames. However, POSIX [specifies](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap10.html)
that `/dev/null` is a **filename**, hence not a **directory**, so you can never have files such as
`/dev/null/xyz`. The scheme this crate uses is to prefix base64-encoded paths with "/dev/null/b64_".


# Running the utilities

`paths_as_strings` comes with two utility programs.

The first is called `make_awkward_dir` and can be run with the command
`cargo run --example make_awkward_dir`. It will create a directory called 'awkward'
which contains all possible 1-byte filenames (Unix) or 2-byte filenames (Windows).
It's useful for testing that the encoding/decoding is working correctly.

The second program scans a directory looking for files that cannot be expressed
as UTF-8 and hence need to be encoded. You can run it using the command
`cargo run --example path_analyzer`. It takes one argument, a directory to start the scan
in, which defaults to the current working directory. It will print out any filenames that
need encoding and totals at the end. For example:

```
Counting paths below /home/phil/repos/paths_as_strings according to encoding needs.

Counting complete. Totals follow:
num_not_encoded = 451, num_encoded = 0
```

This means that of 451 paths found below that directory, 451 of them could
be expressed as UTF-8 strings directly, and none of them needed encoding.

When run against the entire filesystem on my Linux Mint 19 system, it prints

```
num_not_encoded = 8668563, num_encoded = 3

3 out of 8,668,566 paths needed encoding (and were successfully round-tripped).
This represents 0.000034607800182867614% of the total path count.
```

I told you it was rare. The 3 bad filenames were all for files downloaded from the
Internet, they are not part of the standard OS file payload.
