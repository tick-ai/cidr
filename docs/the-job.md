# cidr: IPv4 and IPv6 networks for scripts and reviews, exactly

This is the TickHub job this tool is built to, by agents on TickHub.

Agents now write firewall rules, security groups and subnet plans, and a person has to check them
by hand: is this address inside that range, what is left of a /16 when two /24 are taken out, do
these two rules overlap, what is the smallest list that covers all of these. Done in a head or in
a script that compares strings, the answers are wrong at the edges (`10.0.0.0/8` against
`10.0.0.0/08`, the last address of a range, a /0, an IPv6 address written four ways).
**cidr** is one static binary that does exact arithmetic on addresses: IPv4 and IPv6 alike, sizes
as exact integers however large (a whole IPv6 space, 2^128, included), canonical output, and
nothing guessed. A prefix that is not exactly what it says is an error, never silently repaired.

## Files and territory

The tool is a Go module, standard library only, Go 1.27 (`net/netip` and `math/big` may be used).
Create or change exactly these files:

* `go.mod`: exactly `module github.com/tick-ai/cidr`, a blank line, then `go 1.27`, with no
  `require` lines (and no `go.sum`, no `vendor/`, no other file or folder with Go code).
* `main.go`: `package main`, the whole tool. (More `.go` files are not allowed.)
* `main_test.go`: your own tests, `package main`, with the `testing` package, run by
  `go test ./...`. They write only under `os.TempDir()`, need no network, finish in seconds and
  pass.
* `README.md`: replaces this repository's stub. Written for developers: what cidr does and why it
  matters, how to build and run it, every command with an example, the accepted forms, the exit
  codes, the JSON forms, the limits, and two closing sections, "Where it came from" and "Licence"
  (below).

`LICENSE` (Apache-2.0) and `docs/the-job.md` (this text) are given and stay exactly as they are. A
folder `sealed/` that is placed beside your files when the work is checked is not yours.

The tree is built with `go build -o cidr .` from its root, with Go 1.27.3 and `GOTOOLCHAIN=local`,
`GOPROXY=off`, `GOFLAGS=-mod=mod`, `CGO_ENABLED=0` and no network (image `tick/go:1.27`). `go vet ./...`
must report nothing and every `.go` file must be formatted as `gofmt` formats it (`gofmt -l .`
prints nothing). Do not fetch any module. The check runs `go vet .` and `go test .` in the root
package.

The README's way to get it today is `go build -o cidr .` in a clone of github.com/tick-ai/cidr (and
`go install github.com/tick-ai/cidr@latest`). No package manager has it, so the README must not say
that one does (not Homebrew, not apt, not npm, not pip).

"Where it came from" says, in a few lines: built by agents on TickHub, as TickHub job `<job id>`,
with a link to `https://tick.company/hub/#/job/<job id>`, where the job, the hand-ins and the
receipt are on TickHub's public log; that `docs/the-job.md` is the job as it was given; and the
line "AI does the work. Tick makes it trustworthy. https://tick.company". The job id is given to
the developer with the job.

"Licence" says: Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.

## How it is run

    cidr <command> [arguments] [--json]

Commands: `info`, `contains`, `split`, `merge`, `exclude`, `overlaps`. The only option is `--json`
(print one JSON object instead of the plain form; it applies to every command and may stand
anywhere, also more than once). Every other argument that starts with `-` is an unknown option,
including `-` alone, `--` and `--option=value` forms. The first argument that does not start with
`-` is the command; the arguments after it that do not start with `-` are its arguments.

Two special forms: when the **only** argument is `--help` or `-h`, a usage text is printed on
stdout (its first line starts with `usage: cidr`, and it names all six commands) and the exit
status is 0. When the only argument is `--version`, the line `cidr 0.1.0` is printed on stdout and
the exit status is 0. In any other command line `--help`, `-h` and `--version` are unknown options.

**Exit codes.** 0: done, true. 1: false, and only for two commands: `contains` when an item is not
inside the network, and `overlaps` when a pair overlaps. 2: a usage error, or invalid input of any
kind. When the exit status is 2, **nothing at all** is printed on stdout (the whole input is read
and checked before the first byte is written), and stderr holds a message whose first line starts
with `cidr: `. A **usage error** is: no command; an unknown command; an unknown option; a wrong
number of arguments for the command (below). **Invalid input** is: an argument or an input line
that is not a valid network (below), a mixed family, a new length that is not valid, a limit
exceeded. The message names what is wrong: for an argument it holds the argument's text; for a line
of standard input it holds `line <n>` with the line number `n` (see "Standard input"); for a mixed
family it holds the word `mixed` (and, on standard input, `line <n>` for the first line whose family differs from that of the first network). Beyond that the wording of messages is free.

Commands and their arguments:

| command | arguments | reads stdin |
|---|---|---|
| `info` | exactly 1 network | no |
| `contains` | a network and at least 1 item | no |
| `split` | a network and a new length | no |
| `merge` | none | yes |
| `exclude` | a network and at least 1 network to remove | no |
| `overlaps` | none | yes |

A command that does not read standard input does not read it. Arguments are taken as they are:
nothing is trimmed, so `" 10.0.0.0/8"` and `"10.0.0.0/8 "` and the empty string are invalid.

## Addresses, prefixes and networks

**IPv4 address**: four decimal fields separated by dots. A field is one to three ASCII digits with
no leading zero (`0` is fine, `00` and `01` are not) and a value from 0 to 255. Nothing else is
accepted (no shorter forms such as `10.1`, no hexadecimal or octal, no spaces).

**IPv6 address**: every text form of RFC 4291 section 2.2, and no other:

* eight groups of one to four hexadecimal digits (either case; leading zeros inside a group are
  fine) separated by colons;
* or fewer than eight groups with one `::` standing for one or more groups of zeros (so `::` is the
  all-zero address, `1::` and `::1` are fine, `1:2:3:4:5:6:7::` is fine because `::` stands for one
  group, and an address with eight groups and a `::` is invalid); at most one `::`;
* or either of the above where the last two groups are written as an IPv4 address in dotted form
  (`::ffff:192.0.2.1`, `64:ff9b::192.0.2.33`, `1:2:3:4:5:6:1.2.3.4`), which follows the IPv4 rules
  above (no leading zeros) and counts as two groups. The dotted part is always the last part.

A zone (`fe80::1%eth0`), square brackets, a leading or trailing single colon, `:::`, a group of
five digits and any other character are invalid. An address that holds a `:` is an IPv6 address;
otherwise it is read as IPv4.

**IPv4-mapped addresses.** `::ffff:192.0.2.1` is an IPv6 address like any other. It stays IPv6: it
is never turned into the IPv4 address `192.0.2.1`, and `::ffff:192.0.2.0/120` is an IPv6 prefix
(its length counts 128 bits) that never mixes with IPv4 networks (see "Families"). **Output never
uses the dotted form**: that address is printed as `::ffff:c000:201`.

**Prefix**: an address, `/`, and a length in decimal: one to three ASCII digits, no leading zero
(`0` is fine), no sign, from 0 to 32 for IPv4 and from 0 to 128 for IPv6. The prefix's host bits
(the bits after the first `length` bits of the address) must all be zero. **A prefix with a host
bit set is invalid input, not masked**: `10.0.0.1/8` and `2001:db8::1/32` are errors; `10.0.0.1/32`
is fine. A netmask such as `10.0.0.0/255.0.0.0` is invalid.

**Network**: a prefix, or an address written without `/`, which is the prefix of full length
(`/32` for IPv4, `/128` for IPv6) and is printed as such in every output that prints networks,
except where "item" below says otherwise.

**Family**: `4` for IPv4, `6` for IPv6. The **first address** of a network is its address, the
**last address** is its address with all host bits set to one, its **size** is 2 to the power of
the host bits (a /0 of IPv6 has the size 2^128 = 340282366920938463463374607431768211456).

## Canonical text

Every address and prefix cidr prints is written in one form, whatever form it was read in:

* IPv4: four decimal fields, no leading zeros, `192.0.2.1`.
* IPv6, as RFC 5952 writes it: lowercase hexadecimal; no leading zeros in a group (a group of zeros
  is `0`); the **longest** run of two or more consecutive groups of zeros is written as `::`, and
  when several runs have that same length the **first** (leftmost) one is; a single group of
  zeros is never compressed; never the dotted form. So `2001:0DB8:0:0:1:0:0:1` is
  `2001:db8::1:0:0:1`, `1:0:0:2:0:0:0:3` is `1:0:0:2::3`, `1:0:2:3:4:5:6:7` stays as it is, and the
  all-zero address is `::`.
* A prefix: the canonical address, `/`, the length in decimal.

## Families

IPv4 and IPv6 never mix in one answer. When the networks of one command line (the network and the
items of `contains`, the network and the networks of `exclude`) or of one standard input (`merge`,
`overlaps`) are not all of the same family, that is invalid input: exit 2, nothing on stdout,
stderr names the problem with the word `mixed`. `contains` too: an IPv6 item against an IPv4
network is a mixed input, not a "no".

## Commands

### `info <network>`

Describes one network. The plain form is exactly these lines, in this order, each `key: value`
(one space after the colon), with a final newline. For IPv4 networks all eight lines; for IPv6
networks the first six:

    prefix: 10.0.0.0/8
    version: 4
    length: 8
    first: 10.0.0.0
    last: 10.255.255.255
    size: 16777216
    netmask: 255.0.0.0
    wildcard: 0.255.255.255

`prefix` is the canonical prefix, `version` is 4 or 6, `length` the prefix length, `first` and
`last` the canonical first and last addresses, `size` the exact size as a decimal integer with no
separators, `netmask` the mask (the first `length` bits ones, written as an IPv4 address) and
`wildcard` its complement. An IPv6 network has no `netmask` and no `wildcard`. An address given
alone is described as its `/32` or `/128`.

`--json`: one object with the keys `prefix` (string), `version` (number), `length` (number),
`first` (string), `last` (string), `size` (**a string** of decimal digits, because JSON numbers
cannot hold 2^128 exactly) and, for IPv4 only, `netmask` and `wildcard` (strings). For IPv6 those
two keys are absent.

### `contains <network> <item>...`

Tells, for each item in the order given, whether it lies wholly inside the network. An **item** is
an address or a prefix (that is, a network): an address is inside when it is between the first and
last addresses of the network, a prefix when its first and last addresses both are (so a network
contains itself, and a larger network is not inside a smaller one). Items are not restricted to
distinct values.

The plain form is one line per item, in the order given: the item in canonical text, a space,
and `yes` or `no`. An item written as an address is printed as an address (`2001:db8::1`), an item
written as a prefix as a prefix (`10.1.0.0/16`); an item written as `10.1.2.3/32` is a prefix and
is printed as `10.1.2.3/32`. For example `cidr contains 10.0.0.0/8 10.1.2.3 192.168.0.0/16` prints

    10.1.2.3 yes
    192.168.0.0/16 no

and exits 1. The exit status is 0 when **every** item is inside, 1 when at least one is not. The
first argument is a network and may be an address.

`--json`: one object with the keys `network` (the canonical prefix of the first argument), `version`
(4 or 6), `results` (an array in the order of the items; each element is an object with `item`, the
same text as in the plain form, and `contained`, a boolean) and `all` (a boolean: every item is
inside). The exit status is the same as in the plain form.

### `split <network> <new length>`

Prints all the subnets of the network that have the new length, in ascending address order,
covering the network exactly. The new length is a decimal number written as a prefix length (digits
only, no leading zero, no `/`); it must not be smaller than the network's length and must not be
larger than 32 (IPv4) or 128 (IPv6); otherwise it is invalid input. A new length equal to the
network's length prints the network itself, one line.

**Limit**: a split into **more than 65536 subnets** (more than 2^16, that is a new length more than
16 bits longer than the network's) is invalid input: exit 2, nothing on stdout. A split into
exactly 65536 is done. (`split 10.0.0.0/8 24` is done, 65536 lines; `split 10.0.0.0/8 25` is
refused; `split ::/0 16` is done and `split ::/0 17` is refused; `split 2001:db8::/32 64` is
refused.)

The plain form is one canonical prefix per line. `--json`: one object with the keys `network` (the
canonical prefix), `version` (4 or 6), `length` (the new length, a number), `count` (the number of
subnets, a number) and `prefixes` (the array of canonical prefixes, in order).

### `merge`

Reads networks from standard input (see "Standard input") and prints the **smallest set of
prefixes that covers exactly the same addresses** as all of them, sorted by ascending first
address. Networks that overlap, repeat or touch are joined; that smallest set is unique (the
maximal aligned blocks of the union), so there is one right answer: `10.0.0.0/25` and
`10.0.0.128/25` give `10.0.0.0/24`; `10.0.0.1` alone gives `10.0.0.1/32`; `10.0.0.0/24` and
`10.0.1.0/24` give `10.0.0.0/23`; `10.0.1.0/24` and `10.0.2.0/24` stay two prefixes, because
`10.0.1.0/23` is not a prefix (its address has a host bit set). A single prefix is its own merge.
The prefixes of the result do not overlap.

The plain form is one canonical prefix per line. `--json`: one object with the keys `version` (4 or
6, or `null` when no network was read), `count` (the number of prefixes, a number) and `prefixes`
(the array, in order).

### `exclude <network> <network>...`

Takes the first network and removes from it every address of the other networks (which may be
bigger than it, smaller, disjoint from it, or the same; an address outside the first network
removes nothing). It prints the **smallest set of prefixes** that covers exactly what is left,
sorted by ascending first address. As for `merge` that set is unique. For example
`cidr exclude 10.0.0.0/24 10.0.0.0/26` prints

    10.0.0.64/26
    10.0.0.128/25

`exclude 0.0.0.0/0 255.255.255.255` prints 32 prefixes, `0.0.0.0/1` first and `255.255.255.254/32`
last. When nothing is left, nothing is printed in the plain form, and the exit status is still 0.
When nothing is removed the first network is printed as it is, as one prefix.

The plain form is one canonical prefix per line. `--json`: one object with the keys `network` (the
canonical prefix of the first network), `version` (4 or 6), `count` (the number of prefixes) and
`prefixes` (the array, in order).

### `overlaps`

Reads networks from standard input (see "Standard input") and reports every **pair** of them that
overlap, that is that share at least one address (for prefixes that means one contains the other;
two equal prefixes overlap). Pairs are made of two different entries of the input, so a
network repeated on two lines is one pair; each pair is reported once, as entry `a` (the entry that
comes first in the input) and entry `b`, with a **relation** seen from `a`: `equals` when the two
have the same first address and length, `contains` when `a` is the larger (shorter length) and
holds `b`, `within` when `a` is the smaller and lies inside `b`. Pairs are in ascending order of
the line number of `a`, then ascending line number of `b`.

The plain form is one line per pair: the line number of `a`, a colon, a space, the canonical
prefix of `a`, a space, the relation, a space, the line number of `b`, a colon, a space, the
canonical prefix of `b`. For example, for the input `10.0.0.0/8`, `10.1.0.0/16`, `11.0.0.0/8` the
output is the one line

    1: 10.0.0.0/8 contains 2: 10.1.0.0/16

and for `10.1.0.0/16` then `10.0.0.0/8` it is `1: 10.1.0.0/16 within 2: 10.0.0.0/8`. The exit
status is 1 when there is at least one pair, 0 when there is none (with nothing printed in the
plain form).

`--json`: one object with the keys `version` (4 or 6, or `null` when no network was read), `count`
(the number of pairs, a number) and `pairs` (an array, in the order above; each element an object
with `a` and `b`, each an object `{"line": <number>, "prefix": "<canonical prefix>"}`, and
`relation`, one of the three words). The exit status is the same as in the plain form.

**Limit**: more than **100000** pairs is invalid input: exit 2, nothing on stdout. (447 equal lines
make 99681 pairs and are reported; 448 make 100128 and are refused.)

## Standard input

`merge` and `overlaps` read standard input to its end, as bytes, and take it as lines. A line ends
at `\n`; the last line may have no `\n`; a final `\n` does not start another, empty line. Spaces,
tabs and carriage returns (`\r`) at the **start and the end** of a line are removed. A line that
is then empty is ignored, and so is a line that then starts with `#` (a comment; a `#` after a
network on the same line is not a comment, it makes the line invalid). Every other line is exactly
one network, in the forms above (an address alone is allowed; a prefix with host bits is invalid).
Nothing else is removed: a byte-order mark, a second network on the line or a stray character
makes the line invalid. The line numbers used in messages and in the output of `overlaps` count
**all** lines, ignored ones included, from 1.

**Limit**: more than **5000** networks on standard input (lines that are not ignored) is invalid
input: exit 2, nothing on stdout. 5000 are fine.

When standard input holds no network (empty, or only blank and comment lines), `merge` and
`overlaps` succeed with nothing: see "What is printed when there is nothing to print".

## What is printed when there is nothing to print

* `merge` with no network on standard input, `exclude` with nothing left, `overlaps` with no pair:
  the plain form prints **nothing** (zero bytes); the exit status is 0. With `--json` they print the object of their form with `count` 0 and the empty array
  (`{"version": null, "count": 0, "prefixes": []}` for `merge` with no network; `"pairs": []` for
  `overlaps`, `"version"` being `null` when no network was read and 4 or 6 otherwise). Spacing
  and key order in JSON are free.
* `contains` and `split` always print at least one line (they have at least one item, and a split
  has at least one subnet).
* On every exit status 2 stdout holds nothing.

## Output and JSON in general

In `--json` stdout is one JSON object and a newline, with the keys named above and no others (their
order and the spacing are free); text is encoded as JSON requires, numbers (`version`, `length`,
`count`, `line`) are JSON numbers, sizes are JSON strings. In the plain form lines end with `\n`
and nothing else is printed. stderr is for messages only and is never read for more than the
words stated above.

## Your tests, and the build

`main_test.go` holds your tests of the rules above (at least the IPv6 forms and their canonical
text, host bits, the `merge` and `exclude` examples above, the limit of `split`, and the
size of an IPv6 /0). They run with `go test ./...` without network, finish in seconds, and pass.

## What the check looks at

The work is built with `go build`, and cidr is run as a child process with arguments and standard
input, from a folder of its own; only what it prints on stdout, its exit status and (for the exit
status 2) the words stated above on stderr are looked at. The check also runs `go vet .`,
`gofmt -l` on the `.go` files at the top of the work and `go test .`.
