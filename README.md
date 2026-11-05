# cidr

**cidr does exact arithmetic on IPv4 and IPv6 networks: is this inside that, what is left when I take
this out, what is the smallest list that covers all of these, do these two overlap.**

    cidr <command> [arguments] [--json]

```
$ cidr exclude 10.0.0.0/24 10.0.0.0/26
10.0.0.64/26
10.0.0.128/25

$ cidr contains 10.0.0.0/8 10.1.2.3 192.168.0.0/16
10.1.2.3 yes
192.168.0.0/16 no
$ echo $?
1

$ printf '10.0.0.0/25\n10.0.0.128/25\n' | cidr merge
10.0.0.0/24

$ cidr info ::/0 --json
{"prefix":"::/0","version":6,"length":0,"first":"::","last":"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff","size":"340282366920938463463374607431768211456"}
```

## Why it matters

Agents now write firewall rules, security groups and subnet plans, and a person has to check them. Done
in a head, or in a script that compares strings, the answers are wrong at the edges: `10.0.0.0/8`
against `10.0.0.0/08`, the last address of a range, a /0, an IPv6 address written four ways.

cidr is one static binary with nothing but the Go standard library. It counts exactly (sizes are exact
integers, a whole IPv6 space, 2^128, included), it prints one canonical text for every address, and it
guesses nothing: a prefix that is not exactly what it says (`10.0.0.1/8`) is an error, never silently
repaired. Exit codes and `--json` make it fit for scripts and for reviews.

## Build and run

You need Go 1.27 or later. From a clone of github.com/tick-ai/cidr:

    go build -o cidr .
    ./cidr info 10.0.0.0/8

or

    go install github.com/tick-ai/cidr@latest

cidr is not in any package manager.

## Commands

    cidr <command> [arguments] [--json]

`--json` is the only option: it prints one JSON object instead of the plain form, works with every
command and may stand anywhere, also more than once. Every other argument that starts with `-`
(including `-` alone, `--` and `--option=value`) is an unknown option. The first argument that does not
start with `-` is the command. `cidr --help` (or `-h`) and `cidr --version` work only as the sole
argument.

### info

`cidr info <network>` describes one network.

```
$ cidr info 10.0.0.0/8
prefix: 10.0.0.0/8
version: 4
length: 8
first: 10.0.0.0
last: 10.255.255.255
size: 16777216
netmask: 255.0.0.0
wildcard: 0.255.255.255
```

IPv6 networks print the first six lines (no `netmask`, no `wildcard`). An address given alone is its
`/32` or `/128`.

### contains

`cidr contains <network> <item>...` tells for each item, in order, whether it lies wholly inside the
network. An item is an address or a prefix; a prefix is inside when its first and last addresses both
are, so a network contains itself and a larger network is not inside a smaller one. Items are printed
as they were written (an address as an address, a prefix as a prefix), in canonical text. Exit status 0
when every item is inside, 1 when one is not.

```
$ cidr contains 2001:db8::/32 2001:DB8:0:0:0:0:0:1 2001:db8:1::/48 ::ffff:192.0.2.1
2001:db8::1 yes
2001:db8:1::/48 yes
::ffff:c000:201 no
```

An item of the other family is invalid input (mixed), not a "no".

### split

`cidr split <network> <new length>` prints all the subnets of the new length, in address order. The new
length is digits only, not smaller than the network's length and not larger than 32 (IPv4) or 128
(IPv6). A split into more than 65536 subnets is refused (`split 10.0.0.0/8 24` is done, `split
10.0.0.0/8 25` is not; `split ::/0 16` is done, `split ::/0 17` is not).

```
$ cidr split 10.0.0.0/24 26
10.0.0.0/26
10.0.0.64/26
10.0.0.128/26
10.0.0.192/26
```

### merge

`cidr merge` reads networks from standard input and prints the smallest set of prefixes that covers
exactly the same addresses, sorted by address. Overlapping, repeated and adjacent networks are joined.
The result is unique.

```
$ printf '10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n' | cidr merge
10.0.0.0/23
10.0.2.0/24
```

(`10.0.1.0/24` and `10.0.2.0/24` stay two prefixes: `10.0.1.0/23` is not a prefix.)

### exclude

`cidr exclude <network> <network>...` removes every address of the other networks from the first and
prints the smallest set of prefixes that covers what is left, sorted. The networks to remove may be
bigger, smaller, disjoint or the same. When nothing is left nothing is printed and the exit status is 0;
when nothing is removed the first network is printed as it is.

```
$ cidr exclude 10.0.0.0/16 10.0.0.0/24 10.0.2.0/24
10.0.1.0/24
10.0.3.0/24
10.0.4.0/22
10.0.8.0/21
10.0.16.0/20
10.0.32.0/19
10.0.64.0/18
10.0.128.0/17
```

### overlaps

`cidr overlaps` reads networks from standard input and reports every pair that shares an address, once,
as `<line of a>: <a> <relation> <line of b>: <b>`, where `a` is the entry that comes first, and the
relation seen from `a` is `equals`, `contains` or `within`. Pairs are ordered by the line of `a`, then
the line of `b`. Line numbers count every line, blank and comment lines included. Exit status 1 when
there is at least one pair, 0 when there is none.

```
$ printf '10.0.0.0/8\n10.1.0.0/16\n11.0.0.0/8\n' | cidr overlaps
1: 10.0.0.0/8 contains 2: 10.1.0.0/16
```

## Accepted forms

* **IPv4 address**: four decimal fields separated by dots, each one to three digits with no leading
  zero (`0` is fine, `01` is not), 0 to 255. No short forms (`10.1`), no hexadecimal, no octal.
* **IPv6 address**: every text form of RFC 4291 section 2.2: eight groups of one to four hexadecimal
  digits (either case); or fewer groups with one `::` standing for one or more groups of zeros; or
  either of these with the last two groups written as an IPv4 address (`::ffff:192.0.2.1`,
  `64:ff9b::192.0.2.33`). No zones (`%eth0`), no square brackets, no `:::`. An address that holds a `:`
  is IPv6, otherwise it is IPv4.
* **IPv4-mapped addresses** stay IPv6: `::ffff:192.0.2.1` is never turned into `192.0.2.1`, and
  `::ffff:192.0.2.0/120` is an IPv6 prefix that never mixes with IPv4 networks. Output never uses the
  dotted form: it is printed `::ffff:c000:201`.
* **Prefix**: an address, `/`, and a length of one to three digits with no leading zero and no sign
  (0 to 32 for IPv4, 0 to 128 for IPv6). The host bits (after the first `length` bits) must all be
  zero: `10.0.0.1/8` and `2001:db8::1/32` are invalid, `10.0.0.1/32` is fine. `10.0.0.0/08` and
  `10.0.0.0/255.0.0.0` are invalid.
* **Network**: a prefix, or an address alone, which is the prefix of full length.

Arguments are taken as they are: `" 10.0.0.0/8"`, `"10.0.0.0/8 "` and the empty string are invalid.

### Canonical text

Whatever form was read, cidr prints IPv4 as four decimal fields and IPv6 as RFC 5952 writes it:
lowercase, no leading zeros in a group, the longest run of two or more zero groups written `::` (the
leftmost when several are as long), a single zero group never compressed, never dotted.
`2001:0DB8:0:0:1:0:0:1` is `2001:db8::1:0:0:1`; `1:0:0:2:0:0:0:3` is `1:0:0:2::3`. Prefixes are
`address/length`.

### Standard input (`merge` and `overlaps`)

Standard input is read to its end and taken as lines. A line ends at `\n`; the last may have no `\n`.
Spaces, tabs and carriage returns at the start and end of a line are removed. A line that is then empty,
or starts with `#`, is ignored (a `#` after a network makes the line invalid). Every other line is one
network. Nothing else is removed: a byte-order mark or a second network on a line makes it invalid.
Line numbers count all lines, ignored ones included, from 1.

## Exit codes

| code | meaning |
|---|---|
| 0 | done, true |
| 1 | false: `contains` when an item is not inside, `overlaps` when a pair overlaps |
| 2 | usage error or invalid input |

On exit status 2 nothing at all is printed on stdout (the whole input is read and checked before the
first byte is written) and stderr holds a message whose first line starts with `cidr: `. It names what
is wrong: the argument's text, `line <n>` for a line of standard input, the word `mixed` for IPv4 and
IPv6 in one run. A usage error is no command, an unknown command, an unknown option or a wrong number of
arguments. Invalid input is a bad network, a mixed family, a bad new length or a limit exceeded.

## JSON forms

With `--json`, stdout is one JSON object and a newline. Sizes are strings of decimal digits because JSON
numbers cannot hold 2^128 exactly.

| command | keys |
|---|---|
| `info` | `prefix`, `version` (number), `length` (number), `first`, `last`, `size` (string), and for IPv4 only `netmask`, `wildcard` |
| `contains` | `network`, `version`, `results` (array of `{"item", "contained"}`), `all` (boolean) |
| `split` | `network`, `version`, `length` (the new length), `count`, `prefixes` |
| `merge` | `version` (4, 6 or `null` when no network was read), `count`, `prefixes` |
| `exclude` | `network`, `version`, `count`, `prefixes` |
| `overlaps` | `version` (4, 6 or `null`), `count`, `pairs` (array of `{"a": {"line", "prefix"}, "b": {"line", "prefix"}, "relation"}`) |

```
$ cidr contains 10.0.0.0/8 10.1.2.3 192.168.0.0/16 --json
{"network":"10.0.0.0/8","version":4,"results":[{"item":"10.1.2.3","contained":true},{"item":"192.168.0.0/16","contained":false}],"all":false}

$ printf '' | cidr merge --json
{"version":null,"count":0,"prefixes":[]}
```

The exit status is the same as in the plain form.

## Limits

* `split`: at most 65536 subnets.
* `merge`, `overlaps`: at most 5000 networks on standard input (blank and comment lines are not counted).
* `overlaps`: at most 100000 pairs (447 equal lines make 99681 pairs and are reported; 448 make 100128
  and are refused).

## Tests

    go vet ./...
    go test ./...

The tests build the binary and run it as a child process.

## Where it came from

Built by agents on TickHub, as TickHub job `41aea32b-9baf-4fb7-be51-51ee3ec9b686`. The job, the
hand-ins and the receipt are on TickHub's public log:
https://tick.company/hub/#/job/41aea32b-9baf-4fb7-be51-51ee3ec9b686

`docs/the-job.md` is the job as it was given.

AI does the work. Tick makes it trustworthy. https://tick.company

## Licence

Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.
