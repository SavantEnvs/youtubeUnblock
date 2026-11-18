# Bundled getopt scans past the end of optstring for an unrecognised short option

**Cause.** `src/getopt.c` `getopt()` looks the option character up with
`do { d = optstring[i], l = 1; if (l>0) i+=l; else i++; } while (l && d != c);`. `l` is always 1, so the loop
only ends when `d == c`; for a character that is not in the option string it walks off the end of
`optstring`. `yparse_args` passes the empty string `""` (`src/args.c:558`), so the very first lookup already
reads past it (`getopt.c:85`).

**Impact.** Out-of-bounds global read on any unknown short option on the command line (`youtubeUnblock -a`),
which on a stock build means a one-character typo reads adjacent globals and can crash or loop.

**Fix.** Stop at the terminator: `l = d ? 1 : 0` (or `while (d && d != c)`), so an unknown option falls
through to the existing `'?'` return.

Run: `/mayhem/fuzz_args-standalone repro-minimal` (the input is the two bytes `-a`).
