#include "CLI.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "DOG.h"
#include "abc/FILE.h"
#include "abc/PRO.h"

// Check if flag appears in the val_flags string (NUL-separated list).
// e.g. val_flags = "-g\0-C\0-r\0" (triple-NUL terminated).
static b8 cli_takes_val(char const *val_flags, u8csc flag) {
    if (val_flags == NULL) return NO;
    char const *p = val_flags;
    while (*p) {
        a_cstr(vf, p);
        if ($eq(flag, vf)) return YES;
        p += strlen(p) + 1;
    }
    return NO;
}

ok64 CLIParse(cli *c, char const *const *verb_names,
              char const *val_flags) {
    //  Caller must PATHu8bAlloc(c->repo) before invoking CLIParse
    //  (CLAUDE.md §5: alloc at the top of the call chain).
    sane(c != NULL && c->repo[0] != NULL);
    c->tty_out = isatty(STDOUT_FILENO) ? YES : NO;

    // Repo root — feed into the caller-owned path buffer.  Borrow a
    // temporary `home` just to walk up to the workspace; caller may
    // open its own home later from $path(c->repo).
    {
        home rh = {};
        uri none = {};
        if (HOMEOpen(&rh, &none, NO) == OK) {
            (void)PATHu8bFeed(c->repo, u8bDataC(rh.root));
        }
        HOMEClose(&rh);
    }

    int argn = (int)$arglen;
    int ai = 1;  // skip argv[0]

    // Verb: first arg that matches a known verb name
    if (ai < argn && verb_names != NULL) {
        a$rg(a, ai);
        for (char const *const *vn = verb_names; *vn != NULL; vn++) {
            a_cstr(vs, *vn);
            if ($eq(a, vs)) {
                $mv(c->verb, a);
                ai++;
                break;
            }
        }
    }

    // Remaining args: flags or URIs.  Every non-flag arg becomes one
    // URI via DOGNormalizeArg — bare tokens land in u->path
    // (RFC 3986 path-noscheme), whitespace-bearing args land in
    // u->fragment, and properly-shaped tokens go through the URI
    // lexer.  Verbs interpret the resulting slices: post/patch
    // demote path → ref; put/delete/bro use path as-is.  Free-form
    // text (commit messages, search strings) must be a single
    // whitespace-bearing arg (`be post "fix the typo"`) or carry
    // an explicit `#` (`be post '#fix'`); legacy `-m <msg>` still
    // works.
    u8cs empty_val = {(u8cp)"", (u8cp)""};  // non-NULL empty sentinel
    while (ai < argn) {
        a$rg(a, ai);
        ai++;

        if ($len(a) >= 1 && a[0][0] == '-') {
            if (c->nflags + 2 > CLI_MAX_FLAGS * 2) continue;

            // Check for --flag=value
            u8cs flag_part = {};
            u8cs val_part = {};
            $mv(flag_part, a);
            $for(u8c, ep, a) {
                if (*ep == '=') {
                    flag_part[1] = ep;
                    val_part[0] = ep + 1;
                    val_part[1] = a[1];
                    break;
                }
            }

            if (!$empty(val_part)) {
                // --flag=value
                $mv(c->flags[c->nflags], flag_part);
                c->nflags++;
                $mv(c->flags[c->nflags], val_part);
                c->nflags++;
            } else if (cli_takes_val(val_flags, a)) {
                // -f value (separate args) or -fN (attached)
                // Check for short flag with attached value: -XY where
                // -X takes a value and Y... is the value
                b8 attached = NO;
                if (a[0][1] != '-' && $len(a) > 2) {
                    // Short flag: -X is first 2 chars, rest is value
                    u8cs sf = {a[0], a[0] + 2};
                    if (cli_takes_val(val_flags, sf)) {
                        $mv(c->flags[c->nflags], sf);
                        c->nflags++;
                        u8cs sv = {a[0] + 2, a[1]};
                        $mv(c->flags[c->nflags], sv);
                        c->nflags++;
                        attached = YES;
                    }
                }
                if (!attached) {
                    $mv(c->flags[c->nflags], a);
                    c->nflags++;
                    if (ai < argn) {
                        a$rg(v, ai);
                        ai++;
                        $mv(c->flags[c->nflags], v);
                    } else {
                        $mv(c->flags[c->nflags], empty_val);
                    }
                    c->nflags++;
                }
            } else {
                // Boolean flag
                $mv(c->flags[c->nflags], a);
                c->nflags++;
                $mv(c->flags[c->nflags], empty_val);
                c->nflags++;
            }
        } else {
            // Non-flag arg → URI via DOGNormalizeArg.
            if (c->nuris >= CLI_MAX_URIS) {
                fprintf(stderr,
                    "cli: too many URIs (cap %u) — dropping %.*s\n",
                    (unsigned)CLI_MAX_URIS,
                    (int)$len(a), (char *)a[0]);
                continue;
            }
            uri *u = &c->uris[c->nuris];
            DOGNormalizeArg(u, a);
            $mv(u->data, a);    // restore original data slice
            c->nuris++;
        }
    }
    done;
}
