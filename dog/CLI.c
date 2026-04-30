#include "CLI.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "DOG.h"
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

// URI-shaped iff the token contains `/`, `?`, `#`, `.`, OR is a
// 40-char hex SHA, OR has a `:` whose prefix is a known scheme.
// `:` alone is not enough: prose colons like `cli:` (conventional-
// commit prefixes, "note:", etc.) should kick off the fragment-tail,
// not be misparsed as scp-like host:path.  Known schemes come from
// dog/DOG.{h,c} (DOG_PROJECTORS + DOG_TRANSPORTS) — single source of
// truth, no parallel list maintained here.
static b8 cli_uri_shaped(u8csc a) {
    b8 hex_only = ($len(a) == 40);
    u8cp first_colon = NULL;
    $for(u8c, p, a) {
        u8 c = *p;
        if (c == '/' || c == '?' || c == '#' || c == '.') return YES;
        if (c == ':' && first_colon == NULL) first_colon = p;
        if (hex_only && !((c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F'))) hex_only = NO;
    }
    if (hex_only) return YES;
    if (first_colon != NULL) {
        u8cs scheme = {a[0], first_colon};
        if (DOGIsProjector(scheme) || DOGIsTransport(scheme)) return YES;
    }
    return NO;
}

// Append `a` to c->_tail, prefixed with a separator if the buffer is
// non-empty.  Truncates silently on overflow — the buffer is sized for
// commit messages, not novels.
static void cli_tail_append(cli *c, u8csc a) {
    size_t cap = sizeof(c->_tail);
    if (c->_tail_len > 0 && c->_tail_len + 1 < cap) {
        c->_tail[c->_tail_len++] = ' ';
    }
    size_t alen = (size_t)$len(a);
    if (c->_tail_len + alen >= cap) alen = cap - 1 - c->_tail_len;
    if (alen == 0) return;
    memcpy(c->_tail + c->_tail_len, a[0], alen);
    c->_tail_len += (u32)alen;
}

ok64 CLIParse(cli *c, char const *const *verb_names,
              char const *val_flags) {
    sane(c != NULL);
    *c = (cli){};
    c->tty_out = isatty(STDOUT_FILENO) ? YES : NO;

    // Repo root — copy into owned storage.  Borrow a temporary `home`
    // just to walk up to the workspace; caller may open its own home
    // later from c->repo.
    {
        home rh = {};
        uri none = {};
        if (HOMEOpen(&rh, &none, NO) == OK) {
            size_t rlen = u8bDataLen(rh.root);
            if (rlen >= sizeof(c->_repo)) rlen = sizeof(c->_repo) - 1;
            memcpy(c->_repo, u8bDataHead(rh.root), rlen);
            c->_repo[rlen] = 0;
            c->repo[0] = (u8cp)c->_repo;
            c->repo[1] = (u8cp)c->_repo + rlen;
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

    // Remaining args: flags, URIs, or — once the first non-flag
    // non-URI-shaped arg appears — fragment-tail.  In tail mode,
    // every remaining arg (including those starting with '-') is
    // joined with ' ' into c->_tail; flags lose precedence so a
    // commit message can contain `-Wall` without escaping.
    u8cs empty_val = {(u8cp)"", (u8cp)""};  // non-NULL empty sentinel
    b8 tail_mode = NO;
    while (ai < argn) {
        a$rg(a, ai);
        ai++;

        if (tail_mode) {
            cli_tail_append(c, a);
            continue;
        }

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
        } else if (cli_uri_shaped(a)) {
            // URI: has a structural sigil (one of /.:?#).  Hand to
            // DOGNormalizeArg for full classification.
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
        } else {
            // Bare token — start fragment-tail.  Subsequent args (any
            // shape) feed the tail until argv is exhausted.
            tail_mode = YES;
            cli_tail_append(c, a);
        }
    }

    // Materialize the tail as a synthetic URI with just the fragment.
    // Goes into a fresh slot so an existing path/ref URI keeps its
    // identity — sniff/keeper iterate uris[] looking for the first
    // non-empty fragment when they need a commit message etc.
    if (c->_tail_len > 0 && c->nuris < CLI_MAX_URIS) {
        uri *u = &c->uris[c->nuris++];
        memset(u, 0, sizeof(*u));
        u8cp tail_p = (u8cp)c->_tail;
        u->data[0]     = tail_p;
        u->data[1]     = tail_p + c->_tail_len;
        u->fragment[0] = tail_p;
        u->fragment[1] = tail_p + c->_tail_len;
    }
    done;
}
