//  IGNO: .gitignore parser and matcher using cc/PATH
//
#include "IGNO.h"

#include <string.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"

static a_cstr(GITIGNORE_NAME, ".gitignore");

// Gitignore-style glob: * matches non-/, ** matches everything, ? matches one
static b8 IGNOGlob(u8cs pat, u8cs str) {
    u8cp pp = pat[0], pe = pat[1];
    u8cp sp = str[0], se = str[1];
    while (pp < pe && sp < se) {
        if (*pp == '*') {
            if (pp + 1 < pe && pp[1] == '*') {
                pp += 2;
                if (pp < pe && *pp == '/') pp++;
                // ** matches everything including /
                for (u8cp try = sp; try <= se; try++) {
                    u8cs rp = {pp, pe}, rs = {try, se};
                    if (IGNOGlob(rp, rs)) return YES;
                }
                return NO;
            }
            pp++;
            // * matches anything except /
            for (u8cp try = sp; try <= se; try++) {
                u8cs rp = {pp, pe}, rs = {try, se};
                if (IGNOGlob(rp, rs)) return YES;
                if (try < se && *try == '/') break;
            }
            return NO;
        }
        if (*pp == '?') {
            if (*sp == '/') return NO;
            pp++;
            sp++;
            continue;
        }
        if (*pp != *sp) return NO;
        pp++;
        sp++;
    }
    while (pp < pe && *pp == '*') pp++;
    return pp == pe && sp == se;
}

// Try to match pattern against path
static b8 TryMatch(igno_pat const *pat, u8cs path, b8 is_dir) {
    // Directory-only patterns don't match files
    if (pat->dir_only && !is_dir) return NO;

    u8cs pattern;
    u8csDup(pattern, pat->pattern);
    if ($empty(pattern)) return NO;

    // Strip leading / from pattern for matching (we handle anchoring separately)
    u8cs match_pattern;
    u8csDup(match_pattern, pattern);
    if (!$empty(match_pattern) && *match_pattern[0] == '/') {
        match_pattern[0]++;
    }

    // If pattern has no slash and is not anchored, match against basename only
    // (gitignore rule: patterns without / match anywhere in the tree)
    if (!pat->has_slash && !pat->anchored) {
        u8cs basename = {};
        PATHu8sBase(basename, (path8s){path[0], path[1]});
        return IGNOGlob(match_pattern, basename);
    }

    // Pattern has slash or is anchored - match against full path
    // For anchored patterns, path must match from root
    // For unanchored patterns with slash, pattern can match at any level

    u8cs match_path;
    u8csDup(match_path, path);

    // Skip leading / in path for comparison
    if (!$empty(match_path) && *match_path[0] == '/') {
        match_path[0]++;
    }

    if (pat->anchored) {
        // Anchored: must match from root
        return IGNOGlob(match_pattern, match_path);
    }

    // Unanchored with slash: try matching at each directory level
    // e.g., "foo/bar" should match "x/foo/bar" or "y/z/foo/bar"
    u8cs try_path;
    u8csDup(try_path, match_path);

    while (!$empty(try_path)) {
        if (IGNOGlob(match_pattern, try_path)) {
            return YES;
        }
        // Move to next component
        while (!$empty(try_path) && *try_path[0] != '/') {
            try_path[0]++;
        }
        if (!$empty(try_path) && *try_path[0] == '/') {
            try_path[0]++;
        }
    }

    return NO;
}

ok64 IGNOLoad(ignop out, u8cs dir_path) {
    sane(out && u8csOK(dir_path));
    memset(out, 0, sizeof(*out));

    // Build path to .gitignore
    a_path(gi_path);
    call(u8sFeed, u8bIdle(gi_path), dir_path);
    call(PATHu8bTerm, gi_path);
    call(PATHu8bPush, gi_path, GITIGNORE_NAME);

    // Try to load file
    ok64 o = FILEMapRO(&out->buf, $path(gi_path));
    if (o != OK) {
        // No .gitignore - not an error
        return NONE;
    }

    // Save root directory
    u8csDup(out->root, dir_path);

    // Parse patterns
    u8cs data;
    u8csDup(data, u8bDataC(out->buf));

    while (!$empty(data) && out->count < IGNO_MAX_PATTERNS) {
        // Skip leading whitespace (but not newlines)
        while (!$empty(data) && (**data == ' ' || **data == '\t')) {
            data[0]++;
        }

        // Find end of line
        u8cp line_start = *data;
        while (!$empty(data) && **data != '\n' && **data != '\r') {
            data[0]++;
        }
        u8cp line_end = *data;

        // Skip newline
        while (!$empty(data) && (**data == '\n' || **data == '\r')) {
            data[0]++;
        }

        // Skip blank lines
        if (line_start == line_end) continue;

        // Trim trailing whitespace
        while (line_end > line_start && (line_end[-1] == ' ' || line_end[-1] == '\t')) {
            line_end--;
        }

        // Skip comment lines
        if (*line_start == '#') continue;

        // Parse pattern
        igno_pat *pat = &out->patterns[out->count];
        memset(pat, 0, sizeof(*pat));

        u8cp p = line_start;

        // Check for negation
        if (*p == '!') {
            pat->negated = YES;
            p++;
        }

        // Check for anchor
        if (*p == '/') {
            pat->anchored = YES;
        }

        // Check for trailing / (directory only)
        if (line_end > p && line_end[-1] == '/') {
            pat->dir_only = YES;
            line_end--;  // Trim from pattern
        }

        // Check if pattern contains / (besides leading/trailing)
        for (u8cp c = p; c < line_end; c++) {
            if (*c == '/' && c != p) {
                pat->has_slash = YES;
                break;
            }
        }

        // Store pattern
        pat->pattern[0] = p;
        pat->pattern[1] = line_end;

        out->count++;
    }

    done;
}

void IGNOFree(ignop ig) {
    if (!ig) return;
    if (ig->buf && ig->buf[0]) {
        u8bUnMap(ig->buf);
    }
    memset(ig, 0, sizeof(*ig));
}

//  Hardcoded metadata: .git / .dogs / .sniff are always ignored,
//  whether or not a .gitignore is loaded.  Every dog's wt-scan
//  callbacks pass through IGNOMatch, so this one check keeps
//  internal state (git's .git, keeper's .dogs, sniff's .sniff ULOG)
//  out of diff / status / post / patch worktree passes.
//
//  Matches at ANY directory level — `.git/` at the wt root and a
//  submodule's nested `.git/` are equally ignored, so a submodule's
//  internal git-state never surfaces as untracked.
static b8 igno_is_meta(u8cs rel) {
    if ($empty(rel)) return NO;
    static char const *const metas[] = {".git", ".dogs", ".sniff"};
    u8cp seg = rel[0];
    while (seg < rel[1]) {
        u8cp end = seg;
        while (end < rel[1] && *end != '/') end++;
        size_t sl = (size_t)(end - seg);
        for (u32 i = 0; i < sizeof(metas) / sizeof(metas[0]); i++) {
            size_t ml = strlen(metas[i]);
            if (sl == ml && memcmp(seg, metas[i], ml) == 0)
                return YES;
        }
        seg = (end < rel[1]) ? end + 1 : end;
    }
    return NO;
}

//  Apply every pattern (last-match-wins) to a single path/is_dir pair.
//  Caller controls iteration over the path's parent prefixes — see
//  IGNOMatch.  Splitting this out avoids re-checking already-tested
//  prefixes when we walk up the tree.
static b8 igno_match_one(ignocp ig, u8cs path, b8 is_dir) {
    b8 ignored = NO;
    for (u64 i = 0; i < ig->count; i++) {
        igno_pat const *pat = &ig->patterns[i];
        if (TryMatch(pat, path, is_dir)) ignored = !pat->negated;
    }
    return ignored;
}

b8 IGNOMatch(ignocp ig, u8cs rel_path, b8 is_dir) {
    if ($empty(rel_path)) return NO;
    if (igno_is_meta(rel_path)) return YES;
    if (!ig || ig->count == 0) return NO;

    //  First, the path itself — covers file patterns and dir patterns
    //  applied to the dir entry.
    if (igno_match_one(ig, rel_path, is_dir)) return YES;

    //  Git semantics: a `dir/` pattern that matches any parent of this
    //  path also ignores everything beneath, including files.  Walk
    //  every prefix `a`, `a/b`, … with is_dir=YES so directory-only
    //  patterns can fire.  Stops short of the full path (already
    //  tested above).  Negations on parents intentionally don't
    //  un-ignore descendants here — that's the same shortcut git takes.
    for (u8cp p = rel_path[0]; p < rel_path[1]; p++) {
        if (*p != '/') continue;
        u8cs prefix = {rel_path[0], p};
        if (igno_match_one(ig, prefix, YES)) return YES;
    }
    return NO;
}
