#include "QURY.h"
#include <string.h>

%%{
    machine qury;

    action body_start  { body_mark = p; }
    action body_end    { out->body[0] = body_mark; out->body[1] = p; }
    action anc_tilde   { out->anc_type = '~'; }
    action anc_caret   { out->anc_type = '^'; }
    action anc_digit   { out->ancestry = out->ancestry * 10 + (*p - '0'); }
    action rel_down    { out->rel = QURY_REL_DOWN; }
    action rel_up      { out->rel = QURY_REL_UP; }

    atom     = alnum | [_\-] ;
    seg      = atom+ ('.' atom+)* ;
    pathbody = seg ('/' seg)* ;

    ancestry = ( '~' @anc_tilde | '^' @anc_caret ) ( digit @anc_digit )* ;

    #  Relative-prefix forms.  `./` and `../` introduce a body;
    #  bare `..` is parent-only with an empty body.
    reldown  = ( '.' '/' ) %rel_down ;
    relup    = ( '.' '.' '/' ) %rel_up ;
    relbare  = ( '.' '.' ) %rel_up ;

    spec = ( reldown pathbody >body_start %body_end ancestry? )
         | ( relup   pathbody >body_start %body_end ancestry? )
         | ( pathbody >body_start %body_end ancestry? )
         | relbare ;

    main := spec ;
}%%

%% write data nofinal noerror;

static b8 qury_is_sha(u8cs s) {
    if ($len(s) < QURY_MIN_SHA) return NO;
    $for(u8c, p, s) {
        u8 c = *p;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'))
            continue;
        return NO;
    }
    return YES;
}

ok64 QURYu8sDrain(u8cs input, qrefp out) {
    if (out == NULL) return QURYBAD;
    memset(out, 0, sizeof(qref));
    if (input[0] == NULL || input[0] >= input[1]) return OK;

    // Find the end of this spec (up to '&' or end of input)
    u8cp specend = input[0];
    while (specend < input[1] && *specend != '&') specend++;

    //  Empty spec between separators (e.g. leading `&` in a query
    //  query like `&<sha>`, or two `&&` in a row).  Don't run ragel
    //  on a zero-length range — it would never reach a final state
    //  and we'd report QURYFAIL, breaking callers that walk the
    //  separator chain (POST's parent collector relies on getting
    //  QURY_NONE for empties so it can keep draining).
    if (specend == input[0]) {
        input[0] = (specend < input[1]) ? specend + 1 : specend;
        return OK;     // out->type already QURY_NONE from memset.
    }

    u8cp p = input[0];
    u8cp pe = specend;
    u8cp eof = pe;
    u8cp body_mark = NULL;
    int cs = 0;

    %% write init;
    %% write exec;

    // Advance input past spec and separator
    input[0] = (specend < input[1]) ? specend + 1 : specend;

    if (cs < %%{ write first_final; }%%)
        return QURYFAIL;

    out->type = qury_is_sha(out->body) ? QURY_SHA : QURY_REF;
    return OK;
}

ok64 QURYBuildAbsolute(u8bp out, qrefcp spec, u8cs current) {
    if (out == NULL || spec == NULL) return QURYBAD;
    if (spec->type != QURY_REF) return QURYFAIL;

    if (spec->rel == QURY_REL_NONE) {
        if (!$empty(spec->body))
            u8bFeed(out, spec->body);
        return OK;
    }

    //  parent_len: index of the byte after the parent's last char.
    //  For QURY_REL_DOWN, parent = current (full).  For
    //  QURY_REL_UP, parent = dirname(current) — bytes up to (but
    //  not including) the last '/' in current; 0 if no '/' (which
    //  means current is a top-level branch and parent is trunk).
    u32 parent_len = 0;
    if (spec->rel == QURY_REL_DOWN) {
        parent_len = (u32)$len(current);
    } else {
        // QURY_REL_UP
        if ($empty(current)) {
            parent_len = 0;
        } else {
            u8cp last_slash = NULL;
            $for(u8c, p, current)
                if (*p == '/') last_slash = p;
            parent_len = last_slash
                ? (u32)(last_slash - current[0])
                : 0;
        }
    }

    if (parent_len > 0) {
        u8cs pfx = {current[0], current[0] + parent_len};
        u8bFeed(out, pfx);
    }

    if (!$empty(spec->body)) {
        if (parent_len > 0) u8bFeed1(out, '/');
        u8bFeed(out, spec->body);
    }

    return OK;
}
