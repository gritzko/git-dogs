#include "HUNK.h"

#include "abc/PRO.h"
#include "dog/FRAG.h"
#include "dog/TOK.h"

ok64 HUNKu8sFeed(u8s into, hunk const *hk) {
    sane(u8sOK(into) && hk != NULL);
    u8s inner = {};
    call(TLVu8sStart, into, inner, HUNK_TLV);
    if (!$empty(hk->uri))
        call(TLVu8sFeed, inner, HUNK_TLV_URI, hk->uri);
    if (!$empty(hk->text))
        call(TLVu8sFeed, inner, HUNK_TLV_TXT, hk->text);
    if (!$empty(hk->toks)) {
        u8cs tkb = {(u8cp)hk->toks[0], (u8cp)hk->toks[1]};
        call(TLVu8sFeed, inner, HUNK_TLV_TOK, tkb);
    }
    if (!$empty(hk->hili)) {
        u8cs hib = {(u8cp)hk->hili[0], (u8cp)hk->hili[1]};
        call(TLVu8sFeed, inner, HUNK_TLV_HILI, hib);
    }
    call(TLVu8sEnd, into, inner, HUNK_TLV);
    done;
}

ok64 HUNKu8sDrain(u8cs from, hunk *hk) {
    sane($ok(from) && hk != NULL);
    u8 t = 0;
    u8cs body = {};
    call(TLVu8sDrain, from, &t, body);
    test(t == HUNK_TLV, TLVBADTYPE);
    *hk = (hunk){};
    while (!$empty(body)) {
        u8 st = 0;
        u8cs val = {};
        call(TLVu8sDrain, body, &st, val);
        switch (st) {
        case HUNK_TLV_URI:
            $mv(hk->uri, val);
            break;
        case HUNK_TLV_TXT:
            $mv(hk->text, val);
            break;
        case HUNK_TLV_TOK:
            hk->toks[0] = (tok32c *)val[0];
            hk->toks[1] = (tok32c *)val[1];
            break;
        case HUNK_TLV_HILI:
            hk->hili[0] = (tok32c *)val[0];
            hk->hili[1] = (tok32c *)val[1];
            break;
        default:
            break;
        }
    }
    done;
}

ok64 HUNKu8sFeedText(u8s into, hunk const *hk) {
    sane(u8sOK(into) && hk != NULL);
    if (!$empty(hk->uri)) {
        a_cstr(pfx, "--- ");
        u8sFeed(into, pfx);
        u8sFeed(into, hk->uri);
        a_cstr(sfx, " ---\n");
        u8sFeed(into, sfx);
    }

    if ($empty(hk->text)) { u8sFeed1(into, '\n'); done; }

    if ($empty(hk->hili)) {
        // Plain hunk (grep / search / cat): emit text verbatim.
        u8cs t = {hk->text[0], hk->text[1]};
        u8sFeed(into, t);
        if (*$last(t) != '\n') u8sFeed1(into, '\n');
        u8sFeed1(into, '\n');
        done;
    }

    // Diff hunk: per-line '+' / '-' / ' ' prefix.
    // Single forward cursor over hili (sorted by offset, exclusive end).
    u8c *base = hk->text[0];
    int n_hili = (int)$len(hk->hili);
    int hi_cur = 0;
    a_dup(u8 const, cur, hk->text);
    while (!$empty(cur)) {
        u32 line_lo = (u32)(cur[0] - base);
        u8cs scan = {cur[0], cur[1]};
        b8 had_nl = (u8csFind(scan, '\n') == OK);
        u8c *line_end = scan[0];
        u32 line_hi = (u32)(line_end - base);

        // Skip hili spans that ended at or before line start.
        while (hi_cur < n_hili &&
               tok32Offset(hk->hili[0][hi_cur]) <= line_lo) hi_cur++;
        u8 prefix = ' ';
        for (int hj = hi_cur; hj < n_hili; hj++) {
            u32 span_lo = (hj > 0) ? tok32Offset(hk->hili[0][hj - 1]) : 0;
            if (span_lo >= line_hi) break;
            u8 tag = tok32Tag(hk->hili[0][hj]);
            if (tag == 'I') { prefix = '+'; break; }
            if (tag == 'D') { prefix = '-'; break; }
        }
        u8sFeed1(into, prefix);
        u8cs line = {cur[0], line_end};
        u8sFeed(into, line);
        u8sFeed1(into, '\n');
        cur[0] = had_nl ? line_end + 1 : line_end;
    }
    u8sFeed1(into, '\n');
    done;
}

// Reconstruct one logical version of a line by walking the merged
// text and skipping bytes whose hili tag matches `skip`.  Used by
// HUNKu8sFeedLineBased for mixed-INS/DEL lines: pass skip='I' to
// produce the "old" version, skip='D' for the "new" version.  Emits
// `prefix` then the reconstructed bytes followed by '\n'.
static ok64 hunk_emit_recon(u8s into, u8 prefix, u32 line_lo, u32 line_hi,
                            hunk const *hk, u8 skip) {
    sane(u8sOK(into) && hk != NULL);
    u8c *base = hk->text[0];
    int  n_hili = (int)$len(hk->hili);

    u8sFeed1(into, prefix);
    u32 cursor = line_lo;
    for (int i = 0; i < n_hili; i++) {
        u32 span_lo = (i > 0) ? tok32Offset(hk->hili[0][i - 1]) : 0;
        u32 span_hi = tok32Offset(hk->hili[0][i]);
        if (span_hi <= cursor) continue;
        if (span_lo >= line_hi) break;
        u32 lo = span_lo > cursor ? span_lo : cursor;
        u32 hi = span_hi < line_hi ? span_hi : line_hi;
        if (cursor < lo) {
            u8cs untagged = {base + cursor, base + lo};
            u8sFeed(into, untagged);
        }
        u8 tag = tok32Tag(hk->hili[0][i]);
        if (tag != skip) {
            u8cs span = {base + lo, base + hi};
            u8sFeed(into, span);
        }
        cursor = hi;
    }
    if (cursor < line_hi) {
        u8cs tail = {base + cursor, base + line_hi};
        u8sFeed(into, tail);
    }
    u8sFeed1(into, '\n');
    done;
}

ok64 HUNKu8sFeedLineBased(u8s into, hunk const *hk) {
    sane(u8sOK(into) && hk != NULL);
    if (!$empty(hk->uri)) {
        a_cstr(pfx, "--- ");
        u8sFeed(into, pfx);
        u8sFeed(into, hk->uri);
        a_cstr(sfx, " ---\n");
        u8sFeed(into, sfx);
    }

    if ($empty(hk->text)) { u8sFeed1(into, '\n'); done; }

    if ($empty(hk->hili)) {
        u8cs t = {hk->text[0], hk->text[1]};
        u8sFeed(into, t);
        if (*$last(t) != '\n') u8sFeed1(into, '\n');
        u8sFeed1(into, '\n');
        done;
    }

    //  Reconstruct OLD and NEW byte streams from the tag-tagged
    //  merged text, breaking each side into its own logical lines.
    //  KEEP bytes appear in both streams; DEL only in OLD; INS only
    //  in NEW.  At every '\n':
    //    - DEL '\n'  flushes the OLD line ('-' prefix; KEEP+DEL
    //                bytes accumulated since the previous flush).
    //    - INS '\n'  flushes the NEW line ('+' prefix).
    //    - KEEP '\n' flushes BOTH lines: OLD with '-' if it had any
    //                DEL byte else ' ' (context); NEW with '+' if it
    //                had any INS byte (otherwise it's a context line
    //                already emitted by OLD's flush — drop it to
    //                avoid duplication).
    //
    //  The previous "split merged text on '\n'" approach failed when
    //  the matcher grouped INS and DEL into multi-line blobs that
    //  straddle line boundaries — a "line" of merged text could
    //  contain the tail of an INS region and the head of a DEL
    //  region with no '\n' between them, so the per-line +/-/space
    //  tag-roll-up produced incoherent reconstructions.
    u8c *base = hk->text[0];
    int  n_hili = (int)$len(hk->hili);

    //  Build OLD and NEW byte streams independently:
    //    OLD = KEEP + DEL bytes (tracking per-line "had any DEL").
    //    NEW = KEEP + INS bytes (tracking per-line "had any INS").
    //  Lines are split on real '\n' on each side.  A line whose flag
    //  is set emits with `-`/`+`; otherwise it's a context line — we
    //  emit context lines from the OLD walk only (NEW's context is
    //  byte-identical, so emitting it again would double the line).
    Bu8 oldb = {}, newb = {};
    call(u8bAllocate, oldb, 1UL << 16);
    call(u8bAllocate, newb, 1UL << 16);
    b8 old_dirty = NO, new_dirty = NO;

    u32 prev = 0;
    for (int i = 0; i < n_hili; i++) {
        u32 span_hi = tok32Offset(hk->hili[0][i]);
        u8  tag     = tok32Tag(hk->hili[0][i]);
        u8c *p = base + prev;
        u8c *e = base + span_hi;
        for (; p < e; p++) {
            u8 c = *p;
            b8 is_nl = (c == '\n');
            if (tag == 'X') {
                //  Synthetic '\n' inserted by WEAVEEmitDiff to break
                //  INS↔DEL fusion in bro's TLV path.  The byte does
                //  not exist in OLD or NEW — drop it entirely so the
                //  LineBased renderer sees the underlying spans as
                //  if no break were inserted.
                continue;
            }
            if (tag == 'D') {
                if (is_nl) {
                    u8sFeed1(into, '-');
                    a_dup(u8c, body, u8bData(oldb));
                    u8sFeed(into, body);
                    u8sFeed1(into, '\n');
                    u8bReset(oldb);
                    old_dirty = NO;
                } else {
                    u8bFeed1(oldb, c);
                    old_dirty = YES;
                }
            } else if (tag == 'I') {
                if (is_nl) {
                    //  An INS-tagged '\n' is itself an INS contribution
                    //  — the line break is new even when the line's
                    //  preceding bytes were KEEP.  Always emit `+`.
                    //  Skipping it would silently drop blank-line
                    //  insertions (KEEP context + INS '\n' alone) and
                    //  any line whose only NEW-side change is the
                    //  trailing newline.
                    u8sFeed1(into, '+');
                    a_dup(u8c, body, u8bData(newb));
                    u8sFeed(into, body);
                    u8sFeed1(into, '\n');
                    u8bReset(newb);
                    new_dirty = NO;
                } else {
                    u8bFeed1(newb, c);
                    new_dirty = YES;
                }
            } else { // KEEP
                if (is_nl) {
                    u8sFeed1(into, old_dirty ? '-' : ' ');
                    a_dup(u8c, ob, u8bData(oldb));
                    u8sFeed(into, ob);
                    u8sFeed1(into, '\n');
                    u8bReset(oldb);
                    if (new_dirty) {
                        u8sFeed1(into, '+');
                        a_dup(u8c, nb, u8bData(newb));
                        u8sFeed(into, nb);
                        u8sFeed1(into, '\n');
                    }
                    u8bReset(newb);
                    old_dirty = NO;
                    new_dirty = NO;
                } else {
                    u8bFeed1(oldb, c);
                    u8bFeed1(newb, c);
                }
            }
        }
        prev = span_hi;
    }

    //  Trailing partial line (no terminating '\n').
    if (u8bDataLen(oldb) > 0 || old_dirty) {
        u8sFeed1(into, old_dirty ? '-' : ' ');
        a_dup(u8c, ob, u8bData(oldb));
        u8sFeed(into, ob);
        u8sFeed1(into, '\n');
    }
    if (new_dirty && u8bDataLen(newb) > 0) {
        u8sFeed1(into, '+');
        a_dup(u8c, nb, u8bData(newb));
        u8sFeed(into, nb);
        u8sFeed1(into, '\n');
    }
    u8bFree(oldb);
    u8bFree(newb);
    u8sFeed1(into, '\n');
    done;
}

void HUNKu32sClip(Bu8 arena, u32cs out, u32cs toks, u32 lo, u32 hi) {
    out[0] = NULL;
    out[1] = NULL;
    if ($empty(toks) || lo >= hi) return;
    int n = (int)$len(toks);
    // Find first tok overlapping [lo, hi)
    int first = 0;
    while (first < n && tok32Offset(toks[0][first]) <= lo) first++;
    // Find last tok overlapping [lo, hi)
    int last = first;
    while (last < n) {
        u32 tlo = (last > 0) ? tok32Offset(toks[0][last - 1]) : 0;
        if (tlo >= hi) break;
        last++;
    }
    if (first >= last) return;
    u32gp g = u32aOpen(arena);
    for (int i = first; i < last; i++) {
        u8 tag = tok32Tag(toks[0][i]);
        u32 off = tok32Offset(toks[0][i]);
        if (off > hi) off = hi;
        u32 rebased = off - lo;
        u32gFeed1(g, tok32Pack(tag, rebased));
    }
    u32aClose(arena, out);
}

// --- Source tokenizer wrapper around dog/TOK lexer ---

typedef struct {
    u32bp toks;
    u32   off;
} HUNKTokCtx;

static ok64 HUNKTokCB(u8 tag, u8cs tok, void *ctx) {
    sane(ctx != NULL);
    HUNKTokCtx *c = (HUNKTokCtx *)ctx;
    u32 end = c->off + (u32)$len(tok);
    u32 packed = tok32Pack(tag, end);
    call(u32bFeed1, c->toks, packed);
    c->off = end;
    return OK;
}

ok64 HUNKu32bTokenize(u32bp toks, u8csc source, u8csc ext) {
    sane(toks != NULL && $ok(source));
    if ($empty(source)) done;

    HUNKTokCtx ctx = {.toks = toks, .off = 0};

    u8cs ext_nodot = {};
    if (!$empty(ext) && ext[0][0] == '.') {
        ext_nodot[0] = ext[0] + 1;
        ext_nodot[1] = ext[1];
    } else {
        $mv(ext_nodot, ext);
    }

    TOKstate ts = {
        .data = {source[0], source[1]},
        .cb = HUNKTokCB,
        .ctx = &ctx,
    };
    call(TOKLexer, &ts, ext_nodot);
    done;
}

// Is `s` a plain FRAG ident: [A-Za-z_][A-Za-z0-9_]* ?
static b8 hunk_is_ident(u8cs s) {
    if ($empty(s)) return NO;
    size_t n = (size_t)$len(s);
    u8 c = s[0][0];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'))
        return NO;
    for (size_t i = 1; i < n; i++) {
        c = s[0][i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return NO;
    }
    return YES;
}

ok64 HUNKu8sMakeURI(u8s into, u8csc path, u8csc symbol, u32 lineno) {
    sane(u8sOK(into));
    if (!$empty(path)) u8sFeed(into, path);
    b8 has_sym = !$empty(symbol);
    if (has_sym || lineno > 0)
        u8sFeed1(into, '#');
    if (has_sym) {
        u8cs sym = {symbol[0], symbol[1]};
        if (hunk_is_ident(sym)) {
            // Plain ident — emit verbatim
            u8sFeed(into, sym);
        } else {
            // Quote and percent-escape URI-illegal chars
            u8sFeed1(into, '\'');
            call(FRAGu8sEsc, into, sym);
            u8sFeed1(into, '\'');
        }
        if (lineno > 0) {
            u8sFeed1(into, ':');
            utf8sFeed10(into, (u64)lineno);
        }
    } else if (lineno > 0) {
        utf8sFeed10(into, (u64)lineno);  // bare line number
    }
    done;
}
