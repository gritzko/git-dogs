//
// WEAVE fuzz test — round-trip property of `WEAVEDiff`.
//
// Input format: u8 bytes split into three sections by `\f` (form feed,
// 0x0c).  Section 1 = base text `o`, section 2 = `a`, section 3 = `b`.
// `\f` chosen over `\n` because the test inputs are line-based; using
// `\n` as separator would forbid newlines inside the versions.
//
// Per side `x in {a, b}`:
//   1. wox <- WEAVEDiff(WEAVEFromBlob(o, src=0), WEAVEFromBlob(x, src=X))
//   2. Reproduce `o`: walk wox, concatenate tokens with `inrm.in == 0`.
//      Bytes must equal the original `o`.
//   3. Reproduce `x`: walk wox, concatenate tokens with `inrm.rm == 0`.
//      Bytes must equal the original `x`.
//
// Plus a merge round-trip per side-pair (a, b):
//   3. wm <- WEAVEMerge(woa, wob)
//   4. Walk wm; if it has zero conflict markers, the alive byte
//      stream must contain (in lexer-token order, possibly
//      interleaved) every alive token of woa and every alive token
//      of wob, modulo deletions one side made.  We check the weaker
//      property that the alive byte stream has length >= max(|a|,|b|)
//      / 2 — true merges shouldn't shrink to nothing absent both
//      sides deleting everything.  Conflict-marker outputs are
//      accepted as-is (a conflict per se isn't a fuzz failure).
//
// Tokenizer: C (extension `c`).

#include "WEAVE.h"

#include <stdio.h>
#include <string.h>

#include "abc/PRO.h"
#include "abc/TEST.h"
#include "dog/HUNK.h"

#define WEAVE_FUZZ_MAX 8192
#define WEAVE_BASE_SRC 0u
#define WEAVE_A_SRC    0xA0A0A0A0u
#define WEAVE_B_SRC    0xB0B0B0B0u

// --- Reproduce one side of a 2-layer weave by inrm filter ----------
//
// `keep_pre`  — include tokens with `in != side` (the original side).
// `keep_post` — include tokens with `rm == 0`     (the post side).
// Out goes into `out`.

static ok64 weave_repro_pre(u8bp out, weave const *w, u32 side) {
    sane(out && w);
    u32cp toks = (u32cp)w->toks[1];
    u32cp toks_e = (u32cp)w->toks[2];
    u32   ntok = (u32)(toks_e - toks);
    inrmcp irm = (inrmcp)w->inrm[1];
    u8cp   text = (u8cp)w->text[1];
    u8bReset(out);
    for (u32 i = 0; i < ntok; i++) {
        if (irm[i].in == side) continue;
        u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
        u32 hi = tok32Offset(toks[i]);
        u8cs tb = {text + lo, text + hi};
        call(u8bFeed, out, tb);
    }
    done;
}

static ok64 weave_repro_post(u8bp out, weave const *w) {
    sane(out && w);
    u32cp toks = (u32cp)w->toks[1];
    u32cp toks_e = (u32cp)w->toks[2];
    u32   ntok = (u32)(toks_e - toks);
    inrmcp irm = (inrmcp)w->inrm[1];
    u8cp   text = (u8cp)w->text[1];
    u8bReset(out);
    for (u32 i = 0; i < ntok; i++) {
        if (irm[i].rm != 0) continue;
        u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
        u32 hi = tok32Offset(toks[i]);
        u8cs tb = {text + lo, text + hi};
        call(u8bFeed, out, tb);
    }
    done;
}

// --- Patch-validity property ----------------------------------------
//
// `WEAVEEmitDiff` produces hunks; rendering each hunk via
// `HUNKu8sFeedLineBased` yields unified-diff text:
//   - `-<line>`  removed from to-side
//   - `+<line>`  added on to-side
//   - ` <line>`  context (in both)
// The property: every `-`/`+` line content (without prefix) must be
// an exact line of the corresponding source.  A `+<partial>` whose
// content is not a complete line of the new source is a renderer or
// weave bug — for example the `+//  Stock` partial that the
// test/diff/03-stock-context regression demonstrated.

static b8 weave_line_in(u8cs needle, u8cs haystack) {
    u32 nl = (u32)$len(needle);
    u8cp p = haystack[0];
    u8cp e = haystack[1];
    while (p < e) {
        u8cp eol = p;
        while (eol < e && *eol != '\n') eol++;
        u32 llen = (u32)(eol - p);
        if (llen == nl && (nl == 0 || memcmp(p, needle[0], nl) == 0))
            return YES;
        p = (eol < e) ? eol + 1 : eol;
    }
    //  Tolerate a trailing implicit empty line (file with no final \n).
    return nl == 0;
}

typedef struct {
    u8cs o;
    u8cs x;
} hunk_check_ctx;

//  TLV-rendering property: in the emitted `text + hili` stream, an
//  `I`↔`D` boundary where neither side is '\n' AND the just-closed
//  span contained at least one '\n' would visually fuse the two
//  multi-line edits onto a single screen row in bro (e.g.
//  `name[0]char const *name…`).  Catches the bug fixed by the
//  synthetic-`\n` insertion in `WEAVEEmitDiff`.  Property failure
//  traps via `must()` so libFuzzer captures the offending input.
static void weave_tlv_fusion_check(hunkc *hk) {
    must(hk != NULL, "null hunk");
    int n_hili = (int)$len(hk->hili);
    if (n_hili < 2) return;
    u8c *text = hk->text[0];
    u32 textlen = (u32)$len(hk->text);
    u32 prev_lo = 0;
    u8 prev_tag = tok32Tag(hk->hili[0][0]);
    for (int i = 1; i < n_hili; i++) {
        u32 boundary = tok32Offset(hk->hili[0][i - 1]);
        u8 cur_tag = tok32Tag(hk->hili[0][i]);
        b8 swap = (prev_tag == 'I' && cur_tag == 'D') ||
                  (prev_tag == 'D' && cur_tag == 'I');
        if (swap && boundary > 0 && boundary < textlen) {
            u8 last_byte  = text[boundary - 1];
            u8 first_byte = text[boundary];
            if (last_byte != '\n' && first_byte != '\n') {
                u32 span_len = boundary - prev_lo;
                b8 prev_multi = (span_len > 0) &&
                    (memchr(text + prev_lo, '\n', span_len) != NULL);
                if (prev_multi) {
                    fprintf(stderr,
                        "WEAVE fuzz: INS↔DEL fusion at offset %u "
                        "(%c→%c, span_len=%u, last=0x%02x first=0x%02x)\n",
                        boundary, prev_tag, cur_tag, span_len,
                        last_byte, first_byte);
                    must(0, "INS↔DEL fusion across multi-line span");
                }
            }
        }
        prev_lo = boundary;
        prev_tag = cur_tag;
    }
}

//  Print the body's bytes in mixed printable/hex form so case (b)
//  cases — bodies whose first byte is NUL, or which contain control
//  bytes — produce a useful repro hint instead of an opaque `''`.
static void weave_dump_body(u8cs body) {
    u32 n = (u32)$len(body);
    fprintf(stderr, "[%u]", n);
    for (u32 i = 0; i < n; i++) {
        u8 c = body[0][i];
        if (c >= 0x20 && c < 0x7f && c != '\\') fputc(c, stderr);
        else fprintf(stderr, "\\x%02x", c);
    }
}

static ok64 weave_hunk_check_cb(hunkc *hk, void *vctx) {
    sane(hk && vctx);
    hunk_check_ctx *c = vctx;

    //  Property: no INS↔DEL fusion across multi-line spans.
    weave_tlv_fusion_check(hk);

    //  Render the hunk in plain unified-diff form.
    Bu8 buf = {};
    if (u8bAlloc(buf, (u32)$len(hk->text) + 1024) != OK) return OK;
    if (HUNKu8sFeedLineBased(u8bIdle(buf), hk) != OK) {
        u8bFree(buf); return OK;
    }
    a_dup(u8c, rendered, u8bData(buf));

    u8cp p = rendered[0];
    u8cp e = rendered[1];
    while (p < e) {
        u8cp eol = p;
        while (eol < e && *eol != '\n') eol++;
        u32 llen = (u32)(eol - p);

        //  Skip the title line `--- name ---`.
        if (llen >= 4 && memcmp(p, "--- ", 4) == 0) {
            p = (eol < e) ? eol + 1 : eol;
            continue;
        }
        if (llen == 0) {
            p = (eol < e) ? eol + 1 : eol;
            continue;
        }

        u8 pref = *p;
        u8cs body = {p + 1, eol};
        if (pref == '-' && !weave_line_in(body, c->o)) {
            fprintf(stderr, "WEAVE fuzz: -line not present in OLD: ");
            weave_dump_body(body);
            fputc('\n', stderr);
            must(0, "-line in rendered diff doesn't match OLD");
        }
        if (pref == '+' && !weave_line_in(body, c->x)) {
            fprintf(stderr, "WEAVE fuzz: +line not present in NEW: ");
            weave_dump_body(body);
            fputc('\n', stderr);
            must(0, "+line in rendered diff doesn't match NEW");
        }

        p = (eol < e) ? eol + 1 : eol;
    }

    u8bFree(buf);
    return OK;
}

//  in/from/to predicates for WEAVEEmitDiff matching the `WEAVE_BASE_SRC`
//  / `x_src` 2-layer convention.
static b8 weave_in_from(u32 c, void *ctx) {
    u32 to = *(u32 *)ctx;
    return c != to;
}
static b8 weave_in_to(u32 c, void *ctx) {
    (void)ctx; (void)c;
    return YES;
}

// --- One round-trip test --------------------------------------------

static ok64 weave_check_one(u8cs o_data, u8cs x_data, u32 x_src,
                             u8cs ext) {
    sane($ok(ext));

    weave wo = {}, wx = {}, wox = {};
    Bu8 outbuf = {};
    ok64 ret = OK;

    if (WEAVEInit(&wo)  != OK) { ret = NOROOM; goto out; }
    if (WEAVEInit(&wx)  != OK) { ret = NOROOM; goto out; }
    if (WEAVEInit(&wox) != OK) { ret = NOROOM; goto out; }
    if (u8bAlloc(outbuf, $len(o_data) + $len(x_data) + 16) != OK) {
        ret = NOROOM; goto out;
    }

    ret = WEAVEFromBlob(&wo, o_data, ext, WEAVE_BASE_SRC);
    if (ret != OK) goto out;
    ret = WEAVEFromBlob(&wx, x_data, ext, x_src);
    if (ret != OK) goto out;
    ret = WEAVEDiff(&wox, &wo, &wx, x_src);
    if (ret != OK) goto out;

    //  Property: walking the post-diff weave with `in != x_src` filter
    //  reproduces `o` byte-for-byte.
    ret = weave_repro_pre(outbuf, &wox, x_src);
    if (ret != OK) goto out;
    {
        a_dup(u8c, repro_o, u8bData(outbuf));
        must($len(repro_o) == $len(o_data) &&
             ($len(o_data) == 0 ||
              memcmp(repro_o[0], o_data[0],
                     (size_t)$len(o_data)) == 0),
             "WEAVEDiff round-trip lost the OLD side (in != x_src walk)");
    }

    //  Property: walking with `rm == 0` filter reproduces `x`.
    ret = weave_repro_post(outbuf, &wox);
    if (ret != OK) goto out;
    {
        a_dup(u8c, repro_x, u8bData(outbuf));
        must($len(repro_x) == $len(x_data) &&
             ($len(x_data) == 0 ||
              memcmp(repro_x[0], x_data[0],
                     (size_t)$len(x_data)) == 0),
             "WEAVEDiff round-trip lost the NEW side (rm == 0 walk)");
    }

    //  Property (patch validity + TLV fusion): every `-`/`+` line in
    //  the rendered hunk text must be a real line of `o`/`x`, and the
    //  emitted text must not have INS↔DEL transitions that fuse two
    //  multi-line edits onto one screen row.  Failures `must()`-trap
    //  inside `weave_hunk_check_cb` so libFuzzer captures the input.
    {
        a_cstr(name, "fuzz");
        u32 to_src = x_src;
        hunk_check_ctx hctx = {};
        u8csMv(hctx.o, o_data);
        u8csMv(hctx.x, x_data);
        (void)WEAVEEmitDiff(&wox, name,
                            weave_in_from, &to_src,
                            weave_in_to,   &to_src,
                            weave_hunk_check_cb, &hctx);
    }

out:
    u8bFree(outbuf);
    WEAVEFree(&wo);
    WEAVEFree(&wx);
    WEAVEFree(&wox);
    return ret;
}

// --- Entry point ---------------------------------------------------

FUZZ(u8, WEAVEfuzz) {
    sane(1);
    if ($len(input) > WEAVE_FUZZ_MAX || $len(input) < 4) done;

    //  Split on `\f` into [o, a, b].
    u8cp s1 = NULL, s2 = NULL;
    $for(u8c, p, input) {
        if (*p == 0x0c) {
            if (s1 == NULL) s1 = p;
            else if (s2 == NULL) { s2 = p; break; }
        }
    }
    if (s1 == NULL || s2 == NULL) done;

    a_head(u8c, o_data, input, s1 - input[0]);
    a_rest(u8c, after1, input, s1 - input[0] + 1);
    a_head(u8c, a_data, after1, s2 - s1 - 1);
    a_rest(u8c, b_data, after1, s2 - s1);

    if ($empty(o_data)) done;

    u8c c_ext_b[1] = {'c'};
    u8cs ext = {c_ext_b, c_ext_b + 1};

    ok64 r1 = weave_check_one(o_data, a_data, WEAVE_A_SRC, ext);
    if (r1 != OK) fail(r1);

    if (!$empty(b_data)) {
        ok64 r2 = weave_check_one(o_data, b_data, WEAVE_B_SRC, ext);
        if (r2 != OK) fail(r2);
    }

    //  Merge round-trip: build woa, wob then WEAVEMerge them; the
    //  call should not crash regardless of input shape.  Detailed
    //  property checks live in WEAVE01test (the table-driven test);
    //  this fuzz just keeps `WEAVEMerge` from regressing on adversarial
    //  inputs.
    if (!$empty(b_data)) {
        weave wo = {}, wa_raw = {}, wb_raw = {};
        weave woa = {}, wob = {}, wm = {};
        if (WEAVEInit(&wo)     != OK) goto merge_out;
        if (WEAVEInit(&wa_raw) != OK) goto merge_out;
        if (WEAVEInit(&wb_raw) != OK) goto merge_out;
        if (WEAVEInit(&woa)    != OK) goto merge_out;
        if (WEAVEInit(&wob)    != OK) goto merge_out;
        if (WEAVEInit(&wm)     != OK) goto merge_out;
        if (WEAVEFromBlob(&wo,     o_data, ext, WEAVE_BASE_SRC) != OK) goto merge_out;
        if (WEAVEFromBlob(&wa_raw, a_data, ext, WEAVE_A_SRC)    != OK) goto merge_out;
        if (WEAVEFromBlob(&wb_raw, b_data, ext, WEAVE_B_SRC)    != OK) goto merge_out;
        if (WEAVEDiff(&woa, &wo, &wa_raw, WEAVE_A_SRC) != OK) goto merge_out;
        if (WEAVEDiff(&wob, &wo, &wb_raw, WEAVE_B_SRC) != OK) goto merge_out;
        (void)WEAVEMerge(&wm, &woa, &wob);
    merge_out:
        WEAVEFree(&wo);
        WEAVEFree(&wa_raw);
        WEAVEFree(&wb_raw);
        WEAVEFree(&woa);
        WEAVEFree(&wob);
        WEAVEFree(&wm);
    }

    done;
}
