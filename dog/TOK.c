#include "TOK.h"

#include "CT.h"
#include "CPPT.h"
#include "GOT.h"
#include "PYT.h"
#include "JST.h"
#include "RST.h"
#include "JAT.h"
#include "CST.h"
#include "HTMT.h"
#include "CSST.h"
#include "JSONT.h"
#include "SHT.h"
#include "RBT.h"
#include "HST.h"
#include "MLT.h"
#include "JLT.h"
#include "PHPT.h"
#include "AGDT.h"
#include "VERT.h"
#include "TST.h"
#include "KTT.h"
#include "SCLT.h"
#include "SWFT.h"
#include "DARTT.h"
#include "ZIGT.h"
#include "DT.h"
#include "LUAT.h"
#include "PRLT.h"
#include "RT.h"
#include "ELXT.h"
#include "ERLT.h"
#include "NIMT.h"
#include "NIXT.h"
#include "VIMT.h"
#include "YMLT.h"
#include "TOMLT.h"
#include "SQLT.h"
#include "GQLT.h"
#include "PRTT.h"
#include "HCLT.h"
#include "SCSST.h"
#include "LAXT.h"
#include "CLJT.h"
#include "CMKT.h"
#include "DKFT.h"
#include "FORT.h"
#include "FSHT.h"
#include "GLMT.h"
#include "GLST.h"
#include "MAKT.h"
#include "ODNT.h"
#include "PWST.h"
#include "SOLT.h"
#include "TYST.h"
#include "TXTT.h"
#include "MDT.h"
#include "MKDT.h"
#include "LLT.h"
#include "abc/PATH.h"
#include "abc/PRO.h"

fun b8 TOKIsAlpha_(u8 c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

fun b8 TOKIsAlnum_(u8 c) {
    return TOKIsAlpha_(c) || (c >= '0' && c <= '9');
}

fun b8 TOKIsSpace(u8 c) {
    return c == ' ' || c == '\t' || c == '\n' ||
           c == '\r' || c == '\f' || c == '\v';
}

ok64 TOKSplitText(u8 tag, u8cs text, TOKcb cb, void *ctx) {
    u8c *p = text[0];
    u8c *e = text[1];
    u8cs sub;
    while (p < e) {
        sub[0] = p;
        u8 c = *p;
        if (TOKIsAlnum_(c)) {
            do { ++p; } while (p < e && TOKIsAlnum_(*p));
        } else if (TOKIsSpace(c)) {
            do { ++p; } while (p < e && TOKIsSpace(*p));
        } else if (c >= 0x80) {
            ++p;
            while (p < e && (*p & 0xC0) == 0x80) ++p;
        } else {
            ++p;
        }
        sub[1] = p;
        ok64 o = cb(tag, sub, ctx);
        if (o != OK) return o;
    }
    return OK;
}

typedef ok64 (*TOKfn)(TOKstate *state);

typedef struct {
    u8cs  ext;     // precomputed slice via u8slit; sentinel = empty
    TOKfn lexer;
} TOKentry;

#define E(s, fn) {u8slit(s), (TOKfn)fn}

static const TOKentry TOK_TABLE[] = {
    E("c",          CTLexer),
    E("h",          CTLexer),
    E("cpp",        CPPTLexer),
    E("cc",         CPPTLexer),
    E("cxx",        CPPTLexer),
    E("hpp",        CPPTLexer),
    E("hh",         CPPTLexer),
    E("hxx",        CPPTLexer),
    E("go",         GOTLexer),
    E("py",         PYTLexer),
    E("js",         JSTLexer),
    E("jsx",        JSTLexer),
    E("mjs",        JSTLexer),
    E("ts",         TSTLexer),
    E("tsx",        TSTLexer),
    E("rs",         RSTLexer),
    E("java",       JATLexer),
    E("kt",         KTTLexer),
    E("kts",        KTTLexer),
    E("scala",      SCLTLexer),
    E("sc",         SCLTLexer),
    E("cs",         CSTLexer),
    E("fs",         FSHTLexer),
    E("fsi",        FSHTLexer),
    E("fsx",        FSHTLexer),
    E("swift",      SWFTLexer),
    E("dart",       DARTTLexer),
    E("d",          DTLexer),
    E("zig",        ZIGTLexer),
    E("html",       HTMTLexer),
    E("htm",        HTMTLexer),
    E("css",        CSSTLexer),
    E("scss",       SCSSTLexer),
    E("json",       JSONTLexer),
    E("yml",        YMLTLexer),
    E("yaml",       YMLTLexer),
    E("toml",       TOMLTLexer),
    E("sh",         SHTLexer),
    E("bash",       SHTLexer),
    E("rb",         RBTLexer),
    E("lua",        LUATLexer),
    E("pl",         PRLTLexer),
    E("pm",         PRLTLexer),
    E("r",          RTLexer),
    E("R",          RTLexer),
    E("ex",         ELXTLexer),
    E("exs",        ELXTLexer),
    E("erl",        ERLTLexer),
    E("hrl",        ERLTLexer),
    E("hs",         HSTLexer),
    E("ml",         MLTLexer),
    E("mli",        MLTLexer),
    E("jl",         JLTLexer),
    E("nim",        NIMTLexer),
    E("nims",       NIMTLexer),
    E("php",        PHPTLexer),
    E("clj",        CLJTLexer),
    E("cljs",       CLJTLexer),
    E("cljc",       CLJTLexer),
    E("edn",        CLJTLexer),
    E("nix",        NIXTLexer),
    E("sql",        SQLTLexer),
    E("graphql",    GQLTLexer),
    E("gql",        GQLTLexer),
    E("proto",      PRTTLexer),
    E("hcl",        HCLTLexer),
    E("tf",         HCLTLexer),
    E("tex",        LAXTLexer),
    E("sty",        LAXTLexer),
    E("cls",        LAXTLexer),
    E("vim",        VIMTLexer),
    E("cmake",      CMKTLexer),
    E("dockerfile", DKFTLexer),
    E("mk",         MAKTLexer),
    E("f90",        FORTLexer),
    E("f95",        FORTLexer),
    E("f03",        FORTLexer),
    E("f08",        FORTLexer),
    E("glsl",       GLSTLexer),
    E("vert",       GLSTLexer),
    E("frag",       GLSTLexer),
    E("geom",       GLSTLexer),
    E("comp",       GLSTLexer),
    E("gleam",      GLMTLexer),
    E("odin",       ODNTLexer),
    E("ps1",        PWSTLexer),
    E("psm1",       PWSTLexer),
    E("psd1",       PWSTLexer),
    E("sol",        SOLTLexer),
    E("typ",        TYSTLexer),
    E("agda",       AGDTLexer),
    E("v",          VERTLexer),
    E("sv",         VERTLexer),
    E("ll",         LLTLexer),
    E("md",         MDTLexer),
    E("markdown",   MDTLexer),
    E("mkd",        MKDTLexer),
    E("sm",         MKDTLexer),
    E("txt",        TXTTLexer),
    E("rst",        TXTTLexer),
    {{NULL, NULL},  NULL},
};

// Filename → lexer table for files whose names are their type.
static const TOKentry TOK_NAME_TABLE[] = {
    E("CMakeLists.txt", CMKTLexer),
    E("Makefile",       MAKTLexer),
    E("makefile",       MAKTLexer),
    E("GNUmakefile",    MAKTLexer),
    E("Dockerfile",     DKFTLexer),
    E("Vagrantfile",    RBTLexer),
    E("Gemfile",        RBTLexer),
    E("Rakefile",       RBTLexer),
    E("Justfile",       MAKTLexer),
    E(".gitignore",     SHTLexer),
    E(".gitattributes", SHTLexer),
    E(".gitmodules",    TOMLTLexer),
    E(".bashrc",        SHTLexer),
    E(".bash_profile",  SHTLexer),
    E(".profile",       SHTLexer),
    E(".zshrc",         SHTLexer),
    E(".vimrc",         VIMTLexer),
    E(".clang-format",  YMLTLexer),
    {{NULL, NULL},      NULL},
};

#undef E

const char *TOKExtAt(int i) {
    if (i < 0) return NULL;
    int n = (int)(sizeof(TOK_TABLE) / sizeof(TOK_TABLE[0])) - 1;
    if (i >= n) return NULL;
    return (const char *)TOK_TABLE[i].ext[0];
}

static b8 TOKSliceMatch(u8csc s, u8csc pat) {
    u64 len = u8csLen(s);
    if (len != u8csLen(pat)) return NO;
    return __builtin_memcmp(s[0], pat[0], len) == 0;
}

// Wrappers around abc/PATH for basename and extension extraction.

// Try the name table against the basename of `path`.
static TOKfn TOKFindByName(u8csc path) {
    u8cs base = {};
    a_dup(u8c, p, path);
    PATHu8sBase(base, p);
    if ($empty(base)) return NULL;
    for (const TOKentry *e = TOK_NAME_TABLE; e->ext[0] != NULL; ++e)
        if (TOKSliceMatch(base, e->ext)) return e->lexer;
    return NULL;
}

// Try the ext table against the extension of `path`.
static TOKfn TOKFindByExt(u8csc path) {
    u8cs ext = {};
    a_dup(u8c, p, path);
    PATHu8sExt(ext, p);
    if ($empty(ext)) return NULL;
    for (const TOKentry *e = TOK_TABLE; e->ext[0] != NULL; ++e)
        if (TOKSliceMatch(ext, e->ext)) return e->lexer;
    return NULL;
}

// Resolve lexer for a path, filename, or bare extension.
// Tries: 1) name table by basename, 2) ext table by extension.
static TOKfn TOKResolve(u8csc input) {
    if ($empty(input)) return NULL;
    // If input has no dot and no slash, treat as bare ext directly.
    b8 has_dot = NO, has_slash = NO;
    $for(u8c, p, input) {
        if (*p == '.') has_dot = YES;
        if (*p == '/') has_slash = YES;
    }
    if (!has_dot && !has_slash) {
        // Bare extension like "c" or "py" — try ext table first.
        for (const TOKentry *e = TOK_TABLE; e->ext[0] != NULL; ++e)
            if (TOKSliceMatch(input, e->ext)) return e->lexer;
        // Then name table for extensionless filenames (Makefile, etc.).
        TOKfn fn = TOKFindByName(input);
        if (fn) return fn;
        return NULL;
    }
    // Strip leading dot if caller passed ".c" style.
    u8cs stripped = {};
    if (input[0][0] == '.' && !has_slash && $len(input) > 1) {
        // Could be ".c" (dotted ext) or ".gitignore" (dotfile name).
        // Try name table for dotfiles first.
        TOKfn fn = TOKFindByName(input);
        if (fn) return fn;
        // Then try as dotted ext.
        stripped[0] = input[0] + 1;
        stripped[1] = input[1];
        for (const TOKentry *e = TOK_TABLE; e->ext[0] != NULL; ++e)
            if (TOKSliceMatch(stripped, e->ext)) return e->lexer;
        return NULL;
    }
    // Full path or filename: try name, then ext.
    TOKfn fn = TOKFindByName(input);
    if (fn) return fn;
    return TOKFindByExt(input);
}

b8 TOKKnownExt(u8csc ext) {
    return TOKResolve(ext) != NULL;
}

b8 TOKSameLexer(u8csc a, u8csc b) {
    TOKfn fa = TOKResolve(a);
    TOKfn fb = TOKResolve(b);
    return fa != NULL && fa == fb;
}

ok64 TOKLexer(TOKstate *state, u8csc ext) {
    sane($ok(state->data) && state != NULL);
    TOKfn fn = TOKResolve(ext);
    if (fn == NULL) fn = (TOKfn)TXTTLexer;
    call(fn, state);
    done;
}
