#include "BRO.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "MAUS.h"
#include "abc/ANSI.h"
#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/TTY.h"
#include "abc/URI.h"
#include "abc/UTF8.h"
#include "dog/DEF.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"
#include "dog/TOK.h"

// --- Active bro instance ---
//
// The pager + cat-mode code uses the bro state's arena, hunks, toks
// and deferred-maps buffers heavily. Rather than thread `bro *b`
// through every static helper we keep storage in the caller-owned
// struct (per the DOG 4-fn API) and install a file-static pointer to
// it at BROOpen time. Macros below forward the long-established
// names to the active instance's typed buffers.

static bro *bro_state = NULL;

#define bro_arena  (bro_state->arena)
#define bro_hunks  hunkbDataHead(bro_state->hunks)   // hunk* into DATA
#define bro_toks   (bro_state->toks)                 // shared u32b arena
#define BRO_COLOR  (bro_state->color)
#define bro_nhunks ((u32)hunkbDataLen(bro_state->hunks))

// Tokens arena size — big enough for every hunk's tokens combined.
#define BRO_TOKS_SIZE (1UL << 22)   // 16M u32 entries = 64MB

// --- DOG 4-fn: Open / Close / Update ---

ok64 BROOpen(bro *b, home *h, b8 rw) {
    sane(b && h);
    zerop(b);
    b->h = h;
    b->rw = rw;
    b->color = YES;
    b->pipe_fd = -1;
    b->worker_pid = -1;
    bro_state = b;
    call(u8bMap, b->arena, BRO_ARENA_SIZE);
    call(hunkbMap, b->hunks, BRO_MAX_HUNKS);
    call(u32bMap,  b->toks,  BRO_TOKS_SIZE);
    call(u8bbMap,  b->maps,  BRO_MAX_MAPS);
    done;
}

ok64 BROClose(bro *b) {
    sane(b);
    if (bro_state == b) {
        size_t n = u8bbDataLen(b->maps);
        u8b *head = u8bbDataHead(b->maps);
        for (size_t i = 0; i < n; i++) {
            u8bp mp = (u8bp)head[i];
            if (mp && mp[0]) FILEUnMap(mp);
        }
        if (b->maps[0])  u8bbUnMap(b->maps);
        if (b->toks[0])  u32bUnMap(b->toks);
        if (b->hunks[0]) hunkbUnMap(b->hunks);
        if (b->arena[0]) u8bUnMap(b->arena);
        bro_state = NULL;
    }
    zerop(b);
    done;
}

// Bro does not index — stub to satisfy the DOG 4-fn contract.
ok64 BROUpdate(bro *b, u8 obj_type, u8cs blob, u8csc path) {
    sane(b);
    (void)obj_type; (void)blob; (void)path;
    done;
}

// Reset staging between subcommands — keeps the mappings alive.
ok64 BROArenaInit(void) {
    sane(bro_state);
    u8bShedAll(bro_state->arena);
    hunkbShedAll(bro_state->hunks);
    u32bShedAll(bro_state->toks);
    // Deferred maps stay recorded across a reset so the owning
    // files remain valid for hunks already handed to BRORun.
    return OK;
}

void BROArenaCleanup(void) { /* cleanup lives in BROClose */ }

// Write bytes into the arena, return pointer to start
u8p BROArenaWrite(void const *data, size_t len) {
    if (u8bIdleLen(bro_arena) < len) return NULL;
    u8p p = u8bIdleHead(bro_arena);
    memcpy(p, data, len);
    u8bFed(bro_arena, len);
    return p;
}

// Record a mmap'd file so BROClose can FILEUnMap it after the view
// that references it has been drained.
void BRODefer(u8bp mapped) {
    if (!mapped || u8bbIdleLen(bro_state->maps) == 0) return;
    u8bbFeed1(bro_state->maps, mapped);
}

// Finalize the hunk just staged at hunkbIdleHead.
void BROHunkAdd(void) { hunkbFed(bro_state->hunks, 1); }

// 256-color ink violet for hunk titles
#define BRO_TITLE_COLOR TTY_FG256(56)

// Tag-to-ANSI-color mapping.
// Returns fg color; sets *bold = YES for definitions.
#define FILE_COLOR 56  // 256-color violet for filenames (same as title)

static int BROTagColor(u8 tag, b8 *bold) {
    *bold = NO;
    switch (tag) {
        case 'D': return GRAY;         // comment
        case 'G': return DARK_GREEN;   // string
        case 'L': return LIGHT_CYAN;   // number
        case 'H': return DARK_PINK;    // preproc/annotation
        case 'R': return LIGHT_BLUE;   // keyword
        case 'P': return GRAY;         // punctuation
        case 'N': *bold = YES; return 0; // defined name
        case 'C': *bold = YES; return 0; // function call
        case 'F': return -FILE_COLOR;  // filename (256-color, negative = 256)
        default:  return 0;
    }
}

// --- Line index ---
// Maps line number -> (hunk index, byte offset within hunk text).
// A "line" is range32: lo=hunk index, hi=byte offset within hunk text.
// A title separator is stored as hunk index with hi=UINT32_MAX.

// A hunk has a displayable title if it has a URI.
#define hunk_has_title(hk) (!$empty((hk)->uri))

// --- View stack for file navigation ---
#define BRO_MAX_VIEWS 32

// Saved state of the main view when a file is opened.
typedef struct {
    hunk const *hunks;
    u32 nhunks;
    range32 *lines;
    Brange32 linesbuf;
    u32 nlines;
    u32 scroll;
} BROsave;

// Resources owned by a file view (one opened file).
// Tokens live in the shared bro_state->toks arena; hunk.toks slices it.
typedef struct {
    u8bp mapped;    // mmap'd file
    hunk hunk;      // inline hunk (title + text + toks, no hili)
} BROfileview;

typedef struct {
    hunk const *hunks;
    u32 nhunks;
    range32 *lines;    // line index array (heap buffer)
    Brange32 linesbuf; // buffer owning lines memory
    u32 nlines;        // total line count
    u32 scroll;        // first visible line
    u16 rows, cols;    // terminal dimensions
    char search[256];  // current search pattern
    u32 search_len;    // length of search pattern
    struct termios orig_termios;  // saved terminal state
    int tty_fd;        // /dev/tty for keyboard (stdin may be data pipe)
    b8 raw_mode;       // whether terminal is in raw mode
    b8 mouse_on;       // mouse tracking active (toggled with 'm')
    char flash[128];   // one-shot status bar message (cleared after display)
    // View stack
    BROsave saves[BRO_MAX_VIEWS];
    BROfileview files[BRO_MAX_VIEWS];
    int nsaves;
} BROstate;

// Global for signal handler
static volatile sig_atomic_t bro_resized = 0;

static void bro_winch_handler(int sig) {
    (void)sig;
    bro_resized = 1;
}

// --- Terminal setup ---

static ok64 BRORawEnable(BROstate *st) {
    sane(st != NULL);
    // Open /dev/tty so keyboard input works even when stdin is a data pipe.
    if (st->tty_fd < 0) {
        st->tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY);
        if (st->tty_fd < 0) fail(FAILSANITY);
    }
    if (tcgetattr(st->tty_fd, &st->orig_termios) < 0)
        fail(FAILSANITY);
    struct termios raw = st->orig_termios;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= (tcflag_t)~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= (tcflag_t)~(OPOST);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;  // 100ms timeout
    if (tcsetattr(st->tty_fd, TCSAFLUSH, &raw) < 0)
        fail(FAILSANITY);
    st->raw_mode = YES;
    done;
}

static void BRORawDisable(BROstate *st) {
    if (st->raw_mode) {
        tcsetattr(st->tty_fd, TCSAFLUSH, &st->orig_termios);
        st->raw_mode = NO;
    }
    if (st->tty_fd >= 0) {
        close(st->tty_fd);
        st->tty_fd = -1;
    }
}

static void BROGetSize(BROstate *st) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        st->rows = ws.ws_row;
        st->cols = ws.ws_col;
    } else {
        st->rows = 24;
        st->cols = 80;
    }
}

// Forward declarations for functions used before definition.
static void BROScrollCenter(BROstate *st, u32 target);
static b8 bro_is_source_start(hunkc const *hunks, range32 const *lines,
                              u32 nlines, u32 i);
static void BROReadSpot(BROstate *st, char *buf, int bufsz,
                        char const *prompt);
static ok64 BROForkSpot(BROstate *st, char const *flag,
                        char const *token, char const *filepath,
                        char const *repo);
static u32 BROSearchNext(BROstate *st, u32 from, int direction);

// --- Build line index ---

// Walk one display row forward from `off` inside `text`: advance at most
// `cols` codepoints, stop on '\n' (not consumed), stop at end.  Returns
// the byte offset where the row ends (exclusive).
static u32 bro_row_end(u8csc text, u32 tlen, u32 off, u32 cols) {
    u32 cp = 0;
    while (off < tlen && cp < cols && text[0][off] != '\n') {
        u8 ch = text[0][off];
        u32 clen = UTF8_LEN[ch >> 4];
        if (clen == 0 || off + clen > tlen) clen = 1;
        off += clen;
        cp++;
    }
    return off;
}

u32 BROCountLines(hunkc const *hunks, u32 nhunks, u32 cols) {
    if (cols == 0) cols = 1;
    u32 total = 0;
    for (u32 h = 0; h < nhunks; h++) {
        if (hunk_has_title(&hunks[h])) total++;
        u32 tlen = (u32)$len(hunks[h].text);
        if (tlen == 0) continue;
        a_dup(u8 const, text, hunks[h].text);
        u32 off = 0;
        while (off < tlen) {
            total++;
            u32 end = bro_row_end(text, tlen, off, cols);
            if (end < tlen && text[0][end] == '\n') end++;
            if (end >= tlen) break;
            off = end;
        }
    }
    return total;
}

static ok64 BROBuildIndex(BROstate *st) {
    sane(st != NULL && st->hunks != NULL);

    u32 cols = st->cols > 0 ? st->cols : 80;
    u32 total = BROCountLines(st->hunks, st->nhunks, cols);
    u32 cap = total > 0 ? total : 1;
    ok64 lo = range32bAlloc(st->linesbuf, cap);
    if (lo != OK) fail(NOROOM);
    st->lines = st->linesbuf[0];
    st->nlines = BROAppendLines(st->lines, 0, total,
                                st->hunks, 0, st->nhunks, cols);
    done;
}

// --- Directory listing ---
// Build a hunk for a directory listing. Each entry is a line tagged 'F'.
// Directories get a trailing '/' (FILEScan already yields dir paths with
// a trailing slash).

// Reference point passed to the FILEScan callback: where the text+toks
// blocks began for *this* listing pass, so each entry can write its
// offsets into bro_arena / bro_state->toks.
typedef struct {
    u8p  text_start;
} listdir_ctx;

static ok64 listdir_emit(void0p arg, path8p path) {
    listdir_ctx *ctx = (listdir_ctx *)arg;
    // FILEScan appends '/' to directory paths. Peel it before taking
    // the basename — PATHu8sBase of "bro/test/" would be empty.
    a_dup(u8c, full, u8bDataC(path));
    b8 is_dir = NO;
    if (!$empty(full) && *$last(full) == '/') {
        is_dir = YES;
        u8csShed1(full);
    }
    u8cs name = {};
    PATHu8sBase(name, full);
    if ($empty(name)) return OK;

    u8p wp = BROArenaWrite(name[0], (size_t)$len(name));
    if (wp == NULL) return OK;
    u32 name_end = (u32)(u8bIdleHead(bro_arena) - ctx->text_start);
    u32bFeed1(bro_state->toks, tok32Pack('F', name_end));
    if (is_dir) {
        BROArenaWrite("/", 1);
        u32 sl_end = (u32)(u8bIdleHead(bro_arena) - ctx->text_start);
        u32bFeed1(bro_state->toks, tok32Pack('P', sl_end));
    }
    BROArenaWrite("\n", 1);
    u32 nl_end = (u32)(u8bIdleHead(bro_arena) - ctx->text_start);
    u32bFeed1(bro_state->toks, tok32Pack('W', nl_end));
    return OK;
}

ok64 BROListDir(u8csc dirpath) {
    sane(!$empty(dirpath));
    if (hunkbIdleLen(bro_state->hunks) == 0) fail(NOROOM);

    a_path(dir);
    call(PATHu8bFeed, dir, dirpath);

    // Snapshot arena/toks heads so the callback's entries can be
    // sliced into this hunk's text/toks ranges.
    listdir_ctx ctx = {.text_start = u8bIdleHead(bro_arena)};
    u32 *tok_start = u32bIdleHead(bro_state->toks);

    call(FILEScan, dir, FILE_SCAN_ALL, listdir_emit, &ctx);

    u8p text_end = u8bIdleHead(bro_arena);
    if (text_end == ctx.text_start) done;  // empty dir

    u32 *tok_end = u32bIdleHead(bro_state->toks);
    hunk *hk = hunkbIdleHead(bro_state->hunks);
    *hk = (hunk){};

    // URI = dirpath
    size_t dl = (size_t)$len(dirpath);
    u8p up = BROArenaWrite(dirpath[0], dl);
    if (up) { hk->uri[0] = up; hk->uri[1] = up + dl; }

    hk->text[0] = ctx.text_start;
    hk->text[1] = text_end;
    hk->toks[0] = (u32cp)tok_start;
    hk->toks[1] = (u32cp)tok_end;

    BROHunkAdd();
    done;
}

// --- Tokenize helper ---
// Tokenize source into the active bro state's shared `toks` arena
// and set hk->toks to point at the freshly-written slice. Returns
// YES on success, NO otherwise (unknown ext, arena exhausted, …).
b8 BROTokenize(hunk *hk, u8csc pathslice) {
    if (bro_state == NULL) return NO;
    u8cs ext = {};
    a_dup(u8c, ps, pathslice);
    PATHu8sExt(ext, ps);
    if ($empty(ext) || !TOKKnownExt(ext)) return NO;

    u32 srclen = (u32)$len(hk->text);
    if (u32bIdleLen(bro_state->toks) < (size_t)srclen + 1) return NO;

    u32 *begin = u32bIdleHead(bro_state->toks);
    u8cs source = {hk->text[0], hk->text[1]};
    if (HUNKu32bTokenize(bro_state->toks, source, ext) != OK) return NO;
    u32 *end = u32bIdleHead(bro_state->toks);

    u32 *dts[2] = {begin, end};
    DEFMark(dts, source, ext);
    hk->toks[0] = (u32cp)begin;
    hk->toks[1] = (u32cp)end;
    return YES;
}

// --- File view open / back ---

// Open a file by repo-relative path, push current view onto stack.
// `repo` is the NUL-terminated repo root path.  Returns OK if the
// file was opened (st is updated in place); non-OK on error (st unchanged).
static ok64 BROOpenFile(BROstate *st, u8csc relpath, char const *repo,
                        u32 target_line) {
    sane(st != NULL && !$empty(relpath) && repo != NULL);
    if (st->nsaves >= BRO_MAX_VIEWS) fail(NOROOM);

    // Build absolute path: repo/relpath.  PATHu8bPush rejects
    // multi-segment names, so PATHu8bAdd drains relpath by segments
    // and pushes each separately (handles `dir/sub/file.c`).
    a_path(fpbuf);
    {
        a_cstr(repo_s, repo);
        call(PATHu8bFeed, fpbuf, repo_s);
        u8cg rel_g = {relpath[0], relpath[0], relpath[1]};
        call(PATHu8bAdd, fpbuf, rel_g);
    }

    // Map file
    u8bp mapped = NULL;
    ok64 mo = FILEMapRO(&mapped, $path(fpbuf));
    if (mo != OK) fail(mo);

    int idx = st->nsaves;
    BROfileview *fv = &st->files[idx];
    *fv = (BROfileview){};
    fv->mapped = mapped;

    u8cp src_head = u8bDataHead(mapped);
    u8cp src_idle = u8bIdleHead(mapped);

    fv->hunk = (hunk){};
    fv->hunk.text[0] = src_head;
    fv->hunk.text[1] = src_idle;

    // Copy URI (= path) into arena
    u8p pp = BROArenaWrite(relpath[0], (size_t)$len(relpath));
    if (pp) {
        fv->hunk.uri[0] = pp;
        fv->hunk.uri[1] = pp + $len(relpath);
    }

    BROTokenize(&fv->hunk, relpath);

    // Save current view
    BROsave *sv = &st->saves[idx];
    sv->hunks = st->hunks;
    sv->nhunks = st->nhunks;
    sv->lines = st->lines;
    memcpy(sv->linesbuf, st->linesbuf, sizeof(Brange32));
    sv->nlines = st->nlines;
    sv->scroll = st->scroll;

    // Switch to file view
    st->hunks = &fv->hunk;
    st->nhunks = 1;
    memset(st->linesbuf, 0, sizeof(Brange32));
    call(BROBuildIndex, st);
    // Scroll to target line (1-based file line number).
    // Count only source-line starts — wrap continuations share the
    // same source line number and must not bump the counter.
    if (target_line > 0 && st->nlines > 1) {
        u32 file_ln = 0;
        u32 best = 1;
        for (u32 i = 0; i < st->nlines; i++) {
            if (!bro_is_source_start(st->hunks, st->lines, st->nlines, i))
                continue;
            file_ln++;
            if (file_ln == target_line) { best = i; break; }
            best = i;
        }
        BROScrollCenter(st, best);
    } else {
        st->scroll = (st->nlines > 1) ? 1 : 0;
    }
    st->nsaves = idx + 1;
    done;
}

// Go back to the previous view. Frees the current file view's resources.
static b8 BROBack(BROstate *st) {
    if (st->nsaves <= 0) return NO;
    st->nsaves--;
    int idx = st->nsaves;

    // Free file view resources (tokens live in shared arena).
    BROfileview *fv = &st->files[idx];
    if (fv->mapped != NULL) FILEUnMap(fv->mapped);
    *fv = (BROfileview){};

    // Free current line index
    range32bFree(st->linesbuf);

    // Restore saved view
    BROsave *sv = &st->saves[idx];
    st->hunks = sv->hunks;
    st->nhunks = sv->nhunks;
    st->lines = sv->lines;
    memcpy(st->linesbuf, sv->linesbuf, sizeof(Brange32));
    st->nlines = sv->nlines;
    st->scroll = sv->scroll;
    return YES;
}

// Try to open the file/dir referenced by the hunk at the given line.
// For directory listings, the line text IS the filename; the hunk URI
// is the directory. Constructs dir/filename and opens.
static b8 BROTryOpen(BROstate *st, u32 line, char const *repo) {
    if (line >= st->nlines) return NO;
    range32 *ln = &st->lines[line];
    u32 hunk_idx = ln->lo;
    hunk const *hk = &st->hunks[hunk_idx];
    BROloc loc = {};
    BROHunkLoc(&loc, hk);

    // If this is a content line (not title), check if the hunk is a
    // dir listing. In that case the line text is the entry name.
    if (ln->hi != BRO_TITLE_LINE && !$empty(loc.path)) {
        u32 textlen = (u32)$len(hk->text);
        u32 off = ln->hi;
        u32 end = off;
        while (end < textlen && hk->text[0][end] != '\n') end++;
        if (end > off) {
            u32 elen = end - off;
            // Strip trailing '/' for dirs
            b8 is_dir = (hk->text[0][end - 1] == '/');
            if (is_dir) elen--;
            // Build full path: dir/entry
            a_path(fpbufA);
            a_rest(u8c, after, hk->text, off);
            a_head(u8c, entry, after, elen);
            if (PATHu8bFeed(fpbufA, loc.path) != OK) return NO;
            if (PATHu8bPush(fpbufA, entry) != OK) return NO;
            {
                if (repo == NULL || repo[0] == 0) {
                    snprintf(st->flash, sizeof(st->flash), "no repo root");
                    return NO;
                }
                if (is_dir) {
                    // Open directory listing
                    if (st->nsaves >= BRO_MAX_VIEWS) return NO;
                    int idx = st->nsaves;
                    st->saves[idx] = (BROsave){
                        .hunks = st->hunks, .nhunks = st->nhunks,
                        .lines = st->lines, .nlines = st->nlines,
                        .scroll = st->scroll};
                    memcpy(st->saves[idx].linesbuf, st->linesbuf,
                           sizeof(Brange32));
                    st->files[idx] = (BROfileview){};
                    u32 save_nh = bro_nhunks;
                    if (BROListDir(u8bDataC(fpbufA)) == OK && bro_nhunks > save_nh) {
                        st->hunks = bro_hunks + save_nh;
                        st->nhunks = bro_nhunks - save_nh;
                        memset(st->linesbuf, 0, sizeof(Brange32));
                        BROBuildIndex(st);
                        st->scroll = (st->nlines > 1) ? 1 : 0;
                        st->nsaves = idx + 1;
                        return YES;
                    }
                    return NO;
                }
                ok64 o = BROOpenFile(st, u8bDataC(fpbufA), repo, 0);
                if (o != OK) {
                    snprintf(st->flash, sizeof(st->flash),
                             "open: " U8SFMT ": %s",
                             u8sFmt(u8bDataC(fpbufA)), ok64str(o));
                    return NO;
                }
                return YES;
            }
        }
    }

    // Normal hunk: open path from URI
    if ($empty(loc.path)) {
        snprintf(st->flash, sizeof(st->flash), "no path in hunk");
        return NO;
    }
    if (repo == NULL || repo[0] == 0) {
        snprintf(st->flash, sizeof(st->flash), "no repo root found");
        return NO;
    }
    ok64 o = BROOpenFile(st, loc.path, repo, loc.line);
    if (o != OK) {
        snprintf(st->flash, sizeof(st->flash),
                 "open: " U8SFMT ": %s",
                 u8sFmt(loc.path), ok64str(o));
        return NO;
    }
    return YES;
}

// --- Navigation primitives ---
// These walk the line index built by BROBuildIndex (or
// BROExtendIndex). They are exposed via BRO.h for tests, so they take
// raw arrays rather than BROstate.

static b8 bro_hili_real(u8 tag) {
    return (tag != 0 && tag != 'A') ? YES : NO;
}

// Display line `i` is the first row of its source line (i.e. not a
// wrap continuation of a longer source line).  Title rows return NO.
static b8 bro_is_source_start(hunkc const *hunks, range32 const *lines,
                              u32 nlines, u32 i) {
    if (i >= nlines) return NO;
    range32 const *ln = &lines[i];
    if (ln->hi == BRO_TITLE_LINE) return NO;
    if (i == 0 || ln->hi == 0) return YES;
    range32 const *prev = &lines[i - 1];
    if (prev->lo != ln->lo) return YES;
    if (prev->hi == BRO_TITLE_LINE) return YES;
    return (hunks[ln->lo].text[0][ln->hi - 1] == '\n') ? YES : NO;
}

// Find the line that contains byte offset `off` in hunk `h`.
// Returns the largest line index i with lines[i].lo == h,
// lines[i].hi != BRO_TITLE_LINE, and lines[i].hi <= off.
// BRO_NONE if no such line exists.
static u32 bro_line_for_off(range32 const *lines, u32 nlines,
                            u32 h, u32 off) {
    u32 best = BRO_NONE;
    for (u32 i = 0; i < nlines; i++) {
        if (lines[i].lo < h) continue;
        if (lines[i].lo > h) break;  // hunks are appended in order
        if (lines[i].hi == BRO_TITLE_LINE) continue;
        if (lines[i].hi <= off) best = i;
        else break;
    }
    return best;
}

u32 BROHunkNextLine(range32 const *lines, u32 nlines, u32 from) {
    if (nlines == 0) return BRO_NONE;
    u32 start = (from + 1 < nlines) ? (from + 1) : nlines;
    for (u32 i = start; i < nlines; i++) {
        if (lines[i].lo != lines[i - 1].lo) return i;
    }
    return BRO_NONE;
}

u32 BROHunkPrevLine(range32 const *lines, u32 nlines, u32 from) {
    if (nlines == 0 || from == 0) return BRO_NONE;
    if (from >= nlines) from = nlines - 1;
    // Walk back to the start line of the current hunk.
    u32 i = from;
    while (i > 0 && lines[i - 1].lo == lines[i].lo) i--;
    if (i < from) return i;  // mid-hunk: jump to start of current
    // Already at the current hunk's start; step into the previous hunk.
    if (i == 0) return BRO_NONE;
    i--;
    while (i > 0 && lines[i - 1].lo == lines[i].lo) i--;
    return i;
}

u32 BROHunkCount(range32 const *lines, u32 nlines) {
    if (nlines == 0) return 0;
    u32 n = 1;
    for (u32 i = 1; i < nlines; i++)
        if (lines[i].lo != lines[i - 1].lo) n++;
    return n;
}

u32 BROHunkIndexAt(range32 const *lines, u32 nlines, u32 at) {
    if (nlines == 0) return 0;
    if (at >= nlines) at = nlines - 1;
    u32 n = 1;
    for (u32 i = 1; i <= at; i++)
        if (lines[i].lo != lines[i - 1].lo) n++;
    return n;
}

u32 BROHiliCount(hunk const *hunks, u32 nhunks) {
    u32 n = 0;
    for (u32 h = 0; h < nhunks; h++) {
        u32 nh = (u32)$len(hunks[h].hili);
        for (u32 j = 0; j < nh; j++)
            if (bro_hili_real(tok32Tag(hunks[h].hili[0][j]))) n++;
    }
    return n;
}

u32 BROHiliIndexAt(hunk const *hunks, u32 nhunks,
                   range32 const *lines, u32 nlines, u32 at) {
    u32 n = 0;
    for (u32 h = 0; h < nhunks; h++) {
        u32 nh = (u32)$len(hunks[h].hili);
        for (u32 j = 0; j < nh; j++) {
            tok32 t = hunks[h].hili[0][j];
            if (!bro_hili_real(tok32Tag(t))) continue;
            u32 start_off = (j == 0) ? 0
                          : tok32Offset(hunks[h].hili[0][j - 1]);
            u32 ln = bro_line_for_off(lines, nlines, h, start_off);
            if (ln == BRO_NONE) continue;
            if (ln <= at) n++;
            else return n;
        }
    }
    return n;
}

u32 BROHiliNextLine(hunk const *hunks, u32 nhunks,
                    range32 const *lines, u32 nlines, u32 mid) {
    for (u32 h = 0; h < nhunks; h++) {
        u32 nh = (u32)$len(hunks[h].hili);
        for (u32 j = 0; j < nh; j++) {
            tok32 t = hunks[h].hili[0][j];
            if (!bro_hili_real(tok32Tag(t))) continue;
            u32 start_off = (j == 0) ? 0
                          : tok32Offset(hunks[h].hili[0][j - 1]);
            u32 ln = bro_line_for_off(lines, nlines, h, start_off);
            if (ln == BRO_NONE) continue;
            if (ln > mid) return ln;
        }
    }
    return BRO_NONE;
}

u32 BROHiliPrevLine(hunk const *hunks, u32 nhunks,
                    range32 const *lines, u32 nlines, u32 mid) {
    u32 best = BRO_NONE;
    for (u32 h = 0; h < nhunks; h++) {
        u32 nh = (u32)$len(hunks[h].hili);
        for (u32 j = 0; j < nh; j++) {
            tok32 t = hunks[h].hili[0][j];
            if (!bro_hili_real(tok32Tag(t))) continue;
            u32 start_off = (j == 0) ? 0
                          : tok32Offset(hunks[h].hili[0][j - 1]);
            u32 ln = bro_line_for_off(lines, nlines, h, start_off);
            if (ln == BRO_NONE) continue;
            if (ln >= mid) return best;
            best = ln;
        }
    }
    return best;
}

// --- Rendering ---
// All screen output is built into bro_scr[] buffer, flushed once.

#define BRO_SCR_SIZE (1UL << 20)  // 1MB screen buffer
static Bu8 bro_scr = {};

static ok64 BROScreenInit(void) {
    if (bro_scr[0] != NULL) { u8bReset(bro_scr); return OK; }
    return u8bMap(bro_scr, BRO_SCR_SIZE);
}

static void BROScreenFlush(void) {
    if (u8bDataLen(bro_scr) > 0)
        (void)write(STDOUT_FILENO, u8bDataHead(bro_scr), u8bDataLen(bro_scr));
    u8bReset(bro_scr);
}

// Feed string literal (use scr_puts("text") only with literals/known-len)
static void scr_puts(char const *s) {
    a_cstr(cs, s);
    u8sFeed(u8bIdle(bro_scr), cs);
}

// Feed goto escape: \033[row;colH
static void scr_goto(int row, int col) {
    a_pad(u8, tmp, 32);
    u8sFeed1(tmp_idle, 033);
    u8sFeed1(tmp_idle, '[');
    utf8sFeed10(tmp_idle, (u64)row);
    u8sFeed1(tmp_idle, ';');
    utf8sFeed10(tmp_idle, (u64)col);
    u8sFeed1(tmp_idle, 'H');
    u8bFeed(bro_scr, u8bDataC(tmp));
}

// Direct write helpers (for prompts/setup, not screen rendering)
static void bro_puts(char const *s) {
    a_cstr(cs, s);
    (void)write(STDOUT_FILENO, cs[0], $len(cs));
}
static void bro_write(u8csc s) {
    (void)write(STDOUT_FILENO, s[0], $len(s));
}
static void bro_goto(int row, int col) {
    a_pad(u8, tmp, 32);
    u8sFeed1(tmp_idle, 033);
    u8sFeed1(tmp_idle, '[');
    utf8sFeed10(tmp_idle, (u64)row);
    u8sFeed1(tmp_idle, ';');
    utf8sFeed10(tmp_idle, (u64)col);
    u8sFeed1(tmp_idle, 'H');
    bro_write(u8bDataC(tmp));
}

// Feed one byte with fg tag, bg tag, and search highlight
static void scr_emit_char(u8cp p, u32 n, u8 fg_tag, u8 bg_tag, b8 in_search) {
    b8 bold = NO;
    int fg = BROTagColor(fg_tag, &bold);
    b8 is_ins = (bg_tag == 'I');
    b8 is_del = (bg_tag == 'D');

    u8sp out = u8bIdle(bro_scr);
    if (fg != 0 || bold || is_ins || is_del || in_search) {
        if (bold) escfeed(out, BOLD);
        if (fg < 0) {
            // 256-color FG: \033[38;5;Nm
            u8sFeed1(out, 033); u8sFeed1(out, '[');
            u8sFeed1(out, '3'); u8sFeed1(out, '8');
            u8sFeed1(out, ';'); u8sFeed1(out, '5'); u8sFeed1(out, ';');
            utf8sFeed10(out, (u64)(-fg));
            u8sFeed1(out, 'm');
        } else if (fg > 0) {
            escfeed(out, (u8)fg);
        }
        if (is_ins) escfeedBG256(out, 157);
        else if (is_del) escfeedBG256(out, 217);
        else if (in_search) escfeed(out, 7);
        u8cs chars = {p, p + n};
        u8sFeed(out, chars);
        escfeed(out, 0);  // reset
    } else {
        u8cs chars = {p, p + n};
        u8sFeed(out, chars);
    }
}

// Check if search pattern matches at position pos
static b8 bro_search_at(BROstate *st, u8csc text, u32 pos) {
    if (st->search_len == 0) return NO;
    if (pos + st->search_len > (u32)$len(text)) return NO;
    u8cs hay = {text[0] + pos, text[0] + pos + st->search_len};
    u8cs ndl = {(u8cp)st->search, (u8cp)st->search + st->search_len};
    return $eq(hay, ndl);
}

static void BROStatusBar(BROstate *st);

// Format display title "--- path :: func ---" into buf.
// Returns the number of bytes written (excl NUL).
static int bro_format_title(char *buf, size_t bufsz, hunkc const *hk) {
    BROloc loc = {};
    BROHunkLoc(&loc, hk);
    char pathz[FILE_PATH_MAX_LEN] = {};
    char funcz[256] = {};
    if (!$empty(loc.path)) {
        size_t pl = (size_t)$len(loc.path);
        if (pl >= sizeof(pathz)) pl = sizeof(pathz) - 1;
        memcpy(pathz, loc.path[0], pl);
    }
    if (!$empty(loc.symbol)) {
        size_t fl = (size_t)$len(loc.symbol);
        if (fl >= sizeof(funcz)) fl = sizeof(funcz) - 1;
        memcpy(funcz, loc.symbol[0], fl);
    }
    int n = 0;
    if (pathz[0] && funcz[0] && loc.line > 0)
        n = snprintf(buf, bufsz, "--- %s :: %s:%u ---", pathz, funcz, loc.line);
    else if (pathz[0] && funcz[0])
        n = snprintf(buf, bufsz, "--- %s :: %s ---", pathz, funcz);
    else if (pathz[0] && loc.line > 0)
        n = snprintf(buf, bufsz, "--- %s:%u ---", pathz, loc.line);
    else if (pathz[0])
        n = snprintf(buf, bufsz, "--- %s ---", pathz);
    else if (funcz[0])
        n = snprintf(buf, bufsz, "--- %s ---", funcz);
    if (n < 0) n = 0;
    if ((size_t)n >= bufsz) n = (int)(bufsz - 1);
    return n;
}

static void BRORender(BROstate *st) {
    u8bReset(bro_scr);
    scr_puts(TTY_CUR_HOME);

    u32 visible = (u32)(st->rows - 1);
    if (st->nlines > visible) {
        if (st->scroll > st->nlines - visible)
            st->scroll = st->nlines - visible;
    } else {
        st->scroll = 0;
    }
    u32 end = st->scroll + visible;
    if (end > st->nlines) end = st->nlines;

    for (u32 vi = st->scroll; vi < end; vi++) {
        scr_goto((int)(vi - st->scroll + 1), 1);
        scr_puts(TTY_ERASE_LINE);

        range32 *ln = &st->lines[vi];
        hunk const *hk = &st->hunks[ln->lo];

        if (ln->hi == BRO_TITLE_LINE) {
            scr_puts(BRO_TITLE_COLOR);
            char dtitle[HUNK_TITLE_MAX + 1];
            int dtlen = bro_format_title(dtitle, sizeof(dtitle), hk);
            u32 w = (u32)dtlen < st->cols ? (u32)dtlen : st->cols;
            u8cs ttl = {(u8cp)dtitle, (u8cp)dtitle + w};
            u8sFeed(u8bIdle(bro_scr), ttl);
            scr_puts(TTY_RESET);
            continue;
        }

        u32 textlen = (u32)$len(hk->text);
        u32 off = ln->hi;
        a_dup(u8 const, txts, hk->text);
        u32 cols = st->cols > 0 ? st->cols : 80;
        u32 line_end = bro_row_end(txts, textlen, off, cols);
        u32 w = line_end - off;

        // Find tok cursor for this offset
        int ntoks = (int)$len(hk->toks);
        int tok_i = 0;
        while (tok_i < ntoks &&
               tok32Offset(hk->toks[0][tok_i]) <= off)
            tok_i++;

        int nhili = (int)$len(hk->hili);
        int hili_i = 0;
        while (hili_i < nhili &&
               tok32Offset(hk->hili[0][hili_i]) <= off)
            hili_i++;

        // Carry-over byte counter so a multi-byte search match stays
        // highlighted across the whole run, not just its first char.
        // Seed from any match that started in the previous wrap segment
        // of the same source line (search can span wrap, not '\n').
        u32 search_left = 0;
        if (st->search_len > 1 && off > 0) {
            u32 src_start = off;
            while (src_start > 0 && hk->text[0][src_start - 1] != '\n')
                src_start--;
            u32 back = st->search_len - 1;
            if (off - src_start < back) back = off - src_start;
            for (u32 k = back; k >= 1; k--) {
                u32 bp = off - k;
                if (bro_search_at(st, hk->text, bp)) {
                    search_left = st->search_len - k;
                    break;
                }
            }
        }
        for (u32 j = 0; j < w; ) {
            u32 pos = off + j;
            u8 ch = hk->text[0][pos];
            u32 clen = UTF8_LEN[ch >> 4];
            if (clen > w - j) clen = w - j;  // clamp to line end
            // Advance cursors past pos
            while (tok_i < ntoks &&
                   tok32Offset(hk->toks[0][tok_i]) <= pos)
                tok_i++;
            u8 fg_tag = (tok_i < ntoks)
                            ? tok32Tag(hk->toks[0][tok_i]) : 'S';
            while (hili_i < nhili &&
                   tok32Offset(hk->hili[0][hili_i]) <= pos)
                hili_i++;
            u8 bg_tag = (hili_i < nhili)
                            ? tok32Tag(hk->hili[0][hili_i]) : 'A';
            if (search_left == 0 && bro_search_at(st, hk->text, pos))
                search_left = st->search_len;
            b8 in_search = (search_left > 0) ? YES : NO;
            scr_emit_char(hk->text[0] + pos, clen, fg_tag, bg_tag, in_search);
            if (search_left >= clen) search_left -= clen;
            else search_left = 0;
            j += clen;
        }
    }

    for (u32 row = end - st->scroll + 1; row < st->rows; row++) {
        scr_goto((int)row, 1);
        scr_puts(TTY_ERASE_LINE);
    }

    BROStatusBar(st);
    BROScreenFlush();
}

// Set st->scroll so that line `target` lands on the middle row.
// Clamps to [0, nlines - page].
static void BROScrollCenter(BROstate *st, u32 target) {
    u32 page = (st->rows > 1) ? (u32)(st->rows - 1) : 1;
    u32 half = page / 2;
    u32 s = (target > half) ? (target - half) : 0;
    if (st->nlines > page && s > st->nlines - page)
        s = st->nlines - page;
    st->scroll = s;
}

static void BROStatusBar(BROstate *st) {
    scr_goto(st->rows, 1);
    scr_puts(TTY_INVERSE TTY_ERASE_LINE);

    // Flash message: show it and clear for next render.
    if (st->flash[0]) {
        u8sp out = u8bIdle(bro_scr);
        int slen = snprintf((char *)out[0], $len(out),
                            " %s", st->flash);
        if (slen > 0) {
            if ((u32)slen > st->cols) slen = (int)st->cols;
            u8sFed(out, (size_t)slen);
        }
        scr_puts(TTY_RESET);
        st->flash[0] = 0;
        return;
    }

    u32 cur_hunk = 0;
    if (st->scroll < st->nlines)
        cur_hunk = st->lines[st->scroll].lo;

    u32 hunk_tot = BROHunkCount(st->lines, st->nlines);
    u32 hunk_idx = BROHunkIndexAt(st->lines, st->nlines, st->scroll);
    u32 hili_tot = BROHiliCount(st->hunks, st->nhunks);
    u32 hili_idx = BROHiliIndexAt(st->hunks, st->nhunks,
                                  st->lines, st->nlines, st->scroll);

    hunk const *ch = &st->hunks[cur_hunk];

    // Scroll position as percentage (source line numbers are in the
    // URI, not the local index — see project docs).  ALL means the
    // whole view fits on screen; TOP / BOT are the endpoints.
    char posbuf[8];
    u32 visible = (st->rows > 1) ? (u32)(st->rows - 1) : 1;
    if (st->nlines <= visible)
        snprintf(posbuf, sizeof(posbuf), "ALL");
    else if (st->scroll == 0)
        snprintf(posbuf, sizeof(posbuf), "TOP");
    else if (st->scroll + visible >= st->nlines)
        snprintf(posbuf, sizeof(posbuf), "BOT");
    else {
        u32 max_scroll = st->nlines - visible;
        u32 pct = (u32)((u64)st->scroll * 100 / max_scroll);
        if (pct > 99) pct = 99;  // reserve 100% for BOT
        snprintf(posbuf, sizeof(posbuf), "%u%%", pct);
    }

    // Build the right-side stats first so we know how much room the
    // title gets.  Use a small local buffer (stats are short).
    char stats[128];
    int sn;
    if (hili_tot > 0 && st->search_len > 0)
        sn = snprintf(stats, sizeof(stats),
                      "  %s  H%u/%u  C%u/%u  [/%.*s]",
                      posbuf,
                      hunk_idx, hunk_tot, hili_idx, hili_tot,
                      (int)st->search_len, st->search);
    else if (hili_tot > 0)
        sn = snprintf(stats, sizeof(stats),
                      "  %s  H%u/%u  C%u/%u",
                      posbuf,
                      hunk_idx, hunk_tot, hili_idx, hili_tot);
    else if (st->search_len > 0)
        sn = snprintf(stats, sizeof(stats),
                      "  %s  H%u/%u  [/%.*s]",
                      posbuf,
                      hunk_idx, hunk_tot,
                      (int)st->search_len, st->search);
    else
        sn = snprintf(stats, sizeof(stats),
                      "  %s  H%u/%u",
                      posbuf,
                      hunk_idx, hunk_tot);
    if (sn < 0) sn = 0;
    if ((size_t)sn >= sizeof(stats)) sn = (int)(sizeof(stats) - 1);

    // Format display title for current hunk.
    char dtitle[HUNK_TITLE_MAX + 1];
    int dtlen = bro_format_title(dtitle, sizeof(dtitle), ch);

    // Truncate title to fit: " <title><stats>" within cols.
    u32 cols = st->cols;
    u32 stats_w = (u32)sn;
    u32 title_max = (cols > stats_w + 2) ? (cols - stats_w - 1) : 0;
    u32 title_len = (u32)dtlen;
    if (title_len > title_max) title_len = title_max;

    // Layout: " <title><padding><stats>" exactly cols wide.
    u32 left_len = 1 + title_len;
    u32 pad = (cols > left_len + stats_w) ? (cols - left_len - stats_w) : 0;

    u8sp out = u8bIdle(bro_scr);
    int slen = snprintf((char *)out[0], $len(out),
                        " %.*s%*s%s",
                        (int)title_len, dtitle,
                        (int)pad, "",
                        stats);
    if (slen > 0) {
        if ((u32)slen > cols) slen = (int)cols;
        u8sFed(out, (size_t)slen);
    }
    scr_puts(TTY_RESET);
}

// --- Search ---

// Find next occurrence of search pattern starting from line `from` (direction=+1)
// or backwards from `from` (direction=-1). Returns line index or UINT32_MAX.
//
// A match is reported on the display row whose first byte contains the
// match's start.  The match body may extend past the row's end into a
// wrap continuation (same source line) but not across a '\n'.
static u32 BROSearchNext(BROstate *st, u32 from, int direction) {
    if (st->search_len == 0) return UINT32_MAX;
    u32 i = from;
    for (;;) {
        if (direction > 0) {
            i++;
            if (i >= st->nlines) return UINT32_MAX;
        } else {
            if (i == 0) return UINT32_MAX;
            i--;
        }
        range32 *ln = &st->lines[i];
        if (ln->hi == BRO_TITLE_LINE) continue;
        hunk const *hk = &st->hunks[ln->lo];
        u32 textlen = (u32)$len(hk->text);
        u32 off = ln->hi;
        // Byte span of this display row (bounded by next row in same
        // source line, else source-line end at '\n').
        u32 row_end;
        if (i + 1 < st->nlines && st->lines[i + 1].lo == ln->lo &&
            st->lines[i + 1].hi != BRO_TITLE_LINE) {
            u32 nhi = st->lines[i + 1].hi;
            // Continuation if no '\n' between; otherwise nhi sits past
            // the '\n'.  Either way, the row's first-byte limit is nhi
            // (continuations) or the '\n' (new source line).
            row_end = (nhi > off && hk->text[0][nhi - 1] == '\n')
                      ? nhi - 1 : nhi;
        } else {
            row_end = off;
            while (row_end < textlen && hk->text[0][row_end] != '\n')
                row_end++;
        }
        // Match body may extend up to the source-line end.
        u32 src_end = row_end;
        while (src_end < textlen && hk->text[0][src_end] != '\n')
            src_end++;
        u8cs ndl = {(u8cp)st->search, (u8cp)st->search + st->search_len};
        if (row_end > off && src_end - off >= st->search_len) {
            u32 first_byte_limit = row_end;
            u32 max_start = src_end - st->search_len;
            if (first_byte_limit > max_start + 1) first_byte_limit = max_start + 1;
            for (u32 j = 0; off + j < first_byte_limit; j++) {
                u8cs hay = {hk->text[0] + off + j,
                            hk->text[0] + off + j + st->search_len};
                if ($eq(hay, ndl)) return i;
            }
        }
    }
}

// Read search pattern from user (displayed in status bar)
static void BROReadSearch(BROstate *st) {
    st->search_len = 0;
    memset(st->search, 0, sizeof(st->search));

    for (;;) {
        // Render prompt on status bar
        bro_goto(st->rows, 1);
        bro_puts(TTY_INVERSE TTY_ERASE_LINE);
        bro_puts(" /");
        if (st->search_len > 0) {
            u8cs srch = {(u8cp)st->search, (u8cp)st->search + st->search_len};
            bro_write(srch);
        }
        bro_puts(TTY_RESET);

        u8 ch = 0;
        ssize_t n = read(st->tty_fd, &ch, 1);
        if (n <= 0) continue;
        if (ch == '\n' || ch == '\r') break;  // confirm
        if (ch == 27) {  // escape: cancel
            st->search_len = 0;
            break;
        }
        if (ch == 127 || ch == 8) {  // backspace
            if (st->search_len > 0) st->search_len--;
            continue;
        }
        if (ch >= 32 && st->search_len < sizeof(st->search) - 1) {
            st->search[st->search_len++] = (char)ch;
        }
    }
}

// Read line number from user (displayed in status bar)
// Strip trailing .ext from fragment text. Writes ext to ext_out
// (incl dot, e.g. ".c"), trims from frag in place. Returns YES if found.
static b8 bro_strip_ext(char *frag, char *ext_out, int ext_sz) {
    int fl = (int)strlen(frag);
    int di = fl;
    while (di > 0 && isalnum((u8)frag[di - 1])) di--;
    if (di <= 0 || frag[di - 1] != '.') return NO;
    int es = di - 1;
    if (es > 0 && frag[es - 1] != ' ' &&
        frag[es - 1] != '\'' && frag[es - 1] != '/') return NO;
    int elen = fl - es;
    if (elen <= 1 || elen >= ext_sz) return NO;
    memcpy(ext_out, frag + es, (size_t)elen);
    ext_out[elen] = 0;
    int trim = es;
    while (trim > 0 && frag[trim - 1] == ' ') trim--;
    frag[trim] = 0;
    return YES;
}

// Dispatch a GURI fragment (line/grep/snippet/regex) via spot.
// Handles ext stripping and default ext from current hunk.
static void BRODispatchFragment(BROstate *st, char *frag,
                                char const *repo) {
    if (frag[0] == 0) return;

    // Strip trailing .ext
    char ext_arg[16] = {};
    bro_strip_ext(frag, ext_arg, sizeof(ext_arg));
    if (frag[0] == 0) return;

    // Line number
    if (frag[0] >= '0' && frag[0] <= '9') {
        u32 target = (u32)atoi(frag);
        if (target > 0) target--;
        if (target >= st->nlines) target = st->nlines > 0 ? st->nlines - 1 : 0;
        st->scroll = target;
        return;
    }

    // Classify search type
    int fl = (int)strlen(frag);
    char const *flag = "-g";
    char const *pattern = frag;
    char unquoted[256] = {};
    if (fl >= 2 && frag[0] == '\'' && frag[fl - 1] == '\'') {
        flag = "-s";
        memcpy(unquoted, frag + 1, (size_t)(fl - 2));
        pattern = unquoted;
    } else if (fl >= 2 && frag[0] == '/' && frag[fl - 1] == '/') {
        flag = "-p";
        memcpy(unquoted, frag + 1, (size_t)(fl - 2));
        pattern = unquoted;
    }

    // Resolve ext: explicit > current hunk's ext
    char const *arg = NULL;
    char argz[16] = {};
    if (ext_arg[0]) {
        arg = ext_arg;
    } else if (st->scroll < st->nlines) {
        u32 hi = st->lines[st->scroll].lo;
        hunkc const *hk = &st->hunks[hi];
        BROloc loc2 = {};
        BROHunkLoc(&loc2, hk);
        if (!$empty(loc2.path)) {
            u8cs ext = {};
            a_dup(u8c, lp, loc2.path);
            PATHu8sExt(ext, lp);
            if (!$empty(ext)) {
                size_t el = (size_t)$len(ext);
                if (el + 1 < sizeof(argz)) {
                    argz[0] = '.';
                    memcpy(argz + 1, ext[0], el);
                    arg = argz;
                }
            }
        }
    }

    ok64 o = BROForkSpot(st, flag, pattern, arg, repo);
    if (o != OK && st->flash[0] == 0)
        snprintf(st->flash, sizeof(st->flash), "spot: %s", ok64str(o));
}

// Unified URI prompt. Accepts: line number, path, path#fragment,
// #fragment, or bare fragment. Uses abc/URI to parse.
static void BROReadURI(BROstate *st, char const *repo) {
    char buf[512] = {};
    BROReadSpot(st, buf, sizeof(buf), " : ");
    if (buf[0] == 0) return;

    // Parse with abc/URI
    u8cs input = {(u8cp)buf, (u8cp)buf + strlen(buf)};
    uri u = {};
    $mv(u.data, input);
    ok64 po = URILexer(&u);

    // If URI parsing fails, treat as plain goto-line or search
    if (po != OK) {
        if (buf[0] >= '0' && buf[0] <= '9') {
            u32 target = (u32)atoi(buf);
            if (target > 0) target--;
            if (target >= st->nlines)
                target = st->nlines > 0 ? st->nlines - 1 : 0;
            st->scroll = target;
        }
        return;
    }

    b8 has_path = !$empty(u.path);
    b8 has_frag = !$empty(u.fragment);

    // Path component → open file
    if (has_path) {
        // NUL-terminate path for BROOpenFile
        char pathz[FILE_PATH_MAX_LEN] = {};
        size_t pl = (size_t)$len(u.path);
        if (pl >= sizeof(pathz)) pl = sizeof(pathz) - 1;
        memcpy(pathz, u.path[0], pl);

        // Determine target line from fragment (if numeric)
        u32 target_line = 0;
        if (has_frag && u.fragment[0][0] >= '0' && u.fragment[0][0] <= '9') {
            char lnbuf[32] = {};
            size_t fl = (size_t)$len(u.fragment);
            if (fl >= sizeof(lnbuf)) fl = sizeof(lnbuf) - 1;
            memcpy(lnbuf, u.fragment[0], fl);
            target_line = (u32)atoi(lnbuf);
        }

        u8cs relpath = {(u8cp)pathz, (u8cp)pathz + pl};
        ok64 o = BROOpenFile(st, relpath, repo, target_line);
        if (o != OK)
            snprintf(st->flash, sizeof(st->flash),
                     "open: %s: %s", pathz, ok64str(o));

        // If fragment is non-numeric, set it as search pattern after opening
        if (o == OK && has_frag &&
            !(u.fragment[0][0] >= '0' && u.fragment[0][0] <= '9')) {
            size_t fl = (size_t)$len(u.fragment);
            if (fl < sizeof(st->search)) {
                memcpy(st->search, u.fragment[0], fl);
                st->search_len = (u32)fl;
                u32 f = BROSearchNext(st, st->scroll, +1);
                if (f != UINT32_MAX) st->scroll = f;
            }
        }
        return;
    }

    // Fragment only → dispatch as GURI search
    if (has_frag) {
        char frag[256] = {};
        size_t fl = (size_t)$len(u.fragment);
        if (fl >= sizeof(frag)) fl = sizeof(frag) - 1;
        memcpy(frag, u.fragment[0], fl);
        BRODispatchFragment(st, frag, repo);
        return;
    }

    // Bare text without # → treat as goto line or local search
    if (buf[0] >= '0' && buf[0] <= '9') {
        u32 target = (u32)atoi(buf);
        if (target > 0) target--;
        if (target >= st->nlines)
            target = st->nlines > 0 ? st->nlines - 1 : 0;
        st->scroll = target;
    }
}

// --- Fallback: plain output (when piped) ---

static ok64 BROPlain(hunk const *hunks, u32 nhunks) {
    sane(hunks != NULL);
    call(BROScreenInit);
    for (u32 h = 0; h < nhunks; h++) {
        u8bReset(bro_scr);
        if (hunk_has_title(&hunks[h])) {
            char dtitle[HUNK_TITLE_MAX + 1];
            int dtlen = bro_format_title(dtitle, sizeof(dtitle), &hunks[h]);
            if (BRO_COLOR) scr_puts(BRO_TITLE_COLOR);
            u8cs dts = {(u8cp)dtitle, (u8cp)dtitle + dtlen};
            u8bFeed(bro_scr, dts);
            if (BRO_COLOR) scr_puts(TTY_RESET);
            u8sFeed1(u8bIdle(bro_scr), '\n');
        }
        if (!$empty(hunks[h].text)) {
            u32 tlen = (u32)$len(hunks[h].text);
            if (!BRO_COLOR) {
                // No colors: plain text
                u8bFeed(bro_scr, hunks[h].text);
            } else {
                int ntoks = (int)$len(hunks[h].toks);
                int nhili = (int)$len(hunks[h].hili);
                int tok_i = 0, hili_i = 0;
                int prev_fg = 0;
                int prev_bg = 0;
                b8 prev_bold = NO;
                for (u32 i = 0; i < tlen; i++) {
                    // Advance tok cursor
                    while (tok_i < ntoks &&
                           tok32Offset(hunks[h].toks[0][tok_i]) <= i)
                        tok_i++;
                    u8 fg_tag = (tok_i < ntoks)
                                    ? tok32Tag(hunks[h].toks[0][tok_i])
                                    : 'S';
                    // Advance hili cursor
                    while (hili_i < nhili &&
                           tok32Offset(hunks[h].hili[0][hili_i]) <= i)
                        hili_i++;
                    u8 bg_tag = (hili_i < nhili)
                                    ? tok32Tag(hunks[h].hili[0][hili_i])
                                    : 'A';
                    b8 bold = NO;
                    int fg = BROTagColor(fg_tag, &bold);
                    int bg = 0;
                    if (bg_tag == 'I') bg = 157;
                    else if (bg_tag == 'D') bg = 217;
                    u8sp out = u8bIdle(bro_scr);
                    if (fg != prev_fg || bg != prev_bg ||
                        bold != prev_bold) {
                        if (prev_fg != 0 || prev_bg != 0 || prev_bold)
                            escfeed(out, 0);  // reset
                        if (bold) escfeed(out, BOLD);
                        if (fg != 0) escfeed(out, (u8)fg);
                        if (bg != 0) escfeedBG256(out, (u8)bg);
                        prev_fg = fg;
                        prev_bg = bg;
                        prev_bold = bold;
                    }
                    u8sFeed1(out, hunks[h].text[0][i]);
                    if (hunks[h].text[0][i] == '\n' &&
                        (prev_fg != 0 || prev_bg != 0 || prev_bold)) {
                        escfeed(out, 0);  // reset at EOL
                        prev_fg = 0;
                        prev_bg = 0;
                        prev_bold = NO;
                    }
                }
                if (prev_fg != 0 || prev_bg != 0 || prev_bold)
                    escfeed(u8bIdle(bro_scr), 0);
            }
            // Trailing newline if text doesn't end with one
            if (tlen > 0 && hunks[h].text[0][tlen - 1] != '\n')
                u8sFeed1(u8bIdle(bro_scr), '\n');
            if (h + 1 >= nhunks || hunk_has_title(&hunks[h + 1]))
                u8sFeed1(u8bIdle(bro_scr), '\n');
        }
        // Flush per hunk (hunks can be large)
        BROScreenFlush();
    }
    done;
}

// --- Spot invocation ---

// Resolve spot binary path (lazy, cached).
static char bro_spot_path[FILE_PATH_MAX_LEN] = {};
static void bro_resolve_spot(void) {
    if (bro_spot_path[0]) return;
    a_path(p);
    a$rg(a0, 0);
    a_cstr(spot_name, "spot");
    if (HOMEResolveSibling(NULL, p, spot_name, a0) != OK) return;
    size_t plen = u8bDataLen(p);
    if (plen >= sizeof(bro_spot_path)) plen = sizeof(bro_spot_path) - 1;
    memcpy(bro_spot_path, u8bDataHead(p), plen);
    bro_spot_path[plen] = 0;
}

// Collect unique words from hunk text matching a prefix.
// Words = runs of [a-zA-Z0-9_] starting with [a-zA-Z_].
// Returns count of matches written to out[0..maxout).
// Scan one hunk for words matching prefix, append unique to out.
// Check if word contains needle as a substring (case-sensitive).
static b8 bro_has_substr(u8csc word, u8csc ndl) {
    if ($empty(ndl)) return YES;
    if ($len(ndl) > $len(word)) return NO;
    u64 limit = $len(word) - $len(ndl) + 1;
    for (u64 i = 0; i < limit; i++) {
        u8cs hay = {word[0] + i, word[0] + i + $len(ndl)};
        if ($eq(hay, ndl)) return YES;
    }
    return NO;
}

static int bro_scan_hunk(hunkc const *hk, u8csc ndl,
                         b8 substr, char out[][64], int n, int maxout) {
    u32 tlen = (u32)$len(hk->text);
    if (tlen == 0) return n;
    u8cp txt = hk->text[0];
    u32 i = 0;
    while (i < tlen && n < maxout) {
        if (!isalpha(txt[i]) && txt[i] != '_') { i++; continue; }
        u32 ws = i;
        while (i < tlen && (isalnum(txt[i]) || txt[i] == '_')) i++;
        u32 wlen = i - ws;
        if (wlen < 2 || wlen >= 64) continue;
        if ((u32)$len(ndl) > wlen) continue;
        u8cs word_s = {txt + ws, txt + ws + wlen};
        if (!$empty(ndl)) {
            if (substr) {
                if (!bro_has_substr(word_s, ndl)) continue;
            } else {
                u8cs pfx = {word_s[0], word_s[0] + $len(ndl)};
                if (!$eq(pfx, ndl)) continue;
            }
        }
        a_pad(u8, wbuf, 64);
        u8bFeed(wbuf, word_s);
        u8sFeed1(wbuf_idle, 0);  // NUL for strcmp
        char *wp = (char *)u8bDataHead(wbuf);
        b8 dup = NO;
        for (int j = 0; j < n; j++)
            if (strcmp(out[j], wp) == 0) { dup = YES; break; }
        if (!dup) { memcpy(out[n], wp, wlen + 1); n++; }
    }
    return n;
}

// Collect unique words matching needle. Tries prefix first; if no
// matches, retries as substring.
static int bro_collect_words(hunkc const *hunks, u32 nhunks,
                             u32 start_hunk, u8csc ndl,
                             char out[][64], int maxout) {
    // Pass 1: prefix match
    int n = 0;
    for (u32 k = 0; k < nhunks && n < maxout; k++) {
        u32 h = (start_hunk + k) % nhunks;
        n = bro_scan_hunk(&hunks[h], ndl, NO, out, n, maxout);
    }
    if (n > 0 || $empty(ndl)) return n;
    // Pass 2: substring match
    for (u32 k = 0; k < nhunks && n < maxout; k++) {
        u32 h = (start_hunk + k) % nhunks;
        n = bro_scan_hunk(&hunks[h], ndl, YES, out, n, maxout);
    }
    return n;
}

// Interactive spot prompt with Tab completion.
// Returns the accepted token in buf (NUL-terminated), or buf[0]==0 on cancel.
static void BROReadSpot(BROstate *st, char *buf, int bufsz,
                        char const *prompt) {
    int len = 0;
    buf[0] = 0;

    // Completion state
    char matches[256][64];
    int nmatch = 0, match_idx = -1;
    b8 matches_valid = NO;

    for (;;) {
        // Render prompt
        bro_goto(st->rows, 1);
        bro_puts(TTY_INVERSE TTY_ERASE_LINE);
        bro_puts(prompt);
        if (len > 0) {
            u8cs bs = {(u8cp)buf, (u8cp)buf + len};
            bro_write(bs);
        }
        // Show match count after Tab
        if (matches_valid) {
            char info[32];
            int il = snprintf(info, sizeof(info), " [%d/%d]",
                              nmatch > 0 ? match_idx + 1 : 0, nmatch);
            if (il > 0) (void)write(STDOUT_FILENO, info, (size_t)il);
        }
        bro_puts(TTY_RESET);

        u8 ch = 0;
        ssize_t nr = read(st->tty_fd, &ch, 1);
        if (nr <= 0) continue;
        if (ch == '\n' || ch == '\r') break;
        if (ch == 27) { len = 0; buf[0] = 0; break; }
        if (ch == 127 || ch == 8) {
            if (len > 0) { len--; buf[len] = 0; matches_valid = NO; }
            continue;
        }
        if (ch == '\t') {
            // Tab: complete the last word (separated by non-alpha).
            // Find where the last word starts.
            int wstart = len;
            while (wstart > 0 && (isalnum((u8)buf[wstart - 1]) ||
                                  buf[wstart - 1] == '_'))
                wstart--;
            int pfxlen = len - wstart;
            if (!matches_valid) {
                u32 sh = (st->scroll < st->nlines)
                       ? st->lines[st->scroll].lo : 0;
                u8cs wndl = {(u8cp)buf + wstart,
                             (u8cp)buf + wstart + pfxlen};
                nmatch = bro_collect_words(st->hunks, st->nhunks,
                                           sh, wndl, matches, 256);
                match_idx = -1;
                matches_valid = YES;
            }
            if (nmatch > 0) {
                match_idx = (match_idx + 1) % nmatch;
                int mlen = (int)strlen(matches[match_idx]);
                int newlen = wstart + mlen;
                if (newlen >= bufsz) newlen = bufsz - 1;
                memcpy(buf + wstart, matches[match_idx],
                       (size_t)(newlen - wstart));
                buf[newlen] = 0;
                len = newlen;
            }
            continue;
        }
        if (ch >= 32 && len < bufsz - 1) {
            buf[len++] = (char)ch;
            buf[len] = 0;
            matches_valid = NO;
        }
    }
}

// Fork spot, drain all TLV hunks, push as new view.
// Returns OK if hunks were produced and view pushed.
static ok64 BROForkSpot(BROstate *st, char const *flag,
                        char const *token, char const *filepath,
                        char const *repo) {
    sane(st != NULL && token != NULL && token[0] != 0);
    if (st->nsaves >= BRO_MAX_VIEWS) fail(NOROOM);

    bro_resolve_spot();

    int pfd[2];
    if (pipe(pfd) != 0) fail(FAILSANITY);

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); fail(FAILSANITY); }

    if (pid == 0) {
        // Child: run spot -g <token> [filepath]
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        if (filepath)
            execlp(bro_spot_path, "spot", "--tlv", flag, token,
                   filepath, (char *)NULL);
        else
            execlp(bro_spot_path, "spot", "--tlv", flag, token,
                   (char *)NULL);
        _exit(127);
    }

    // Parent: read TLV hunks from pipe
    close(pfd[1]);

    // Use a temporary arena-like approach: drain into bro_arena at current pos.
    // Save the arena position to restore if we fail.
    u8p arena_save = u8bIdleHead(bro_arena);
    u32 hunks_save = bro_nhunks;

    // Read buffer — heap allocated, not 128KB on stack
    Bu8 pdbuf = {};
    ok64 mo2 = u8bMap(pdbuf, 1UL << 16);
    if (mo2 != OK) { close(pfd[0]); waitpid(pid, NULL, 0); fail(mo2); }

    for (;;) {
        // Read into idle space
        size_t space = u8bIdleLen(pdbuf);
        if (space == 0) {
            ok64 ro = u8bReMap(pdbuf, u8bSize(pdbuf) * 2);
            if (ro != OK) break;
            space = u8bIdleLen(pdbuf);
        }
        ssize_t nr = read(pfd[0], u8bIdleHead(pdbuf), space);
        if (nr <= 0) break;
        u8bFed(pdbuf, (size_t)nr);

        // Drain complete TLV records
        a_dup(u8 const, from, u8bDataC(pdbuf));
        while (!$empty(from) && bro_nhunks < BRO_MAX_HUNKS) {
            a_dup(u8 const, save, from);
            hunk tlv_hk = {};
            ok64 o = HUNKu8sDrain(from, &tlv_hk);
            if (o != OK) { $mv(from, save); break; }
            hunk *hk = &bro_hunks[bro_nhunks];
            *hk = (hunk){};
            if (!$empty(tlv_hk.uri)) {
                u8p up = BROArenaWrite(tlv_hk.uri[0], (size_t)$len(tlv_hk.uri));
                if (up) { hk->uri[0] = up; hk->uri[1] = u8bIdleHead(bro_arena); }
            }
            if (!$empty(tlv_hk.text)) {
                u8p xp = BROArenaWrite(tlv_hk.text[0], (size_t)$len(tlv_hk.text));
                if (xp) { hk->text[0] = xp; hk->text[1] = u8bIdleHead(bro_arena); }
            }
            if (!$empty(tlv_hk.toks)) {
                size_t tn = (size_t)((u8cp)tlv_hk.toks[1] - (u8cp)tlv_hk.toks[0]);
                u8p tkp = BROArenaWrite(tlv_hk.toks[0], tn);
                if (tkp) { hk->toks[0] = (u32cp)tkp; hk->toks[1] = (u32cp)u8bIdleHead(bro_arena); }
            }
            if (!$empty(tlv_hk.hili)) {
                size_t hn = (size_t)((u8cp)tlv_hk.hili[1] - (u8cp)tlv_hk.hili[0]);
                u8p hp = BROArenaWrite(tlv_hk.hili[0], hn);
                if (hp) { hk->hili[0] = (u32cp)hp; hk->hili[1] = (u32cp)u8bIdleHead(bro_arena); }
            }
            hunkbFed(bro_state->hunks, 1);
        }
        // Compact: shift consumed data out
        size_t consumed = u8bDataLen(pdbuf) - $len(from);
        if (consumed > 0) {
            u8bUsed(pdbuf, consumed);
            u8bShift(pdbuf, 0);
        }
    }
    u8bUnMap(pdbuf);

    close(pfd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    u32 new_nhunks = bro_nhunks - hunks_save;
    if (new_nhunks == 0) {
        // No results — restore hunks buffer + arena, flash message
        hunkbShed(bro_state->hunks,
                  (size_t)hunkbDataLen(bro_state->hunks) - hunks_save);
        // Roll IDLE back to the snapshot taken before this fork
        size_t added = (size_t)(u8bIdleHead(bro_arena) - arena_save);
        if (added > 0) u8bShed(bro_arena, added);
        snprintf(st->flash, sizeof(st->flash), "spot: no results");
        fail(FAILSANITY);
    }

    // Save current view and switch to spot results
    int idx = st->nsaves;
    BROsave *sv = &st->saves[idx];
    sv->hunks = st->hunks;
    sv->nhunks = st->nhunks;
    sv->lines = st->lines;
    memcpy(sv->linesbuf, st->linesbuf, sizeof(Brange32));
    sv->nlines = st->nlines;
    sv->scroll = st->scroll;

    st->hunks = bro_hunks + hunks_save;
    st->nhunks = new_nhunks;
    memset(st->linesbuf, 0, sizeof(Brange32));
    call(BROBuildIndex, st);
    st->scroll = (st->nlines > 1) ? 1 : 0;
    st->nsaves = idx + 1;
    done;
}

// --- Unified key handler ---
// Returns: -1 = quit, 0 = no change, 1 = changed (needs render).

#define BRO_KEY_QUIT    (-1)
#define BRO_KEY_NONE    0
#define BRO_KEY_CHANGED 1

static int BROHandleKey(BROstate *st, u8 ch, char const *repo) {
    u32 page = (st->rows > 1) ? (u32)(st->rows - 1) : 1;

    if (ch == 'q' || ch == 'Q') {
        return BRO_KEY_QUIT;
    }
    if (ch == 'h') return BROBack(st) ? BRO_KEY_CHANGED : BRO_KEY_NONE;
    if (ch == 'l' || ch == '\r' || ch == '\n') {
        BROTryOpen(st, st->scroll, repo);
        return BRO_KEY_CHANGED;
    }
    if (ch == ' ' || ch == 'f') {
        if (st->scroll + page < st->nlines) st->scroll += page;
        else if (st->nlines > page) st->scroll = st->nlines - page;
        return BRO_KEY_CHANGED;
    }
    if (ch == 'b') {
        if (st->scroll >= page) st->scroll -= page;
        else st->scroll = 0;
        return BRO_KEY_CHANGED;
    }
    if (ch == 'j') {
        if (st->scroll + 1 < st->nlines) { st->scroll++; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == 'k') {
        if (st->scroll > 0) { st->scroll--; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == 'g') { st->scroll = 0; return BRO_KEY_CHANGED; }
    if (ch == 'G') {
        st->scroll = (st->nlines > page) ? st->nlines - page : 0;
        return BRO_KEY_CHANGED;
    }
    if (ch == ':' || ch == '#') { BROReadURI(st, repo); return BRO_KEY_CHANGED; }
    if (ch == '/') {
        BROReadSearch(st);
        if (st->search_len > 0) {
            u32 f = BROSearchNext(st, st->scroll, +1);
            if (f != UINT32_MAX) st->scroll = f;
        }
        return BRO_KEY_CHANGED;
    }
    if (ch == 'n') {
        u32 f = BROSearchNext(st, st->scroll, +1);
        if (f != UINT32_MAX) { st->scroll = f; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == 'N') {
        u32 f = BROSearchNext(st, st->scroll, -1);
        if (f != UINT32_MAX) { st->scroll = f; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == 'd') {
        u32 half = page / 2;
        if (st->scroll + half < st->nlines) st->scroll += half;
        else if (st->nlines > page) st->scroll = st->nlines - page;
        return BRO_KEY_CHANGED;
    }
    if (ch == 'u') {
        u32 half = page / 2;
        if (st->scroll >= half) st->scroll -= half;
        else st->scroll = 0;
        return BRO_KEY_CHANGED;
    }
    if (ch == ']' || ch == '}') {
        u32 nx = BROHunkNextLine(st->lines, st->nlines, st->scroll);
        if (nx != BRO_NONE) { st->scroll = nx; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == '[' || ch == '{') {
        u32 pv = BROHunkPrevLine(st->lines, st->nlines, st->scroll);
        if (pv != BRO_NONE) { st->scroll = pv; return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == ')' || ch == '(') {
        u32 mid = st->scroll + (page > 0 ? (page - 1) / 2 : 0);
        u32 hl = (ch == ')')
            ? BROHiliNextLine(st->hunks, st->nhunks, st->lines, st->nlines, mid)
            : BROHiliPrevLine(st->hunks, st->nhunks, st->lines, st->nlines, mid);
        if (hl != BRO_NONE) { BROScrollCenter(st, hl); return BRO_KEY_CHANGED; }
        return BRO_KEY_NONE;
    }
    if (ch == '.') {
        // List the containing directory of the current hunk's file.
        // Falls back to cwd when the current hunk has no URI or its
        // path is already a bare name (no '/').
        u8cs dir = {};
        u8cs loc_path = {};
        if (st->scroll < st->nlines) {
            u32 hi = st->lines[st->scroll].lo;
            BROloc loc = {};
            BROHunkLoc(&loc, &st->hunks[hi]);
            if (!$empty(loc.path)) $mv(loc_path, loc.path);
        }
        if (!$empty(loc_path)) {
            // Peel a trailing '/' (dir URI like "bro/") so we look at
            // the parent of the dir, not the dir itself.
            if (*$last(loc_path) == '/') u8csShed1(loc_path);
            u8cp sl = loc_path[1];
            while (sl > loc_path[0] && *(sl - 1) != '/') sl--;
            if (sl > loc_path[0]) {
                dir[0] = loc_path[0];
                dir[1] = sl - 1;       // exclude the '/'
            }
        }
        if ($empty(dir)) { dir[0] = (u8cp)"."; dir[1] = (u8cp)"." + 1; }
        if (st->nsaves >= BRO_MAX_VIEWS) {
            snprintf(st->flash, sizeof(st->flash), "view stack full");
            return BRO_KEY_NONE;
        }
        int idx = st->nsaves;
        BROsave *sv = &st->saves[idx];
        sv->hunks = st->hunks;
        sv->nhunks = st->nhunks;
        sv->lines = st->lines;
        memcpy(sv->linesbuf, st->linesbuf, sizeof(Brange32));
        sv->nlines = st->nlines;
        sv->scroll = st->scroll;
        st->files[idx] = (BROfileview){};

        u32 save_nh = bro_nhunks;
        ok64 lo = BROListDir(dir);
        if (lo != OK) {
            snprintf(st->flash, sizeof(st->flash),
                     "list dir " U8SFMT ": %s",
                     u8sFmt(dir), ok64str(lo));
            return BRO_KEY_NONE;
        }
        if (bro_nhunks <= save_nh) {
            snprintf(st->flash, sizeof(st->flash),
                     "empty: " U8SFMT, u8sFmt(dir));
            return BRO_KEY_NONE;
        }
        st->hunks = bro_hunks + save_nh;
        st->nhunks = bro_nhunks - save_nh;
        memset(st->linesbuf, 0, sizeof(Brange32));
        BROBuildIndex(st);
        st->scroll = (st->nlines > 1) ? 1 : 0;
        st->nsaves = idx + 1;
        return BRO_KEY_CHANGED;
    }
    if (ch == 'm') {
        st->mouse_on = !st->mouse_on;
        if (st->mouse_on) MAUSEnable(STDOUT_FILENO);
        else MAUSDisable(STDOUT_FILENO);
        return BRO_KEY_NONE;
    }
    if (ch == '\'') {
        // Local token search (GURI-consistent alias for /)
        BROReadSearch(st);
        if (st->search_len > 0) {
            u32 f = BROSearchNext(st, st->scroll, +1);
            if (f != UINT32_MAX) st->scroll = f;
        }
        return BRO_KEY_CHANGED;
    }
    if (ch == 033) {
        u8 seq[2] = {};
        ssize_t n1 = read(st->tty_fd, &seq[0], 1);
        if (n1 <= 0) {
            // Bare Esc (no sequence followed): disable mouse if on
            if (st->mouse_on) {
                st->mouse_on = NO;
                MAUSDisable(STDOUT_FILENO);
            }
            return BRO_KEY_NONE;
        }
        if (seq[0] != '[') return BRO_KEY_NONE;
        ssize_t n2 = read(st->tty_fd, &seq[1], 1);
        if (n2 <= 0) return BRO_KEY_NONE;
        if (seq[1] == '<') {
            // SGR mouse
            u8 mbuf[32];
            mbuf[0] = 033; mbuf[1] = '['; mbuf[2] = '<';
            int mi = 3;
            for (;;) {
                if (mi >= (int)sizeof(mbuf)) break;
                ssize_t r = read(st->tty_fd, &mbuf[mi], 1);
                if (r <= 0) break;
                if (mbuf[mi] == 'M' || mbuf[mi] == 'm') { mi++; break; }
                mi++;
            }
            MAUSevent mev = {};
            if (MAUSParse(&mev, mbuf, mi)) {
                if (mev.type == MAUS_WHEEL) {
                    u32 step = 3;
                    if (mev.button == MAUS_UP) {
                        if (st->scroll >= step) st->scroll -= step;
                        else st->scroll = 0;
                    } else if (mev.button == MAUS_DOWN) {
                        if (st->scroll + step < st->nlines) st->scroll += step;
                        else if (st->nlines > page) st->scroll = st->nlines - page;
                    }
                    return BRO_KEY_CHANGED;
                }
                if (mev.type == MAUS_PRESS && mev.button == MAUS_LEFT) {
                    u32 line = st->scroll + mev.row - 1;
                    if (line < st->nlines) {
                        BROTryOpen(st, line, repo);
                        return BRO_KEY_CHANGED;
                    }
                }
            }
            return BRO_KEY_NONE;
        }
        switch (seq[1]) {
        case 'A': if (st->scroll > 0) st->scroll--; return BRO_KEY_CHANGED;
        case 'B': if (st->scroll + 1 < st->nlines) st->scroll++; return BRO_KEY_CHANGED;
        case '5':
            (void)read(st->tty_fd, &seq[0], 1);
            if (st->scroll >= page) st->scroll -= page;
            else st->scroll = 0;
            return BRO_KEY_CHANGED;
        case '6':
            (void)read(st->tty_fd, &seq[0], 1);
            if (st->scroll + page < st->nlines) st->scroll += page;
            else if (st->nlines > page) st->scroll = st->nlines - page;
            return BRO_KEY_CHANGED;
        case 'H': st->scroll = 0; return BRO_KEY_CHANGED;
        case 'F':
            st->scroll = (st->nlines > page) ? st->nlines - page : 0;
            return BRO_KEY_CHANGED;
        }
    }
    return BRO_KEY_NONE;
}

// --- Main entry ---

ok64 BRORun(hunk const *hunks, u32 nhunks) {
    sane(hunks != NULL && nhunks > 0);

    // Fallback: plain output when stdout is not a terminal
    if (!isatty(STDOUT_FILENO))
        return BROPlain(hunks, nhunks);

    BROstate st = {};
    st.tty_fd = -1;
    st.hunks = hunks;
    st.nhunks = nhunks;

    // Resolve repo root for file navigation — reuse bro's home if set,
    // otherwise walk up from cwd.
    char repo[FILE_PATH_MAX_LEN] = {};
    home scratch_h = {};
    home *rh = bro_state && bro_state->h ? bro_state->h : &scratch_h;
    if (rh == &scratch_h) {
        uri none = {};
        if (HOMEOpen(rh, &none, NO) != OK) rh = NULL;
    }
    if (rh != NULL) {
        size_t rl = u8bDataLen(rh->root);
        if (rl < sizeof(repo)) {
            memcpy(repo, u8bDataHead(rh->root), rl);
            repo[rl] = 0;
        }
    }

    BROGetSize(&st);
    call(BROBuildIndex, &st);
    call(BROScreenInit);
    call(BRORawEnable, &st);

    // Install SIGWINCH handler
    struct sigaction sa = {}, old_sa = {};
    sa.sa_handler = bro_winch_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, &old_sa);

    // Hide cursor
    bro_puts("\033[?25l");

    // Alternate screen buffer
    bro_puts("\033[?1049h");
    // Mouse tracking starts disabled (toggle with 'm').

    // Initial scroll: if first hunk has a line number in its URI, center
    // on that line. Otherwise skip the title.
    {
        BROloc loc0 = {};
        if (nhunks > 0) BROHunkLoc(&loc0, &hunks[0]);
        if (loc0.line > 0 && st.nlines > 1) {
            u32 file_ln = 0, best = 1;
            for (u32 i = 0; i < st.nlines; i++) {
                if (!bro_is_source_start(st.hunks, st.lines, st.nlines, i))
                    continue;
                file_ln++;
                if (file_ln == loc0.line) { best = i; break; }
                best = i;
            }
            BROScrollCenter(&st, best);
        } else if (st.nlines > 1) {
            st.scroll = 1;
        }
    }

    BRORender(&st);

    b8 quit = NO;
    while (!quit) {
        if (bro_resized) {
            bro_resized = 0;
            // Save source-line anchor before the index is rebuilt.
            u32 anchor_h = 0, anchor_off = 0;
            b8 have_anchor = NO;
            if (st.scroll < st.nlines &&
                st.lines[st.scroll].hi != BRO_TITLE_LINE) {
                anchor_h = st.lines[st.scroll].lo;
                anchor_off = st.lines[st.scroll].hi;
                have_anchor = YES;
            }
            BROGetSize(&st);
            range32bFree(st.linesbuf);
            memset(st.linesbuf, 0, sizeof(Brange32));
            if (BROBuildIndex(&st) == OK && have_anchor) {
                u32 ln = bro_line_for_off(st.lines, st.nlines,
                                          anchor_h, anchor_off);
                if (ln != BRO_NONE) st.scroll = ln;
            }
            BRORender(&st);
        }
        u8 ch = 0;
        ssize_t nr = read(st.tty_fd, &ch, 1);
        if (nr <= 0) continue;
        int r = BROHandleKey(&st, ch, repo);
        if (r == BRO_KEY_QUIT) quit = YES;
        else if (r == BRO_KEY_CHANGED) BRORender(&st);
    }

    // Restore: disable mouse, leave alternate screen, show cursor, reset
    if (st.mouse_on) MAUSDisable(STDOUT_FILENO);
    bro_puts("\033[?1049l");
    bro_puts("\033[?25h");
    BRORawDisable(&st);
    sigaction(SIGWINCH, &old_sa, NULL);
    // Free any stacked file views
    while (st.nsaves > 0) BROBack(&st);
    range32bFree(st.linesbuf);

    done;
}

// --- Pipe pager: incremental display of TLV hunks from a pipe ---

#define PIPE_RDBUF_INIT (1UL << 22)  // 4MB initial read buffer
#define PIPE_MAX_LINES  (1UL << 20)  // 1M lines max

// Append lines for hunks [from..nhunks) into lines[nlines..maxlines).
// One entry per display row: title separator, source-line start, or
// a wrap continuation of a long source line (`cols` codepoints each).
// Returns new total nlines.
u32 BROAppendLines(range32 *lines, u32 nlines, u32 maxlines,
                   hunkc const *hunks, u32 from, u32 nhunks, u32 cols) {
    if (cols == 0) cols = 1;
    u32 li = nlines;
    for (u32 h = from; h < nhunks; h++) {
        if (hunk_has_title(&hunks[h])) {
            if (li < maxlines)
                lines[li++] = (range32){h, BRO_TITLE_LINE};
        }
        u32 tlen = (u32)$len(hunks[h].text);
        if (tlen == 0) continue;
        a_dup(u8 const, text, hunks[h].text);
        u32 off = 0;
        while (off < tlen) {
            if (li < maxlines)
                lines[li++] = (range32){h, off};
            u32 end = bro_row_end(text, tlen, off, cols);
            if (end < tlen && text[0][end] == '\n') end++;
            if (end >= tlen) break;
            off = end;
        }
    }
    return li;
}

ok64 BROPipeRun(int pipefd) {
    sane(pipefd >= 0);

    // If pipefd is a TTY (bro invoked with no data source), ignore
    // it — otherwise the pipe-drain would swallow keystrokes that
    // should reach the keyboard handler (e.g. 'q' to quit).
    b8 pipe_eof = isatty(pipefd) ? YES : NO;

    // Non-blocking so the read loop can drain what's ready and exit
    // on EAGAIN without a separate poll probe.
    if (!pipe_eof) {
        int fl = fcntl(pipefd, F_GETFL, 0);
        if (fl >= 0) (void)fcntl(pipefd, F_SETFL, fl | O_NONBLOCK);
    }

    call(BROArenaInit);

    // Allocate growable read buffer
    Bu8 rdbuf = {};
    call(u8bMap, rdbuf, PIPE_RDBUF_INIT);

    // Resolve repo root
    char repo[FILE_PATH_MAX_LEN] = {};
    {
        home rh = {};
        uri none = {};
        if (HOMEOpen(&rh, &none, NO) == OK) {
            size_t rl = u8bDataLen(rh.root);
            if (rl < sizeof(repo)) {
                memcpy(repo, u8bDataHead(rh.root), rl);
                repo[rl] = 0;
            }
            HOMEClose(&rh);
        }
    }

    // Allocate line index
    BROstate st = {};
    st.tty_fd = -1;
    ok64 lo = range32bAlloc(st.linesbuf, PIPE_MAX_LINES);
    if (lo != OK) {
        u8bUnMap(rdbuf);
        return NOROOM;
    }
    st.lines = st.linesbuf[0];
    st.hunks = bro_hunks;
    st.nhunks = 0;

    BROGetSize(&st);
    st.nlines = 0;

    call(BROScreenInit);
    if (BRORawEnable(&st) != OK) {
        u8bUnMap(rdbuf);
        range32bFree(st.linesbuf);
        return FAILSANITY;
    }

    struct sigaction sa = {}, old_sa = {};
    sa.sa_handler = bro_winch_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, &old_sa);

    bro_puts("\033[?25l");    // hide cursor
    bro_puts("\033[?1049h");  // alt screen
    // Mouse tracking starts disabled (toggle with 'm').

    // Show initial "nothing..." while waiting for data
    u8bReset(bro_scr);
    scr_goto(st.rows, 1);
    scr_puts(TTY_INVERSE TTY_ERASE_LINE " nothing..." TTY_RESET);
    BROScreenFlush();

    b8 quit = NO;
    u32 indexed_nhunks = 0;
    u32 rendered_nhunks = 0;

    while (!quit) {
        if (bro_resized) {
            bro_resized = 0;
            // Preserve source-line anchor across reindex.
            u32 anchor_h = 0, anchor_off = 0;
            b8 have_anchor = NO;
            if (st.scroll < st.nlines &&
                st.lines[st.scroll].hi != BRO_TITLE_LINE) {
                anchor_h = st.lines[st.scroll].lo;
                anchor_off = st.lines[st.scroll].hi;
                have_anchor = YES;
            }
            BROGetSize(&st);
            st.nlines = BROAppendLines(st.lines, 0, PIPE_MAX_LINES,
                                        bro_hunks, 0, bro_nhunks, st.cols);
            indexed_nhunks = bro_nhunks;
            if (have_anchor) {
                u32 ln = bro_line_for_off(st.lines, st.nlines,
                                          anchor_h, anchor_off);
                if (ln != BRO_NONE) st.scroll = ln;
            }
            if (st.nlines > 0) BRORender(&st);
        }

        struct pollfd fds[2];
        int nfds = 0;
        fds[0].fd = st.tty_fd;
        fds[0].events = POLLIN;
        nfds = 1;
        if (!pipe_eof) {
            fds[1].fd = pipefd;
            fds[1].events = POLLIN;
            nfds = 2;
        }

        int pr = poll(fds, (nfds_t)nfds, 16);

        b8 changed = NO;
        b8 key_pressed = NO;

        // Drain everything ready before rendering so a fast producer
        // doesn't trigger a burst of partial-frame repaints (visible
        // as screen blinking during load).
        if (!pipe_eof && (fds[1].revents & (POLLIN | POLLHUP))) {
            for (;;) {
                size_t space = u8bIdleLen(rdbuf);
                if (space == 0) break;
                ssize_t nr = read(pipefd, u8bIdleHead(rdbuf), space);
                if (nr > 0) {
                    u8bFed(rdbuf, (size_t)nr);
                    continue;
                }
                if (nr == 0) pipe_eof = YES;
                break;  // EAGAIN or EOF
            }

            // Drain complete TLV records
            a_dup(u8 const, from, u8bDataC(rdbuf));
            while (!$empty(from) && bro_nhunks < BRO_MAX_HUNKS) {
                a_dup(u8 const, save, from);
                hunk tlv_hk = {};
                ok64 o = HUNKu8sDrain(from, &tlv_hk);
                if (o != OK) {
                    $mv(from, save);
                    // Buffer full with incomplete record — grow
                    if ($len(from) >= u8bIdleLen(rdbuf)) {
                        // Compact first, then grow
                        size_t eaten = u8bDataLen(rdbuf) - $len(from);
                        if (eaten > 0) {
                            u8bUsed(rdbuf, eaten);
                            u8bShift(rdbuf, 0);
                        }
                        ok64 ro = u8bReMap(rdbuf, u8bSize(rdbuf) * 2);
                        if (ro == OK) {
                            $mv(from, u8bDataC(rdbuf));
                            continue;  // retry drain
                        }
                    }
                    break;
                }
                // Copy fields into arena
                hunk *hk = &bro_hunks[bro_nhunks];
                *hk = (hunk){};
                if (!$empty(tlv_hk.uri)) {
                    u8p up = BROArenaWrite(tlv_hk.uri[0],
                                            (size_t)$len(tlv_hk.uri));
                    if (up) {
                        hk->uri[0] = up;
                        hk->uri[1] = u8bIdleHead(bro_arena);
                    }
                }
                if (!$empty(tlv_hk.text)) {
                    u8p xp = BROArenaWrite(tlv_hk.text[0],
                                            (size_t)$len(tlv_hk.text));
                    if (xp) {
                        hk->text[0] = xp;
                        hk->text[1] = u8bIdleHead(bro_arena);
                    }
                }
                if (!$empty(tlv_hk.toks)) {
                    u8p tkp = BROArenaWrite(tlv_hk.toks[0],
                                  (size_t)((u8cp)tlv_hk.toks[1] -
                                           (u8cp)tlv_hk.toks[0]));
                    if (tkp) {
                        hk->toks[0] = (u32cp)tkp;
                        hk->toks[1] = (u32cp)u8bIdleHead(bro_arena);
                    }
                }
                if (!$empty(tlv_hk.hili)) {
                    u8p hp = BROArenaWrite(tlv_hk.hili[0],
                                 (size_t)((u8cp)tlv_hk.hili[1] -
                                          (u8cp)tlv_hk.hili[0]));
                    if (hp) {
                        hk->hili[0] = (u32cp)hp;
                        hk->hili[1] = (u32cp)u8bIdleHead(bro_arena);
                    }
                }
                hunkbFed(bro_state->hunks, 1);
            }

            // Compact: shift remaining to buffer start
            size_t consumed = u8bDataLen(rdbuf) - $len(from);
            if (consumed > 0) {
                u8bUsed(rdbuf, consumed);
                u8bShift(rdbuf, 0);
            }
        }

        // Handle keyboard input
        if (fds[0].revents & POLLIN) {
            u8 ch = 0;
            ssize_t nr = read(st.tty_fd, &ch, 1);
            if (nr > 0) {
                int r = BROHandleKey(&st, ch, repo);
                if (r == BRO_KEY_QUIT) quit = YES;
                else if (r == BRO_KEY_CHANGED) changed = YES;
                key_pressed = YES;
            }
        }

        // Extend line index for any new hunks
        if (bro_nhunks > indexed_nhunks) {
            st.nlines = BROAppendLines(st.lines, st.nlines,
                                         PIPE_MAX_LINES, bro_hunks,
                                         indexed_nhunks, bro_nhunks,
                                         st.cols);
            st.nhunks = bro_nhunks;
            indexed_nhunks = bro_nhunks;
        }
        // Render whenever new hunks have been indexed.  The 16ms poll
        // timeout caps refresh at ~60 fps even when the producer
        // streams quickly, so explicit debouncing isn't needed.
        if (indexed_nhunks > rendered_nhunks) {
            // Skip the first title line on the first render so the
            // user lands on actual content, not the title separator.
            if (rendered_nhunks == 0 && st.nlines > 1) st.scroll = 1;
            changed = YES;
            rendered_nhunks = indexed_nhunks;
        }
        if ((changed || key_pressed) && st.nlines > 0)
            BRORender(&st);

        // Pipe done, no results — show "nothing!" and wait for quit
        if (pipe_eof && st.nlines == 0 && !quit) {
            u8bReset(bro_scr);
            scr_goto(st.rows, 1);
            scr_puts(TTY_INVERSE TTY_ERASE_LINE " nothing!" TTY_RESET);
            BROScreenFlush();
        }
    }

    // Teardown
    if (st.mouse_on) MAUSDisable(STDOUT_FILENO);
    bro_puts("\033[?1049l");
    bro_puts("\033[?25h");
    BRORawDisable(&st);
    sigaction(SIGWINCH, &old_sa, NULL);

    while (st.nsaves > 0) BROBack(&st);
    range32bFree(st.linesbuf);
    u8bUnMap(rdbuf);
    BROArenaCleanup();

    done;
}
