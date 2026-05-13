#include "GRAF.h"

#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/HUNK.h"

// --- Helper: read file via mmap ---
static ok64 graf_merge_read(u8cs *data, u8bp *mapped, u8cs path_arg) {
    sane(data != NULL && mapped != NULL);
    a_path(path, path_arg);
    call(FILEMapRO, mapped, $path(path));
    (*data)[0] = u8bDataHead(*mapped);
    (*data)[1] = u8bIdleHead(*mapped);
    done;
}

// 3-way token-level merge: writes resolved bytes to outpath (or stdout
// when outpath is empty).  No commit context (CLI debug entry point),
// so this is a blob-only WEAVE merge — conflict markers emitted in
// WEAVE format (`<<<<` / `||||` / `>>>>`).
ok64 GRAFMerge(u8cs base_path, u8cs ours_path, u8cs theirs_path,
               u8cs outpath) {
    sane($ok(base_path) && $ok(ours_path) && $ok(theirs_path));

    u8cs ext_nodot = {};
    PATHu8sExt(ext_nodot, ours_path);

    u8bp map_b = NULL, map_o = NULL, map_t = NULL;
    u8cs base_data = {}, ours_data = {}, theirs_data = {};
    call(graf_merge_read, &base_data, &map_b, base_path);
    call(graf_merge_read, &ours_data, &map_o, ours_path);
    call(graf_merge_read, &theirs_data, &map_t, theirs_path);

    u64 outsz = $len(ours_data) + $len(theirs_data) + 4096;
    u8 *out[4] = {};
    ok64 o = u8bAlloc(out, outsz);
    if (o != OK) goto cleanup;

    o = GRAFMerge3Bytes(base_data, ours_data, theirs_data,
                        ext_nodot, out);
    if (o != OK) { u8bFree(out); goto cleanup; }

    u8cs result = {out[1], out[2]};
    if (!$empty(outpath)) {
        a_path(opath, outpath);
        int fd = -1;
        o = FILECreate(&fd, $path(opath));
        if (o != OK) { u8bFree(out); goto cleanup; }
        o = FILEFeedAll(fd, result);
        close(fd);
    } else {
        o = FILEFeedAll(STDOUT_FILENO, result);
    }
    u8bFree(out);

cleanup:
    if (map_b) FILEUnMap(map_b);
    if (map_o) FILEUnMap(map_o);
    if (map_t) FILEUnMap(map_t);
    return o;
}
