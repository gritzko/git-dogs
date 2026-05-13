#include "DPATH.h"

%%{
    machine dpath;
    alphtype unsigned char;

    # Valid UTF-8 byte sequences (no NUL, no overlongs, no surrogates)
    utf8_1 = 0x01..0x7F ;
    utf8_2 = 0xC2..0xDF 0x80..0xBF ;
    utf8_3 = 0xE0 0xA0..0xBF 0x80..0xBF
           | 0xE1..0xEC 0x80..0xBF 0x80..0xBF
           | 0xED 0x80..0x9F 0x80..0xBF
           | 0xEE..0xEF 0x80..0xBF 0x80..0xBF ;
    utf8_4 = 0xF0 0x90..0xBF 0x80..0xBF 0x80..0xBF
           | 0xF1..0xF3 0x80..0xBF 0x80..0xBF 0x80..0xBF
           | 0xF4 0x80..0x8F 0x80..0xBF 0x80..0xBF ;

    # Safe byte: valid UTF-8 char, no slash, no backslash
    safe = (utf8_1 - [/\\]) | utf8_2 | utf8_3 | utf8_4 ;

    # Dangerous exact names (case-insensitive).  The `.git` reject is
    # a defensive guard at tree-entry boundaries for data ingested via
    # keeper's UNPK (git pack imports), not a signal that our own
    # workspace uses `.git` — it does not.
    dotgit  = '.' [gG][iI][tT] ;
    dotbe   = '.' [bB][eE] ;
    bad     = '.' | '..' | dotgit | dotbe ;

    main := ( safe+ - bad ) ;
}%%

%% write data nofinal noerror;

ok64 DPATHu8sDrainSeg(u8cs input, u8cs out) {
    if (input[0] == NULL || input[0] >= input[1])
        return DPATHFAIL;

    u8cp p = input[0];
    u8cp pe = input[1];
    u8cp eof = pe;
    int cs = 0;

    %% write init;
    %% write exec;

    if (cs < %%{ write first_final; }%%)
        return DPATHBAD;

    out[0] = input[0];
    out[1] = p;
    input[0] = p;
    return OK;
}
