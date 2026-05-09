
/* #line 1 "WIRE.c.rl" */
//  WIRE.c.rl — git pkt-line text-payload classifier (DRAFT).
//
//  Scope: pure function.  Caller has already extracted one complete
//  pkt-line payload (e.g. via PKTu8sDrain) and decided which role's
//  grammar applies.  This machine classifies the payload into a
//  wire_evt or returns WIREBADREQ.
//
//  No streaming, no buffering, no zlib, no framing.  Slices in the
//  emitted event point into the caller's payload — caller copies
//  what it wants to keep.
//
//  Build: ragel -C WIRE.c.rl -o WIRE.rl.c -L

#include "WIRE.h"

#include "abc/HEX.h"
#include "abc/PRO.h"

#include <string.h>


/* #line 106 "WIRE.c.rl" */



/* #line 24 "WIRE.rl.c" */
static const char _wire_line_actions[] = {
	0, 1, 1, 1, 2, 1, 4, 1, 
	5, 1, 6, 1, 10, 1, 11, 1, 
	12, 2, 0, 1, 2, 2, 3, 2, 
	2, 8, 2, 2, 9, 2, 2, 12, 
	2, 2, 13, 2, 5, 14, 2, 5, 
	15, 2, 7, 8, 2, 7, 14, 2, 
	7, 15, 3, 6, 7, 8, 3, 6, 
	7, 14, 3, 6, 7, 15
};

static const unsigned char _wire_line_key_offsets[] = {
	0, 0, 6, 11, 14, 15, 16, 17, 
	21, 25, 26, 27, 31, 32, 33, 34, 
	35, 36, 37, 38, 42, 43, 44, 45, 
	46, 47, 48, 49, 53, 54, 55, 56, 
	57, 61, 65, 70, 74, 79, 82, 86, 
	91, 94, 97, 98, 99, 104, 108, 108, 
	108, 112, 116, 121, 122, 123, 126, 127, 
	128, 131, 132
};

static const unsigned char _wire_line_trans_keys[] = {
	65u, 78u, 48u, 57u, 97u, 102u, 32u, 48u, 
	57u, 97u, 102u, 0u, 10u, 32u, 67u, 75u, 
	32u, 48u, 57u, 97u, 102u, 65u, 90u, 97u, 
	122u, 65u, 75u, 100u, 104u, 115u, 119u, 111u, 
	110u, 101u, 97u, 118u, 101u, 32u, 48u, 57u, 
	97u, 102u, 104u, 97u, 108u, 108u, 111u, 119u, 
	32u, 48u, 57u, 97u, 102u, 97u, 110u, 116u, 
	32u, 48u, 57u, 97u, 102u, 48u, 57u, 97u, 
	102u, 32u, 48u, 57u, 97u, 102u, 48u, 57u, 
	97u, 102u, 32u, 48u, 57u, 97u, 102u, 0u, 
	10u, 32u, 48u, 57u, 97u, 102u, 32u, 48u, 
	57u, 97u, 102u, 0u, 10u, 32u, 0u, 10u, 
	32u, 10u, 10u, 32u, 48u, 57u, 97u, 102u, 
	65u, 90u, 97u, 122u, 48u, 57u, 97u, 102u, 
	48u, 57u, 97u, 102u, 32u, 48u, 57u, 97u, 
	102u, 10u, 10u, 0u, 10u, 32u, 10u, 10u, 
	0u, 10u, 32u, 10u, 10u, 0
};

static const char _wire_line_single_lengths[] = {
	0, 2, 1, 3, 1, 1, 1, 0, 
	0, 1, 1, 4, 1, 1, 1, 1, 
	1, 1, 1, 0, 1, 1, 1, 1, 
	1, 1, 1, 0, 1, 1, 1, 1, 
	0, 0, 1, 0, 1, 3, 0, 1, 
	3, 3, 1, 1, 1, 0, 0, 0, 
	0, 0, 1, 1, 1, 3, 1, 1, 
	3, 1, 1
};

static const char _wire_line_range_lengths[] = {
	0, 2, 2, 0, 0, 0, 0, 2, 
	2, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 2, 0, 0, 0, 0, 
	0, 0, 0, 2, 0, 0, 0, 0, 
	2, 2, 2, 2, 2, 0, 2, 2, 
	0, 0, 0, 0, 2, 2, 0, 0, 
	2, 2, 2, 0, 0, 0, 0, 0, 
	0, 0, 0
};

static const unsigned char _wire_line_index_offsets[] = {
	0, 0, 5, 9, 13, 15, 17, 19, 
	22, 25, 27, 29, 34, 36, 38, 40, 
	42, 44, 46, 48, 51, 53, 55, 57, 
	59, 61, 63, 65, 68, 70, 72, 74, 
	76, 79, 82, 86, 89, 93, 97, 100, 
	104, 108, 112, 114, 116, 120, 123, 124, 
	125, 128, 131, 135, 137, 139, 143, 145, 
	147, 151, 153
};

static const char _wire_line_indicies[] = {
	2, 3, 0, 0, 1, 4, 5, 5, 
	1, 1, 1, 1, 6, 7, 1, 8, 
	1, 9, 1, 10, 10, 1, 11, 11, 
	1, 12, 1, 13, 1, 14, 15, 16, 
	17, 1, 18, 1, 19, 1, 20, 1, 
	21, 1, 22, 1, 23, 1, 24, 1, 
	25, 25, 1, 26, 1, 27, 1, 28, 
	1, 29, 1, 30, 1, 31, 1, 32, 
	1, 33, 33, 1, 34, 1, 35, 1, 
	36, 1, 37, 1, 38, 38, 1, 39, 
	39, 1, 40, 41, 41, 1, 42, 42, 
	1, 43, 44, 44, 1, 1, 1, 1, 
	45, 46, 46, 1, 47, 48, 48, 1, 
	1, 1, 1, 49, 50, 1, 1, 51, 
	1, 52, 1, 53, 54, 55, 55, 1, 
	11, 11, 1, 1, 1, 56, 56, 1, 
	57, 57, 1, 58, 59, 59, 1, 1, 
	60, 1, 61, 62, 1, 1, 63, 1, 
	64, 1, 65, 66, 1, 1, 67, 1, 
	68, 1, 69, 0
};

static const char _wire_line_trans_targs[] = {
	2, 0, 4, 9, 3, 2, 41, 5, 
	6, 7, 44, 45, 10, 46, 12, 15, 
	20, 28, 13, 14, 47, 16, 17, 18, 
	19, 48, 21, 22, 23, 24, 25, 26, 
	27, 49, 29, 30, 31, 32, 50, 34, 
	35, 34, 36, 37, 36, 53, 39, 40, 
	39, 56, 42, 41, 43, 43, 8, 44, 
	48, 49, 51, 50, 52, 52, 54, 53, 
	55, 55, 57, 56, 58, 58
};

static const char _wire_line_trans_actions[] = {
	17, 0, 0, 0, 3, 1, 5, 0, 
	0, 0, 17, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 17, 0, 0, 0, 0, 0, 0, 
	0, 17, 0, 0, 0, 0, 17, 17, 
	20, 1, 17, 3, 1, 5, 17, 3, 
	1, 5, 7, 0, 9, 0, 3, 1, 
	1, 1, 3, 1, 9, 0, 7, 0, 
	9, 0, 7, 0, 9, 0
};

static const char _wire_line_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 35, 54, 44, 29, 15, 13, 11, 
	26, 32, 23, 50, 41, 38, 58, 47, 
	35, 54, 44
};

static const int wire_line_start = 1;
static const int wire_line_first_final = 41;
static const int wire_line_error = 0;

static const int wire_line_en_upload = 11;
static const int wire_line_en_receive = 33;
static const int wire_line_en_advert = 38;
static const int wire_line_en_client = 1;


/* #line 109 "WIRE.c.rl" */

ok64 WIREClassify(u8csc payload, wire_role role, wire_evt *out) {
    sane(out);

    *out = (wire_evt){0};
    struct {
        sha1   sha;
        sha1   sha_old;
        u32    sha_pos;
        b8     bad;          // any sha != 40 chars; rejected post-exec
        u8c   *name[2];
        u8c   *caps[2];
    } ctx = {0};

    u8c const *p   = payload[0];
    u8c const *pe  = payload[1];
    u8c const *eof = pe;
    int cs = 0;

    
/* #line 185 "WIRE.rl.c" */
	{
	cs = wire_line_start;
	}

/* #line 129 "WIRE.c.rl" */

    switch (role) {
    case WIRE_UPLOAD:  cs = wire_line_en_upload;  break;
    case WIRE_RECEIVE: cs = wire_line_en_receive; break;
    case WIRE_CLIENT:  cs = wire_line_en_client;  break;
    case WIRE_ADVERT:  cs = wire_line_en_advert;  break;
    default: return WIREBADREQ;
    }

    
/* #line 197 "WIRE.rl.c" */
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const unsigned char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _wire_line_trans_keys + _wire_line_key_offsets[cs];
	_trans = _wire_line_index_offsets[cs];

	_klen = _wire_line_single_lengths[cs];
	if ( _klen > 0 ) {
		const unsigned char *_lower = _keys;
		const unsigned char *_mid;
		const unsigned char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _wire_line_range_lengths[cs];
	if ( _klen > 0 ) {
		const unsigned char *_lower = _keys;
		const unsigned char *_mid;
		const unsigned char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _wire_line_indicies[_trans];
	cs = _wire_line_trans_targs[_trans];

	if ( _wire_line_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _wire_line_actions + _wire_line_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
/* #line 27 "WIRE.c.rl" */
	{
        ctx.sha_pos = 0;
        memset(&ctx.sha, 0, sizeof(ctx.sha));
    }
	break;
	case 1:
/* #line 31 "WIRE.c.rl" */
	{
        //  Bounded write — sha_done rejects everything ≠ 40 chars.
        if (ctx.sha_pos < 40) {
            u8 v = BASE16rev[(*p)];
            ctx.sha.data[ctx.sha_pos >> 1] |=
                (ctx.sha_pos & 1) ? v : (v << 4);
        }
        ctx.sha_pos++;
    }
	break;
	case 2:
/* #line 40 "WIRE.c.rl" */
	{ if (ctx.sha_pos != 40) ctx.bad = 1; }
	break;
	case 3:
/* #line 41 "WIRE.c.rl" */
	{ ctx.sha_old = ctx.sha; }
	break;
	case 4:
/* #line 43 "WIRE.c.rl" */
	{ ctx.name[0] = (u8c *)p; }
	break;
	case 5:
/* #line 44 "WIRE.c.rl" */
	{ ctx.name[1] = (u8c *)p; }
	break;
	case 6:
/* #line 46 "WIRE.c.rl" */
	{ ctx.caps[0] = (u8c *)p; }
	break;
/* #line 302 "WIRE.rl.c" */
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _wire_line_actions + _wire_line_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 2:
/* #line 40 "WIRE.c.rl" */
	{ if (ctx.sha_pos != 40) ctx.bad = 1; }
	break;
	case 5:
/* #line 44 "WIRE.c.rl" */
	{ ctx.name[1] = (u8c *)p; }
	break;
	case 6:
/* #line 46 "WIRE.c.rl" */
	{ ctx.caps[0] = (u8c *)p; }
	break;
	case 7:
/* #line 47 "WIRE.c.rl" */
	{ ctx.caps[1] = (u8c *)p; }
	break;
	case 8:
/* #line 51 "WIRE.c.rl" */
	{
        out->kind = WIRE_WANT;
        out->sha  = ctx.sha;
        $mv(out->caps, ctx.caps);
    }
	break;
	case 9:
/* #line 56 "WIRE.c.rl" */
	{ out->kind = WIRE_HAVE;    out->sha = ctx.sha; }
	break;
	case 10:
/* #line 57 "WIRE.c.rl" */
	{ out->kind = WIRE_DONE; }
	break;
	case 11:
/* #line 58 "WIRE.c.rl" */
	{ out->kind = WIRE_NAK; }
	break;
	case 12:
/* #line 59 "WIRE.c.rl" */
	{ out->kind = WIRE_ACK;     out->sha = ctx.sha; }
	break;
	case 13:
/* #line 60 "WIRE.c.rl" */
	{ out->kind = WIRE_SHALLOW; out->sha = ctx.sha; }
	break;
	case 14:
/* #line 61 "WIRE.c.rl" */
	{
        out->kind = WIRE_REF;
        out->sha  = ctx.sha;
        $mv(out->name, ctx.name);
        $mv(out->caps, ctx.caps);
    }
	break;
	case 15:
/* #line 67 "WIRE.c.rl" */
	{
        out->kind    = WIRE_UPDATE;
        out->old_sha = ctx.sha_old;
        out->sha     = ctx.sha;       // new_sha
        $mv(out->name, ctx.name);
        $mv(out->caps, ctx.caps);
    }
	break;
/* #line 368 "WIRE.rl.c" */
		}
	}
	}

	_out: {}
	}

/* #line 139 "WIRE.c.rl" */

    if (cs < wire_line_first_final || ctx.bad) {
        *out = (wire_evt){0};
        return WIREBADREQ;
    }
    done;
}
