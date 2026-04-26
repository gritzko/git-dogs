
/* #line 1 "dog/QURY.c.rl" */
#include "QURY.h"
#include <string.h>


/* #line 33 "dog/QURY.c.rl" */



/* #line 7 "dog/QURY.rl.c" */
static const char _qury_actions[] = {
	0, 1, 0, 1, 1, 1, 4, 1, 
	6, 2, 1, 2, 2, 1, 3, 2, 
	5, 0, 2, 6, 0
};

static const char _qury_key_offsets[] = {
	0, 0, 9, 17, 19, 27, 35, 47, 
	49
};

static const char _qury_trans_keys[] = {
	45, 46, 95, 48, 57, 65, 90, 97, 
	122, 45, 95, 48, 57, 65, 90, 97, 
	122, 46, 47, 45, 95, 48, 57, 65, 
	90, 97, 122, 45, 95, 48, 57, 65, 
	90, 97, 122, 45, 94, 95, 126, 46, 
	47, 48, 57, 65, 90, 97, 122, 48, 
	57, 47, 0
};

static const char _qury_single_lengths[] = {
	0, 3, 2, 2, 2, 2, 4, 0, 
	1
};

static const char _qury_range_lengths[] = {
	0, 3, 3, 0, 3, 3, 4, 1, 
	0
};

static const char _qury_index_offsets[] = {
	0, 0, 7, 13, 16, 22, 28, 37, 
	39
};

static const char _qury_indicies[] = {
	0, 2, 0, 0, 0, 0, 1, 3, 
	3, 3, 3, 3, 1, 4, 5, 1, 
	6, 6, 6, 6, 6, 1, 7, 7, 
	7, 7, 7, 1, 3, 9, 3, 10, 
	8, 3, 3, 3, 1, 11, 1, 12, 
	1, 0
};

static const char _qury_trans_targs[] = {
	6, 0, 3, 6, 8, 5, 6, 6, 
	2, 7, 7, 7, 4
};

static const char _qury_trans_actions[] = {
	1, 0, 0, 0, 0, 0, 18, 15, 
	0, 12, 9, 5, 0
};

static const char _qury_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 3, 0, 
	7
};

static const int qury_start = 1;

static const int qury_en_main = 1;


/* #line 36 "dog/QURY.c.rl" */

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

    
/* #line 111 "dog/QURY.rl.c" */
	{
	cs = qury_start;
	}

/* #line 77 "dog/QURY.c.rl" */
    
/* #line 114 "dog/QURY.rl.c" */
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _qury_trans_keys + _qury_key_offsets[cs];
	_trans = _qury_index_offsets[cs];

	_klen = _qury_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
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

	_klen = _qury_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
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
	_trans = _qury_indicies[_trans];
	cs = _qury_trans_targs[_trans];

	if ( _qury_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _qury_actions + _qury_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
/* #line 7 "dog/QURY.c.rl" */
	{ body_mark = p; }
	break;
	case 1:
/* #line 8 "dog/QURY.c.rl" */
	{ out->body[0] = body_mark; out->body[1] = p; }
	break;
	case 2:
/* #line 9 "dog/QURY.c.rl" */
	{ out->anc_type = '~'; }
	break;
	case 3:
/* #line 10 "dog/QURY.c.rl" */
	{ out->anc_type = '^'; }
	break;
	case 4:
/* #line 11 "dog/QURY.c.rl" */
	{ out->ancestry = out->ancestry * 10 + (*p - '0'); }
	break;
	case 5:
/* #line 12 "dog/QURY.c.rl" */
	{ out->rel = QURY_REL_DOWN; }
	break;
	case 6:
/* #line 13 "dog/QURY.c.rl" */
	{ out->rel = QURY_REL_UP; }
	break;
/* #line 208 "dog/QURY.rl.c" */
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
	const char *__acts = _qury_actions + _qury_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 1:
/* #line 8 "dog/QURY.c.rl" */
	{ out->body[0] = body_mark; out->body[1] = p; }
	break;
	case 6:
/* #line 13 "dog/QURY.c.rl" */
	{ out->rel = QURY_REL_UP; }
	break;
/* #line 229 "dog/QURY.rl.c" */
		}
	}
	}

	_out: {}
	}

/* #line 78 "dog/QURY.c.rl" */

    // Advance input past spec and separator
    input[0] = (specend < input[1]) ? specend + 1 : specend;

    if (cs < 6)
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
