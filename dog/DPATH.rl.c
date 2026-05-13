
/* #line 1 "DPATH.c.rl" */
#include "DPATH.h"


/* #line 30 "DPATH.c.rl" */



/* #line 6 "DPATH.rl.c" */
static const char _dpath_key_offsets[] = {
	0, 0, 18, 20, 22, 24, 26, 28, 
	30, 32, 54, 71, 88, 107, 126
};

static const unsigned char _dpath_trans_keys[] = {
	0u, 46u, 47u, 92u, 224u, 237u, 240u, 244u, 
	128u, 193u, 194u, 223u, 225u, 239u, 241u, 243u, 
	245u, 255u, 128u, 191u, 160u, 191u, 128u, 191u, 
	128u, 159u, 144u, 191u, 128u, 191u, 128u, 143u, 
	0u, 46u, 47u, 66u, 71u, 92u, 98u, 103u, 
	224u, 237u, 240u, 244u, 128u, 193u, 194u, 223u, 
	225u, 239u, 241u, 243u, 245u, 255u, 0u, 47u, 
	92u, 224u, 237u, 240u, 244u, 128u, 193u, 194u, 
	223u, 225u, 239u, 241u, 243u, 245u, 255u, 0u, 
	47u, 92u, 224u, 237u, 240u, 244u, 128u, 193u, 
	194u, 223u, 225u, 239u, 241u, 243u, 245u, 255u, 
	0u, 47u, 69u, 92u, 101u, 224u, 237u, 240u, 
	244u, 128u, 193u, 194u, 223u, 225u, 239u, 241u, 
	243u, 245u, 255u, 0u, 47u, 73u, 92u, 105u, 
	224u, 237u, 240u, 244u, 128u, 193u, 194u, 223u, 
	225u, 239u, 241u, 243u, 245u, 255u, 0u, 47u, 
	84u, 92u, 116u, 224u, 237u, 240u, 244u, 128u, 
	193u, 194u, 223u, 225u, 239u, 241u, 243u, 245u, 
	255u, 0
};

static const char _dpath_single_lengths[] = {
	0, 8, 0, 0, 0, 0, 0, 0, 
	0, 12, 7, 7, 9, 9, 9
};

static const char _dpath_range_lengths[] = {
	0, 5, 1, 1, 1, 1, 1, 1, 
	1, 5, 5, 5, 5, 5, 5
};

static const char _dpath_index_offsets[] = {
	0, 0, 14, 16, 18, 20, 22, 24, 
	26, 28, 46, 59, 72, 87, 102
};

static const char _dpath_trans_targs[] = {
	0, 9, 0, 0, 3, 5, 6, 8, 
	0, 2, 4, 7, 0, 11, 11, 0, 
	2, 0, 2, 0, 2, 0, 4, 0, 
	4, 0, 4, 0, 0, 10, 0, 12, 
	13, 0, 12, 13, 3, 5, 6, 8, 
	0, 2, 4, 7, 0, 11, 0, 0, 
	0, 3, 5, 6, 8, 0, 2, 4, 
	7, 0, 11, 0, 0, 0, 3, 5, 
	6, 8, 0, 2, 4, 7, 0, 11, 
	0, 0, 10, 0, 10, 3, 5, 6, 
	8, 0, 2, 4, 7, 0, 11, 0, 
	0, 14, 0, 14, 3, 5, 6, 8, 
	0, 2, 4, 7, 0, 11, 0, 0, 
	10, 0, 10, 3, 5, 6, 8, 0, 
	2, 4, 7, 0, 11, 0
};

static const int dpath_start = 1;

static const int dpath_en_main = 1;


/* #line 33 "DPATH.c.rl" */

ok64 DPATHu8sDrainSeg(u8cs input, u8cs out) {
    if (input[0] == NULL || input[0] >= input[1])
        return DPATHFAIL;

    u8cp p = input[0];
    u8cp pe = input[1];
    u8cp eof = pe;
    int cs = 0;

    
/* #line 80 "DPATH.rl.c" */
	{
	cs = dpath_start;
	}

/* #line 44 "DPATH.c.rl" */
    
/* #line 83 "DPATH.rl.c" */
	{
	int _klen;
	unsigned int _trans;
	const unsigned char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _dpath_trans_keys + _dpath_key_offsets[cs];
	_trans = _dpath_index_offsets[cs];

	_klen = _dpath_single_lengths[cs];
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

	_klen = _dpath_range_lengths[cs];
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
	cs = _dpath_trans_targs[_trans];

	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

/* #line 45 "DPATH.c.rl" */

    if (cs < 11)
        return DPATHBAD;

    out[0] = input[0];
    out[1] = p;
    input[0] = p;
    return OK;
}
