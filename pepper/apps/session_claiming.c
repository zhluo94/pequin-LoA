#include <session_claiming.h>

/**
 * Algorithm Description:
 *
 * 1) Verifier sets up the P and V keys:
 *      ./pepper_compile_and_setup_V.sh session_claiming session_claiming.vkey session_claiming.pkey
 *
 * 2) Prover claims that she knows the preimage to that hash        (located in the bin/exo2 file)
 *      ./pepper_compile_and_setup_P.sh session_claiming
 *
 * 3) Verifier generates and provides the input_hash (which is a sha256 hash)     (located in the session_claiming.inputs file)
 *      bin/pepper_verifier_session_claiming gen_input session_claiming.inputs
 *
 * 4) Prover generates a proof (session_claiming.proof) that he knows the preimage
 *      bin/pepper_prover_session_claiming prove session_claiming.pkey session_claiming.inputs session_claiming.outputs session_claiming.proof
 *
 * 5) Finally, Verifier checks the computation without ever knowing the preimage
 *      bin/pepper_verifier_session_claiming verify session_claiming.vkey session_claiming.inputs session_claiming.outputs session_claiming.proof
**/


void compute(struct In *input, struct Out *output) {
    uint32_t i, j, k;
    preimage_t preimages[NUM_SESSIONS];              /* prover will fill it with his private preimage */
    uint8_t prover_hashes[NUM_SESSIONS][SHA256_BLOCK_SIZE];         /* this is the hash of private preimage */

    uint32_t tmp_array[1] = {0};
    uint32_t *input_params[1] = { tmp_array };
    uint32_t lens[1] = { 1 };
    exo_compute(input_params, lens, preimages, 2);     /* fill preimage variable with prover's private preimage */
    
    /* compute sha256 for all preimages */
    SHA256_CTX ctx;
    for (i=0; i < NUM_SESSIONS; i++) {
        sha256_init(&ctx);
    	sha256_update(&ctx, preimages[i].preimage, PREIMAGE_LEN);   
    	sha256_final(&ctx, prover_hashes[i]);	
    }

    uint32_t session_usage, session_rep_update, tmp_usage, tmp_rep_update;
    uint8_t *session_hash;

    output->total_usage = 0;
    output->total_rep_update = 0;

    for (i = 0; i < TOTAL_NUM_SESSIONS; i++) {				/* iterate all the sessions in the table */
    	session_hash = input->hashes[i];
    	session_usage = input->usages[i];
    	session_rep_update = input->rep_updates[i];
    	for (j=0; j < NUM_SESSIONS; j++) {					/* iterate all the known hashes*/
    		tmp_usage = session_usage;
    		tmp_rep_update = session_rep_update;
    		for (k = 0; k < SHA256_BLOCK_SIZE; k++) { 	/* check each byte of hash */
    			if (session_hash[k] != prover_hashes[j][k]) {   /* if at most one is different, the prover does not know the preimage! */
            		    tmp_usage = 0;
            		    tmp_rep_update = 0;
        		}
    		}	
        	output->total_usage += tmp_usage;
        	output->total_rep_update += tmp_rep_update;
    	}
    }
}


/**
 * SHA256 code from https://github.com/cnasikas/data-processing/tree/master/zkp/app/queries/sha256
**/
void sha256_transform(SHA256_CTX *ctx, uint8_t *data) {
	uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
	for ( ; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, uint8_t *data, uint32_t len) {
	uint32_t i;
	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, uint8_t *hash) {
	uint32_t i;
	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56) {
            ctx->data[i++] = 0x00;
        }
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64) {
            ctx->data[i++] = 0x00;
        }
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}
