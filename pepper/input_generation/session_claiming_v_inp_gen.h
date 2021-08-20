#define TOTAL_NUM_SESSIONS 100
#define SHA256_BLOCK_SIZE 32            /* SHA256 outputs a 32 uint8_t digest */

#define PREIMAGE_LEN 4
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_helper(uint8_t *preimage, uint8_t *hash)；
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, uint8_t *data, uint32_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint8_t sha256_hash[32] = { 136, 212, 38, 111, 212, 230, 51, 141, 19, 184, 69, 252, 242, 137, 87, 157, 32, 156, 137, 120, 35, 185, 33, 125, 163, 225, 97, 147, 111, 3, 21, 137 };
// sha256 hash of 'a', 'b', 'c', 'd'

void session_claiming_input_gen (mpq_t * input_q, int num_inputs, char *argv[]) {
    int session_idx = rand() % TOTAL_NUM_SESSIONS; // the index for users
    int usage, rep, sid, hash, input_idx;
    input_idx = 0;
    // session usages
    for (int i = 0; i < TOTAL_NUM_SESSIONS; i++) {
    	usage = (i == session_idx)? 12345 : rand();
        mpq_set_ui(input_q[input_idx], usage, 1);
        input_idx++;
    }
    // session rep updates
    for (int i = 0; i < TOTAL_NUM_SESSIONS; i++) {
    	rep = (i == session_idx)? 54321 : rand();
        mpq_set_ui(input_q[input_idx], rep, 1);
        input_idx++;
    }
    // session sids
    for (int i = 0; i < TOTAL_NUM_SESSIONS; i++) {
    	sid = i;
        mpq_set_ui(input_q[input_idx], sid, 1);
        input_idx++;
    }
    // session hashes
    uint8_t preimage[PREIMAGE_LEN] = {97, 98, 99, 100};
    uint8_t hash[SHA256_BLOCK_SIZE];
    for (int i = 0; i < TOTAL_NUM_SESSIONS; i++) {
    	bool is_right_idx = (i == session_idx);
        if(is_right_idx) {
            sha256_helper(preimage, hash);
            for (int j=0; j < SHA256_BLOCK_SIZE; j++) {
                mpq_set_ui(input_q[input_idx], hash[j], 1);
                input_idx++;
            }
        } 
        else {
            for (int j=0; j < SHA256_BLOCK_SIZE; j++) {
                mpq_set_ui(input_q[input_idx], rand() % 256, 1);
                input_idx++;
            }  
        }
    	// for (int j=0; j < SHA256_BLOCK_SIZE; j++) {
    	// 	if(is_right_idx)
    	// 		mpq_set_ui(input_q[input_idx], sha256_hash[j], 1);
    	// 	else
    	// 		mpq_set_ui(input_q[input_idx], rand() % 256, 1);
		   //  input_idx++;
    	// }
    }

}

/* helper function to compute SHA256 */
void sha256_helper(uint8_t *preimage, uint8_t *hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, preimage, PREIMAGE_LEN);   
    sha256_final(&ctx, hash);   
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
