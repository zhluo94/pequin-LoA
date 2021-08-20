#define TOTAL_NUM_SESSIONS 100
#define SHA256_BLOCK_SIZE 32            /* SHA256 outputs a 32 uint8_t digest */

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
    for (int i = 0; i < TOTAL_NUM_SESSIONS; i++) {
    	bool is_right_idx = (i == session_idx);
    	for (int j=0; j < SHA256_BLOCK_SIZE; j++) {
    		if(is_right_idx)
    			mpq_set_ui(input_q[input_idx], sha256_hash[j], 1);
    		else
    			mpq_set_ui(input_q[input_idx], rand() % 256, 1);
		    input_idx++;
    	}
    }

}
