#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define BUFFER_SIZE 1024
#define BUFFER_CHUNK 10*BUFFER_SIZE
#define PREIMAGE_LEN 4

void compute(int *input, uint8_t **output);

int main(int argc, char **argv) {
    int i = 0, j = 0;
    int nRead;
    char buf[BUFFER_SIZE];
    int inStrSize = BUFFER_CHUNK;
    char *inString = (char *) malloc(inStrSize*sizeof(char));
    char *tok, *stok;
    char *saveptr1, *saveptr2, *str1, *str2;

    int input_length, output_length;
    int *dst;
    int *input;
    uint8_t **output;

    if ((argc == 0) || (argv == 0)) { exit(-1); }

    while (0 < (nRead = read(STDIN_FILENO, buf, BUFFER_CHUNK))) {
        if (i + nRead > inStrSize) { // assumes that BUFFER_CHUNK 
            inStrSize += BUFFER_CHUNK;
            if (NULL == (inString = (char *) realloc(inString, inStrSize))) {
                perror("failed to realloc inString");
                exit(-1);
            }
        }
        memcpy(inString + i, buf, nRead);
        i += nRead;
    }
    inString[i] = '\0';  // null terminate

    // tokenize on spaces, braces
    for (i=-1, str1 = inString ; ; i++, str1 = NULL) {
        tok = strtok_r(str1, " []", &saveptr1);

        if (i == input_length || NULL == tok) { break; }

        if (i < 0) {
            dst = &input_length;
        } else {
            dst = &(input[i]);
        }

        // tokenize on rational notation, e.g., 5%2
        // note that we turn these into integers!
        for (str2 = tok; ; str2 = NULL) {
            stok = strtok_r(str2, " %", &saveptr2);

            if (NULL == stok) { break; }

            if (str2 != NULL) {
                *dst = (int) atoi(stok);
            } else {
                *dst /= (int) atoi(stok);
            }
        }

        if (i < 0) {
            input = (int *) calloc(input_length, sizeof(int));
        }
    }

    free(inString);
    //fprintf(stderr, "number of sessions: %u\n", input[0]);
    output_length = input[0];
    output = (uint8_t **) calloc(output_length, sizeof(uint8_t*));
    for(i = 0; i < output_length; i ++) {
        output[i] = calloc(PREIMAGE_LEN, sizeof(uint8_t));
    }

    compute(input, output);

    //fprintf(stderr, "\n");
    for (i=0; i < output_length; i++) {
        for (j = 0; j < PREIMAGE_LEN; j++) {
            printf("%u\n", output[i][j]);
            //fprintf(stderr, "%u ", output[i][j]);
        }
    }
    //fprintf(stderr, "\n");

    free(input);
    for(i = 0; i < output_length; i ++)
    {
        free(output[i]);
    }
    free(output);

    return 0;
}

void compute(int *input, uint8_t **output) {
    int num_sessions = input[0];
    int i, j;
    uint32_t pre_sum = 2387; // random
    //uint8_t preimage[PREIMAGE_LEN] = {97, 98, 99, 100};
    //srand(100); // use 100 as the seed 
    for (i = 0; i < num_sessions; i++) {
        for (j = 0; j < PREIMAGE_LEN; j++) {
            //output[i][j] = preimage[j];
            output[i][j] = (pre_sum >> (8 * j)) & 255; 
        }
        pre_sum++;  
     }
} 
