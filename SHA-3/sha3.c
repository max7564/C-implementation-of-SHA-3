/**************************************************************************************************
 *
 *  Project
 *  -------
 *  SHA-3 (Keccak) Implementation
 *
 *  File
 *  ----
 *  sha3.c
 *
 *  Purpose
 *  -------
 *  Implements the SHA-3 hashing algorithm defined in FIPS 202.
 *
 *  Author
 *  ------
 *  Max Kim
 *
 *  Date Created
 *  ------------
 *  2026-07-14
 *
 *  Last Modified
 *  -------------
 *  2026-07-16
 *
 *  References
 *  ----------
 *  FIPS PUB 202
 *  Keccak Specifications
 *
 **************************************************************************************************/


/*************************************************************************************************
 * Define Conditions
 *************************************************************************************************/


/*************************************************************************************************
 * Include Header Files
 *************************************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sha3.h"


/*************************************************************************************************
 * Declare Global Constants
 *************************************************************************************************/

 // Number of rows in the Keccak state.
#define KECCAK_ROWS                     5

// Number of columns in the Keccak state. 
#define KECCAK_COLUMNS                  5

// Number of lanes in the state. 
#define KECCAK_STATE_SIZE               25

// Number of bits in one lane. 
#define KECCAK_LANE_SIZE                64

// Number of bytes in one lane.
#define KECCAK_LANE_BYTES               8

// Number of rounds in Keccak-f[1600]. 
#define KECCAK_NUMBER_OF_ROUNDS         24

// SHA3-256 rate in bytes. 
#define SHA3_256_RATE                   136

// SHA-3 domain separation suffix (bits 01 followed by first padding bit).
#define SHA3_DOMAIN_PADDING             0x06

// Final bit of the pad10*1 padding rule.
#define SHA3_FINAL_PADDING_BIT          0x80


/*************************************************************************************************
 * Define Data Types
 *************************************************************************************************/

// Represents the 5×5 Keccak state. 
typedef struct
{
    uint64_t lane[KECCAK_COLUMNS][KECCAK_ROWS];

} KeccakState;

/*************************************************************************************************
 * Declare Global Variables
 *************************************************************************************************/


// Rotation offsets used by the Rho step, indexed as [column x][row y].
static const uint8_t rotation_offsets[KECCAK_COLUMNS][KECCAK_ROWS] =
{
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

// Round constants used by the Iota step. 
static const uint64_t round_constants[KECCAK_NUMBER_OF_ROUNDS] =
{
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};


/*************************************************************************************************
 * Declare Functions
 *************************************************************************************************/


// Helper Functions 

static uint64_t rotate_left(
    uint64_t value,
    unsigned int shift);

static uint64_t load_lane(
    const uint8_t* bytes);

static void store_lane(
    uint64_t lane,
    uint8_t* bytes);


// Keccak Round Functions 

static void theta(
    KeccakState* state);

static void rho(
    KeccakState* state);

static void pi(
    KeccakState* state);

static void chi(
    KeccakState* state);

static void iota(
    KeccakState* state,
    unsigned int round);


// Permutation 

static void keccak_f1600(
    KeccakState* state);


// Sponge 

static void absorb(
    KeccakState* state,
    const uint8_t* message,
    size_t length);

static void squeeze(
    KeccakState* state,
    uint8_t* digest,
    size_t length);


/*************************************************************************************************
 * Define Functions
 *************************************************************************************************/

 /*************************************************************************************************
  * Function Name : rotate_left()
  * Parameters    : uint64_t value,
  *                 unsigned int shift
  * Return Value  : Rotated 64-bit value
  * Operation     : Performs a circular left rotation.
  * Description   : Used by the Rho step to rotate a lane.
  *************************************************************************************************/

static uint64_t rotate_left(
    uint64_t value,
    unsigned int shift)
{
    // A shift of zero must be handled separately because shifting a 64-bit
    // value by 64 bits is undefined behavior in C.
    if (shift == 0U)
    {
        return value;
    }

    return (value << shift) | (value >> (KECCAK_LANE_SIZE - shift));
}

/*************************************************************************************************
 * Function Name : load_lane()
 * Parameters    : const uint8_t* bytes
 * Return Value  : 64-bit lane value
 * Operation     : Assembles a 64-bit lane from 8 bytes in little-endian order.
 * Description   : FIPS 202 defines the state-to-byte-string conversion in
 *                 little-endian order, independent of host endianness.
 *************************************************************************************************/

static uint64_t load_lane(
    const uint8_t* bytes)
{
    uint64_t lane = 0U;
    unsigned int index;

    for (index = 0U; index < KECCAK_LANE_BYTES; index++)
    {
        lane |= ((uint64_t)bytes[index]) << (8U * index);
    }

    return lane;
}

/*************************************************************************************************
 * Function Name : store_lane()
 * Parameters    : uint64_t lane,
 *                 uint8_t* bytes
 * Return Value  : None
 * Operation     : Splits a 64-bit lane into 8 bytes in little-endian order.
 * Description   : Inverse of load_lane(); used when squeezing the digest
 *                 out of the sponge state.
 *************************************************************************************************/

static void store_lane(
    uint64_t lane,
    uint8_t* bytes)
{
    unsigned int index;

    for (index = 0U; index < KECCAK_LANE_BYTES; index++)
    {
        bytes[index] = (uint8_t)(lane >> (8U * index));
    }
}

/*************************************************************************************************
 * Function Name : theta()
 * Parameters    : KeccakState* state
 * Return Value  : None
 * Operation     : XORs each lane with the parities of two nearby columns.
 * Description   : Step θ of the Keccak round function. Computes the parity
 *                 C[x] of every column, derives D[x] = C[x-1] ^ ROTL(C[x+1], 1),
 *                 and XORs D[x] into every lane of column x.
 *************************************************************************************************/

static void theta(
    KeccakState* state)
{
    uint64_t column_parity[KECCAK_COLUMNS];
    uint64_t column_delta[KECCAK_COLUMNS];
    unsigned int x;
    unsigned int y;

    // Compute the parity of each column.
    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        column_parity[x] = state->lane[x][0]
            ^ state->lane[x][1]
            ^ state->lane[x][2]
            ^ state->lane[x][3]
            ^ state->lane[x][4];
    }

    // Combine the parities of the two neighboring columns.
    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        column_delta[x] = column_parity[(x + 4U) % KECCAK_COLUMNS]
            ^ rotate_left(column_parity[(x + 1U) % KECCAK_COLUMNS], 1U);
    }

    // Apply the delta to every lane in the column.
    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        for (y = 0U; y < KECCAK_ROWS; y++)
        {
            state->lane[x][y] ^= column_delta[x];
        }
    }
}

/*************************************************************************************************
 * Function Name : rho()
 * Parameters    : KeccakState* state
 * Return Value  : None
 * Operation     : Rotates each lane by a fixed, lane-specific offset.
 * Description   : Step ρ of the Keccak round function. Provides diffusion
 *                 between the bit positions within each lane.
 *************************************************************************************************/

static void rho(
    KeccakState* state)
{
    unsigned int x;
    unsigned int y;

    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        for (y = 0U; y < KECCAK_ROWS; y++)
        {
            state->lane[x][y] = rotate_left(state->lane[x][y], rotation_offsets[x][y]);
        }
    }
}

/*************************************************************************************************
 * Function Name : pi()
 * Parameters    : KeccakState* state
 * Return Value  : None
 * Operation     : Permutes the positions of the lanes within the state.
 * Description   : Step π of the Keccak round function. Each lane is moved
 *                 according to A'[x][y] = A[(x + 3y) mod 5][x], which
 *                 rearranges the lanes without changing their contents.
 *************************************************************************************************/

static void pi(
    KeccakState* state)
{
    KeccakState temp;
    unsigned int x;
    unsigned int y;

    temp = *state;

    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        for (y = 0U; y < KECCAK_ROWS; y++)
        {
            state->lane[x][y] = temp.lane[(x + (3U * y)) % KECCAK_COLUMNS][x];
        }
    }
}

/*************************************************************************************************
 * Function Name : chi()
 * Parameters    : KeccakState* state
 * Return Value  : None
 * Operation     : Applies a non-linear transformation along each row.
 * Description   : Step χ of the Keccak round function. The only non-linear
 *                 step: A'[x][y] = A[x][y] ^ (~A[x+1][y] & A[x+2][y]).
 *************************************************************************************************/

static void chi(
    KeccakState* state)
{
    KeccakState temp;
    unsigned int x;
    unsigned int y;

    temp = *state;

    for (x = 0U; x < KECCAK_COLUMNS; x++)
    {
        for (y = 0U; y < KECCAK_ROWS; y++)
        {
            state->lane[x][y] = temp.lane[x][y]
                ^ ((~temp.lane[(x + 1U) % KECCAK_COLUMNS][y])
                    & temp.lane[(x + 2U) % KECCAK_COLUMNS][y]);
        }
    }
}

/*************************************************************************************************
 * Function Name : iota()
 * Parameters    : KeccakState* state,
 *                 unsigned int round
 * Return Value  : None
 * Operation     : XORs a round constant into lane (0, 0).
 * Description   : Step ι of the Keccak round function. Breaks the symmetry
 *                 between rounds by mixing in a distinct constant per round.
 *************************************************************************************************/

static void iota(
    KeccakState* state,
    unsigned int round)
{
    state->lane[0][0] ^= round_constants[round];
}

/*************************************************************************************************
 * Function Name : keccak_f1600()
 * Parameters    : KeccakState* state
 * Return Value  : None
 * Operation     : Applies all 24 rounds of the Keccak-f[1600] permutation.
 * Description   : Each round applies the five step mappings θ, ρ, π, χ, ι
 *                 in order, as defined in FIPS 202 Section 3.3.
 *************************************************************************************************/

static void keccak_f1600(
    KeccakState* state)
{
    unsigned int round;

    for (round = 0U; round < KECCAK_NUMBER_OF_ROUNDS; round++)
    {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, round);
    }
}

/*************************************************************************************************
 * Function Name : absorb()
 * Parameters    : KeccakState* state,
 *                 const uint8_t* message,
 *                 size_t length
 * Return Value  : None
 * Operation     : Absorbs the message into the sponge state, then applies
 *                 the SHA-3 padding and absorbs the final block.
 * Description   : Full rate-sized blocks are XORed into the state followed
 *                 by the permutation. The remaining bytes are placed in a
 *                 final block padded with the SHA-3 domain suffix (0x06)
 *                 and the closing pad bit (0x80), per the pad10*1 rule.
 *************************************************************************************************/

static void absorb(
    KeccakState* state,
    const uint8_t* message,
    size_t length)
{
    uint8_t block[SHA3_256_RATE];
    size_t remaining = length;
    size_t offset;
    unsigned int lane_index;
    unsigned int x;
    unsigned int y;

    // Absorb all full rate-sized blocks.
    while (remaining >= SHA3_256_RATE)
    {
        for (lane_index = 0U; lane_index < (SHA3_256_RATE / KECCAK_LANE_BYTES); lane_index++)
        {
            x = lane_index % KECCAK_COLUMNS;
            y = lane_index / KECCAK_COLUMNS;

            state->lane[x][y] ^= load_lane(&message[lane_index * KECCAK_LANE_BYTES]);
        }

        keccak_f1600(state);

        message += SHA3_256_RATE;
        remaining -= SHA3_256_RATE;
    }

    // Build the final padded block from the remaining bytes.
    memset(block, 0, sizeof(block));

    for (offset = 0U; offset < remaining; offset++)
    {
        block[offset] = message[offset];
    }

    // Append the SHA-3 domain suffix and the final padding bit. When only
    // one padding byte fits, both merge into the same byte (0x86).
    block[remaining] ^= SHA3_DOMAIN_PADDING;
    block[SHA3_256_RATE - 1U] ^= SHA3_FINAL_PADDING_BIT;

    // Absorb the final block.
    for (lane_index = 0U; lane_index < (SHA3_256_RATE / KECCAK_LANE_BYTES); lane_index++)
    {
        x = lane_index % KECCAK_COLUMNS;
        y = lane_index / KECCAK_COLUMNS;

        state->lane[x][y] ^= load_lane(&block[lane_index * KECCAK_LANE_BYTES]);
    }

    keccak_f1600(state);
}

/*************************************************************************************************
 * Function Name : squeeze()
 * Parameters    : KeccakState* state,
 *                 uint8_t* digest,
 *                 size_t length
 * Return Value  : None
 * Operation     : Extracts the requested number of digest bytes from the state.
 * Description   : Reads lanes out of the state in little-endian byte order.
 *                 For SHA3-256 the digest (32 bytes) fits within a single
 *                 rate-sized block, so no additional permutations are needed,
 *                 but the loop supports longer outputs for completeness.
 *************************************************************************************************/

static void squeeze(
    KeccakState* state,
    uint8_t* digest,
    size_t length)
{
    uint8_t lane_bytes[KECCAK_LANE_BYTES];
    size_t produced = 0U;
    size_t block_offset;
    size_t copy_count;
    unsigned int lane_index;
    unsigned int x;
    unsigned int y;

    while (produced < length)
    {
        block_offset = 0U;

        // Copy out lanes until the block is exhausted or the digest is full.
        for (lane_index = 0U;
            (lane_index < (SHA3_256_RATE / KECCAK_LANE_BYTES)) && (produced < length);
            lane_index++)
        {
            x = lane_index % KECCAK_COLUMNS;
            y = lane_index / KECCAK_COLUMNS;

            store_lane(state->lane[x][y], lane_bytes);

            copy_count = length - produced;

            if (copy_count > KECCAK_LANE_BYTES)
            {
                copy_count = KECCAK_LANE_BYTES;
            }

            memcpy(&digest[produced], lane_bytes, copy_count);

            produced += copy_count;
            block_offset += copy_count;
        }

        // Permute again if more output is required.
        if (produced < length)
        {
            keccak_f1600(state);
        }
    }

    (void)block_offset;
}

/*************************************************************************************************
 * Function Name : sha3_256()
 * Parameters    : const uint8_t* message,
 *                 size_t message_length,
 *                 uint8_t digest[SHA3_256_DIGEST_SIZE]
 * Return Value  : None
 * Operation     : Computes the SHA3-256 digest of the input message.
 * Description   : Initializes the Keccak state to zero, absorbs the padded
 *                 message, and squeezes out a 32-byte digest.
 *************************************************************************************************/

void sha3_256(
    const uint8_t* message,
    size_t message_length,
    uint8_t digest[SHA3_256_DIGEST_SIZE])
{
    KeccakState state;

    memset(&state, 0, sizeof(state));

    absorb(&state, message, message_length);

    squeeze(&state, digest, SHA3_256_DIGEST_SIZE);
}
