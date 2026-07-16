/**************************************************************************************************
 *
 *  Project
 *  -------
 *  SHA-3 (Keccak) Implementation
 *
 *  File
 *  ----
 *  sha3.h
 *
 *  Purpose
 *  -------
 *  Public interface for the SHA-3 hashing algorithm defined in FIPS 202.
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

#ifndef SHA3_H
#define SHA3_H

/*************************************************************************************************
 * Include Header Files
 *************************************************************************************************/

#include <stdint.h>
#include <stddef.h>

/*************************************************************************************************
 * Declare Global Constants
 *************************************************************************************************/

// SHA3-256 output length in bytes.
#define SHA3_256_DIGEST_SIZE            32

/*************************************************************************************************
 * Declare Functions
 *************************************************************************************************/

/*************************************************************************************************
 * Function Name : sha3_256()
 * Parameters    : const uint8_t* message,
 *                 size_t message_length,
 *                 uint8_t digest[SHA3_256_DIGEST_SIZE]
 * Return Value  : None
 * Operation     : Computes the SHA3-256 digest of the input message.
 * Description   : Absorbs the message into the Keccak sponge, applies the
 *                 SHA-3 domain padding, and squeezes out a 32-byte digest.
 *************************************************************************************************/

void sha3_256(
    const uint8_t* message,
    size_t message_length,
    uint8_t digest[SHA3_256_DIGEST_SIZE]);

#endif /* SHA3_H */
