#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include "sha3.h"

static void print_digest(const uint8_t digest[SHA3_256_DIGEST_SIZE])
{
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++)
    {
        printf("%02x", digest[i]);
    }
}

static int run_test(const char* name, const uint8_t* msg, size_t len, const char* expected_hex)
{
    uint8_t digest[SHA3_256_DIGEST_SIZE];
    char hex[2 * SHA3_256_DIGEST_SIZE + 1];

    sha3_256(msg, len, digest);

    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++)
    {
        sprintf(&hex[2 * i], "%02x", digest[i]);
    }

    int ok = (strcmp(hex, expected_hex) == 0);
    printf("%-28s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok)
    {
        printf("  got:      ");
        print_digest(digest);
        printf("\n  expected: %s\n", expected_hex);
    }
    return ok;
}

int main(void)
{
    int all_ok = 1;

    // Empty string
    all_ok &= run_test("empty string", (const uint8_t*)"", 0,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    // "abc"
    all_ok &= run_test("\"abc\"", (const uint8_t*)"abc", 3,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    // 448-bit message
    const char* m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    all_ok &= run_test("448-bit message", (const uint8_t*)m448, strlen(m448),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    // 896-bit message
    const char* m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    all_ok &= run_test("896-bit message", (const uint8_t*)m896, strlen(m896),
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");

    // One million 'a' characters
    {
        static uint8_t million[1000000];
        memset(million, 'a', sizeof(million));
        all_ok &= run_test("1,000,000 x 'a'", million, sizeof(million),
            "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
    }

    // Length exactly one byte less than the rate (135 bytes) - padding edge case
    {
        uint8_t msg[135];
        memset(msg, 0x00, sizeof(msg));
        uint8_t digest[SHA3_256_DIGEST_SIZE];
        sha3_256(msg, sizeof(msg), digest);
        printf("135-byte edge case digest:   ");
        print_digest(digest);
        printf("\n");
    }

    // Length exactly equal to the rate (136 bytes)
    {
        uint8_t msg[136];
        memset(msg, 0x00, sizeof(msg));
        uint8_t digest[SHA3_256_DIGEST_SIZE];
        sha3_256(msg, sizeof(msg), digest);
        printf("136-byte edge case digest:   ");
        print_digest(digest);
        printf("\n");
    }

    printf("\n%s\n", all_ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return all_ok ? 0 : 1;
}