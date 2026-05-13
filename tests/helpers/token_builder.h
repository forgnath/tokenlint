#ifndef TOKEN_BUILDER_H
#define TOKEN_BUILDER_H

/* Construct token_t directly in tests without JWT parsing.
 * See docs/test-strategy.md and docs/architecture.md.
 * TODO: implement builder pattern */

#include "../../include/token.h"
#include "../../include/tokenlint.h"

/* Example intended usage:
 *
 * token_t t = token_builder_new(arena)
 *     .alg(ALG_RS256)
 *     .kid("key-2026-01")
 *     .iss("https://auth.example.com")
 *     .aud_single("my-service")
 *     .exp(reference_time + 3600)
 *     .iat(reference_time)
 *     .build();
 */

#endif /* TOKEN_BUILDER_H */
