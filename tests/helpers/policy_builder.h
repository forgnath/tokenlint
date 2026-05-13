#ifndef POLICY_BUILDER_H
#define POLICY_BUILDER_H

/* Construct policy_t directly in tests without touching the YAML parser.
 * See docs/test-strategy.md and docs/architecture.md.
 * TODO: implement builder pattern */

#include "../../include/policy.h"
#include "../../include/tokenlint.h"

/* Example intended usage:
 *
 * policy_t p = policy_builder_new(arena)
 *     .environment(ENV_PROD)
 *     .issuer_exact("https://auth.example.com")
 *     .audience_exact("my-service")
 *     .algorithm(ALG_RS256)
 *     .require_claims(CLAIM_EXP | CLAIM_ISS | CLAIM_AUD)
 *     .max_ttl(3600)
 *     .build();
 */

#endif /* POLICY_BUILDER_H */
