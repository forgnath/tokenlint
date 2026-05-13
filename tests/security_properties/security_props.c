/* Security property tests — release-blocking.
 * Runner exits 2 (not 1) on any failure.
 * See docs/test-strategy.md for all 12 property definitions.
 */

#include "../helpers/test_runner.h"

/* TODO: implement all 12 named security properties:
 *
 * PROP_ALG_NONE_ALWAYS_FAILS
 * PROP_POLICY_ALG_NONE_SCHEMA_FAILS
 * PROP_BAD_SIGNATURE_ALWAYS_FAILS
 * PROP_UNKNOWN_ALG_ALWAYS_FAILS
 * PROP_AMBIGUOUS_KEY_MATCH_FAILS
 * PROP_REQUIRE_KID_PREVENTS_FALLBACK
 * PROP_EXPIRED_TOKEN_ALWAYS_FAILS
 * PROP_SUPPRESSION_CANNOT_HIDE_SCHEMA_ERRORS
 * PROP_CLI_SUPPRESSION_NEVER_AFFECTS_EXIT_BY_DEFAULT
 * PROP_AT_FLAG_PRODUCES_DETERMINISTIC_OUTPUT
 * PROP_SCHEMA_VERSION_MISMATCH_HALTS
 * PROP_FINDING_OVERFLOW_NEVER_SILENT
 */

int main(void) {
    test_case_t props[] = {
        /* { "PROP_NAME", prop_fn, 1 } */
    };
    return tl_run_tests(props, sizeof(props) / sizeof(props[0]));
}
