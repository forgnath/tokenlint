#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

/* Minimal C test framework for tokenlint */
/* See docs/test-strategy.md for usage */

#include <stdio.h>
#include <string.h>
#include "../../include/findings.h"

typedef void (*test_fn_t)(void);

typedef struct {
    const char *name;
    test_fn_t   fn;
    int         is_security_property;
} test_case_t;

/* TODO: implement tl_assert, tl_run_tests, finding assertion helpers */

#define TEST(name) static void test_##name(void)
#define SECURITY_PROP(name) static void prop_##name(void)

#define ASSERT_TRUE(expr) \
    tl_assert((expr), #expr, __FILE__, __LINE__)
#define ASSERT_FALSE(expr) \
    tl_assert(!(expr), "!(" #expr ")", __FILE__, __LINE__)
#define ASSERT_EQ(a, b) \
    tl_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_NULL(ptr) \
    tl_assert((ptr) == NULL, #ptr " == NULL", __FILE__, __LINE__)
#define ASSERT_NOT_NULL(ptr) \
    tl_assert((ptr) != NULL, #ptr " != NULL", __FILE__, __LINE__)

#define ASSERT_FINDING(fs, id) \
    tl_assert_finding_present((fs), (id), 1, __FILE__, __LINE__)
#define ASSERT_NO_FINDING(fs, id) \
    tl_assert_finding_present((fs), (id), 0, __FILE__, __LINE__)
#define ASSERT_FINDING_SUPPRESSED(fs, id) \
    tl_assert_finding_suppressed((fs), (id), __FILE__, __LINE__)
#define ASSERT_CLEAN(fs) \
    tl_assert_no_active_fail((fs), __FILE__, __LINE__)

void tl_assert(int cond, const char *expr, const char *file, int line);
void tl_assert_finding_present(const finding_set_t *fs, const char *id,
                                int expect_present,
                                const char *file, int line);
void tl_assert_finding_suppressed(const finding_set_t *fs, const char *id,
                                   const char *file, int line);
void tl_assert_no_active_fail(const finding_set_t *fs,
                               const char *file, int line);

int tl_run_tests(const test_case_t *tests, size_t count);

#endif /* TEST_RUNNER_H */
