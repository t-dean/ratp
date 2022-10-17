#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#include <stdio.h>
#include <string.h>

/**************/
/* Test cases */
/**************/

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_BOLD "\033[1m"
#define COLOR_RESET "\033[0m"

#define DECL_TEST(name) int test_##name(void)
#define DECL_LOCAL_TEST(name) static DECL_TEST(name)
#define TEST_END() return 0
#define TEST_MAIN_START() int passed = 0, failed = 0
#define RUN_TEST(name) do\
                       {\
                         if (test_##name() != 0)\
                         {\
                           failed++;\
                           printf("%-60s " COLOR_RED "FAILED" COLOR_RESET "\n", #name);\
                         }\
                         else\
                         {\
                           passed++;\
                           printf("%-60s " COLOR_GREEN "PASSED" COLOR_RESET "\n", #name);\
                         }\
                       } while (0)
#define TEST_MAIN_END() do\
                      {\
                        printf("Unit tests complete: " COLOR_BOLD "%d PASSED, %d FAILED" COLOR_RESET "\n", passed, failed);\
                        if (failed > 0)\
                        {\
                          return 1;\
                        }\
                        else\
                        {\
                          return 0;\
                        }\
                      } while (0)

/**************/
/* Assertions */
/**************/

#define ASSERT(a) ASSERT_INT(a, __LINE__, __FILE__)
#define ASSERT_EQ(a, b) ASSERT_EQ_INT(a, b, __LINE__, __FILE__)
#define ASSERT_STR_EQ(a, b) ASSERT_STR_EQ_INT(a, b, __LINE__, __FILE__)
#define ASSERT_NE(a, b) ASSERT_NE_INT(a, b, __LINE__, __FILE__)
#define ASSERT_STR_NE(a, b) ASSERT_STR_NE_INT(a, b, __LINE__, __FILE__)
#define ASSERT_LT(a, b) ASSERT_LT_INT(a, b, __LINE__, __FILE__)
#define ASSERT_LT(a, b) ASSERT_LT_INT(a, b, __LINE__, __FILE__)
#define ASSERT_LE(a, b) ASSERT_LE_INT(a, b, __LINE__, __FILE__)
#define ASSERT_GE(a, b) ASSERT_GE_INT(a, b, __LINE__, __FILE__)

#define ASSERT_INT(a, line, file) do\
                        {\
                          if (!(a))\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s\n",\
                                file, line, #a);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_EQ_INT(a, b, line, file) do\
                        {\
                          if (a != b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s == %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_STR_EQ_INT(a, b, line, file) do\
                        {\
                          if (strcmp(a, b) != 0)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: \"%s\" == \"%s\"\n",\
                                file, line, a, b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_STR_NE_INT(a, b, line, file) do\
                        {\
                          if (strcmp(a, b) == 0)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: \"%s\" != \"%s\"\n",\
                                file, line, a, b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_NE_INT(a, b, line, file) do\
                        {\
                          if (a == b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s != %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_LT_INT(a, b, line, file) do\
                        {\
                          if (a >= b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s < %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_GT_INT(a, b, line, file) do\
                        {\
                          if (a <= b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s > %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_LE_INT(a, b, line, file) do\
                        {\
                          if (a > b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s <= %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#define ASSERT_GE_INT(a, b, line, file) do\
                        {\
                          if (a < b)\
                          {\
                            fprintf(stderr, "%s:%d: assert failed: %s >= %s\n",\
                                file, line, #a, #b);\
                            return 1;\
                          }\
                        } while (0)

#endif /* UNIT_TEST_H */
