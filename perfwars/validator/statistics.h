#ifndef _STATISTICS_H
#include "common.h"

//difference of two timevals as a float
//standard deviation as a float
//mean average as a float


/* CSV format ? */
/*
 * test_start
 * test_end
 * random_seed
 * run_time
 * max_concurrency
 * round_no
 * round_start
 * round_end
 * p1_curve_x
 * p1_curve_y
 * p2_curve_x
 * p2_curve_y
 * realized_end
 * mean_latency
 * timeout
 * concurrency
 * success_no
 * failed_no
 * mean_conntime
 * mean_first_byte
 * validation_failed_no
 * validation_success_no
 */

void statistics_calculate(round_t *r);
void statistics_json_round(round_t *r);
const char * statistics_json_manager(manager_t *m);
#endif
