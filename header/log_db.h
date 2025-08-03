#ifndef LOG_DB_H
#define LOG_DB_H

#include "common.h"
#include "queue_set.h"
#include <time.h>
#include <sqlite3.h>



int check_table_exist();

int connect_db();

int disconnect_db();

int create_table();

int clear_table();

int begin_transaction();

int commit_transaction();

int rollback_transaction();

int insert_op(const DBop *op);

int print_log(struct tm *time);



#endif
