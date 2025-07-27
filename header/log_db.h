#ifndef LOG_DB_H
#define LOG_DB_H


#include <time.h>
#include <sqlite3.h>
#include "common.h"
#include "queue_set.h"

int check_table_exist();

int connect_db();

int disconnect_db();

int create_table();

void print_log(void);

int begin_transaction();

int commit_transaction();

int rollback_transaction();

int insert_op(const DBop *op);



#endif