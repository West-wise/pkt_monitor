#include "common.h"
#include "log_db.h"


static sqlite3 *db = NULL;
static const char *db_name = "detection_log.db";

char *err_msg = NULL;

int check_table_exist(){
        if(db == NULL) {
                fprintf(stderr, "Databse is not exist\n");
                return -1;
        }
        char *sql = "SELECT * FROM detection_log;";
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if(rc != SQLITE_OK){
                fprintf(stderr,"table is not exist\n");
                return -1;

        }
        if(sqlite3_step(stmt) == SQLITE_ROW){
                sqlite3_finalize(stmt);
                return 0;
        }

        sqlite3_finalize(stmt);
        return -1;
}

int connect_db(){
        int rc = sqlite3_open(db_name, &db);
        if(rc != SQLITE_OK){
                fprintf(stderr, "open failed : %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                return -1;
        }

        sqlite3_exec(db, "PRAGMA journal_mode = WAL;",0,0,NULL); //wal mode 활성화
        return 0;
}

int disconnect_db(){
        if(db != NULL){
                int rc = sqlite3_close(db);
                if(rc != SQLITE_OK){
                        fprintf(stderr, "disconnect failed!\n");
                        return -1;
                }
                db = NULL;
                fprintf(stderr, "db disconnect succesfull\n");
        }
        return 0;
}

int create_table(){
                char *sql = "CREATE TABLE IF NOT EXISTS detection_log (detection_time TEXT NOT NULL, protocol TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, pattern TEXT NOT NULL );";
                        int rc = sqlite3_exec(db, sql, 0,0, &err_msg);
        if(rc != SQLITE_OK){
                fprintf(stderr, "create table error: %s\n", err_msg);
                sqlite3_free(err_msg);
                return -1;
        }else{
                printf("Create table success\n");
        }
        return 0;
}

int begin_transaction(){
        if(db==NULL){
                fprintf(stderr, "db not connected, cannot begin transaction\n");
                return -1;
        }
        int rc = sqlite3_exec(db, "BEGIN TRANSACTION;",0,0,NULL);
        if(rc != SQLITE_OK){
                fprintf(stderr, "Failed to start Transaction\n");
                return -1;
        }
        return 0;
}

int commit_transaction(){
        if (db == NULL) {
                fprintf(stderr, "Database not connected. cannot commit transaction\n");
                return -1;
        }
        int rc = sqlite3_exec(db, "COMMIT;", 0, 0, NULL);
        if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to commit transaction");
                return -1;
        }
        return 0;
}


int rollback_transaction(){
        if (db == NULL) {
                fprintf(stderr, "db not connected. cannot rollback transaction.\n");
                return -1;
        }
        int rc = sqlite3_exec(db, "ROLLBACK;", 0, 0, NULL);
        if (rc != SQLITE_OK) {
                fprintf(stderr, "[DB] Error: Failed to rollback transaction: %s\n", sqlite3_errmsg(db));
                return -1;
        }
        return 0;
}

int insert_op(const DBop *op){
        if(db==NULL || op == NULL){
                fprintf(stderr, "cannot insert data\n");
                return -1;
        }
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO detection_log (detection_time, protocol, src_ip, src_port, dst_ip, dst_posrt, pattern) VALUES (?, ?, ?, ?, ?, ?, ?);";

        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if(rc != SQLITE_OK){
                fprintf(stderr, "sql compile failed\n");
                return -1;
        }


        char time_str[30];
        struct tm *info = localtime((time_t*)&op->time);
        if(info){
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", info);
        } else {

        }
        sqlite3_bind_text(stmt, 1, time_str, -1, SQLITE_TRANSIENT);





}


void print_log(void){

}
