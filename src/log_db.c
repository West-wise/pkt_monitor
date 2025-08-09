#include "log_db.h"


static sqlite3 *db = NULL;
static const char *db_name = "detection_log.db";

char *err_msg = NULL;

int check_table_exist(){
    if(db == NULL) {
        fprintf(stderr, "Database is not connected\n");
        return -1;
    }
    char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='detection_log';";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if(rc != SQLITE_OK){
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if(rc == SQLITE_ROW){
        return 0; // Table exists
    } else {
        return -1; // Table does not exist or an error occurred
    }
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
			fprintf(stderr, "disconnect failed! : %s\n", sqlite3_errmsg(db));
			return -1;
		}
		db = NULL;
		// fprintf(stderr, "db disconnect succesfull\n");
	}
	return 0;
}

int create_table(){
	    char *sql = "CREATE TABLE IF NOT EXISTS detection_log (id INTEGER PRIMARY KEY AUTOINCREMENT, detection_time TEXT NOT NULL, protocol TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, pattern TEXT NOT NULL);";
		int rc = sqlite3_exec(db, sql, 0,0, &err_msg);
        if(rc != SQLITE_OK){
                fprintf(stderr, "create table error: %s\n", sqlite3_errmsg(db));
                sqlite3_free(err_msg);
                return -1;
        }else{
		printf("Create table success\n");
	}
        return 0;
}

int clear_table() {
    const char *sql = "DELETE FROM detection_log;";
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to delete all data from table: %s\n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        return -1;
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
	// printf("commit success\n");
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
	const char *sql = "INSERT INTO detection_log (detection_time, protocol, src_ip, src_port, dst_ip, dst_port, pattern) VALUES (?, ?, ?, ?, ?, ?, ?);";
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if(rc != SQLITE_OK){
		fprintf(stderr, "sql compile failed: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	// time
	char time_str[30];
	struct tm time_info;
	// thread-safe인 localtime_r()로 변경 및 NULL 체크
	if(localtime_r((time_t*)&op->time, &time_info) != NULL){
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &time_info);
	} else {
		strncpy(time_str, "1970-01-01 00:00:00", sizeof(time_str));
	}

	if(sqlite3_bind_text(stmt, 1, time_str, -1, SQLITE_TRANSIENT)!=0){
		fprintf(stderr, "Failed to bin timestamp\n");
	}
	// protocol
	switch(op->protocol){
		case 6:
			sqlite3_bind_text(stmt,2,"TCP",-1, SQLITE_TRANSIENT);
			break;
		case 17:
			sqlite3_bind_text(stmt,2,"UDP", -1 ,SQLITE_TRANSIENT);
			break;
		case 1:
			sqlite3_bind_text(stmt,2,"ICMP", -1, SQLITE_TRANSIENT);
			break;
		default:
			sqlite3_bind_text(stmt,2,"ETC", -1, SQLITE_TRANSIENT);
			break;
	}
	// src_ip
	char src_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &op->src_ip, src_ip_str, INET_ADDRSTRLEN);
	sqlite3_bind_text(stmt,3,src_ip_str,-1,SQLITE_TRANSIENT);
	// src_port
	sqlite3_bind_int(stmt,4, op->src_port);
	// dst_ip
	char dst_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &op->dst_ip, dst_ip_str, INET_ADDRSTRLEN);
	sqlite3_bind_text(stmt,5,dst_ip_str, -1, SQLITE_TRANSIENT);
	// dst_port
	sqlite3_bind_int(stmt,6, op->dst_port);
	// pattern
	sqlite3_bind_text(stmt,7, op->matched_pattern, -1, SQLITE_TRANSIENT);

	int rc_step = sqlite3_step(stmt);
	if(rc_step != SQLITE_DONE){
		fprintf(stderr, "Failed to step query exec, Error Code: %d :  %s\n",sqlite3_errcode(db), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}
	sqlite3_finalize(stmt);
	return 0;
}


int print_log(struct tm *time){
	sqlite3_stmt *stmt;
	const char *sql = "SELECT * FROM detection_log;";
	// const char *sql = "SELECT * FROM detection_log;";
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if(rc != SQLITE_OK){
		fprintf(stderr, "sql compile failed: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	char time_str[30];
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time);
	// sqlite3_bind_text(stmt,1,time_str,-1,SQLITE_TRANSIENT);

	printf("\n--- logging after %s  ---\n", time_str);
    int row_count = 0;
    // 3. 쿼리 실행 및 결과 행 처리
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        row_count++;
        // 각 컬럼의 데이터 가져오기 (컬럼 인덱스는 0부터 시작)
        int id = sqlite3_column_int(stmt, 0);
		//  (detection_time, protocol, src_ip, src_port, dst_ip, dst_port, pattern)
        const unsigned char *det_time = sqlite3_column_text(stmt, 1);
        const unsigned char *protocol = sqlite3_column_text(stmt, 2);
        const unsigned char *src_ip = sqlite3_column_text(stmt, 3);
		int src_port = sqlite3_column_int(stmt, 4);
		const unsigned char *dst_ip = sqlite3_column_text(stmt, 5);
		int dst_port = sqlite3_column_int(stmt, 6);
		const unsigned char *pattern = sqlite3_column_text(stmt, 7);


        printf("| DATE: %-19s | Protocol: %-7s | SRC_IP: %-15s | SRC_PORT: %-7d | DST_IP: %-15s | DST_PORT: %-7d | PATTERN: %s |\n",
             det_time, protocol, src_ip, src_port, dst_ip, dst_port, pattern);
    }

    if (row_count == 0) {
        printf("no dection...\n");
    }

	printf("------------------------------------------\n");
	sqlite3_finalize(stmt);
	return 0;
}
