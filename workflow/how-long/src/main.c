#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

const int TERMINAL_COL_WIDTH = 80;

const char PROGRAM_TITLE[] = "HOW LONG?";
const char PROGRAM_TITLE_LEN = sizeof(PROGRAM_TITLE);

const size_t DATE_STR_ISO8601_LEN = 10;

typedef struct Date {
    int year;
    int month;
    int day;
} Date;

typedef enum AppError {
    APP_ERR_DATE_STR_INVALID_LENGTH = 1,
} AppError;

typedef struct Result {
    bool ok;
    AppError app_err;
} Result;

void render_title() {
    for (int i = 0; i < TERMINAL_COL_WIDTH; i++) {
        printf("=");
    }
    printf("\n\n");

    for (int i = 0; i < ((TERMINAL_COL_WIDTH / 2) - (PROGRAM_TITLE_LEN / 2)); i++) {
        printf(" ");
    }
    printf("%s", PROGRAM_TITLE);
    printf("\n\n");

    for (int i = 0; i < TERMINAL_COL_WIDTH; i++) {
        printf("=");
    }
    printf("\n\n");
}

Result parse_date_str(char* date_str, size_t date_str_len, struct tm* date) {
    if (date_str_len != DATE_STR_ISO8601_LEN) {
        return (Result) { .ok = false, .app_err = APP_ERR_DATE_STR_INVALID_LENGTH };
    }

    char year[] = "0000";
    char month[] = "00";
    char day[] = "00";

    strncpy(year, date_str, 4);
    strncpy(month, date_str + 5, 2);
    strncpy(day, date_str + 8, 2);

    date->tm_year = atoi(year) - 1900;
    date->tm_mon = atoi(month) - 1;
    date->tm_mday = atoi(day);

    return (Result) { .ok = true, .app_err = 0 };
}

int main(int argc, char* argv[]) {
    render_title();

    if (argc != 2) {
        printf("Woops! Expected exactly one arg. Arg must be a date string in ISO 8601 format\nexcluding the timestamp.\n");
        return 1;
    }

    /** This should be an ISO formatted string. */
    char* date_str = argv[1];
    const size_t date_str_len = strlen(date_str);

    struct tm target_date_tm = { 0 };

    Result date_parse_result = parse_date_str(date_str, date_str_len, &target_date_tm);
    if (date_parse_result.app_err == APP_ERR_DATE_STR_INVALID_LENGTH) {
        printf("Woops, the date string given has an invalid length!");
    }

    time_t now = time(NULL);
    time_t target_date = mktime(&target_date_tm);

    double seconds_diff = difftime(target_date, now);

    printf("Aproximatelly %d days until %s", (int)(seconds_diff / (60 * 60 * 24) + 1), asctime(&target_date_tm));

    return 0;
}