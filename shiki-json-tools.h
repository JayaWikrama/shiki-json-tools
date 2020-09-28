#ifndef __SHIKI_JSON_TOOLS__
#define __SHIKI_JSON_TOOLS__

#include <stdint.h>
#include <stdlib.h>
#include "../shiki-linked-list/shiki-linked-list.h"

#define JSON_DEBUG_ON 1
#define JSON_DEBUG_OFF 0

typedef SHLink sjsonList;

long sjson_get_version(char *_version);
void sjson_view_version();

int8_t sjson_set_debug_mode(int8_t mode);
void sjson_remove_whitespace_from_json_string(char *_buff, size_t _buff_length);
int16_t sjson_get_list(sjsonList *sjson_list, char *buff_source, uint16_t size_of_source);
uint16_t sjson_count_data_by_key(sjsonList _sjson_list, const char *_key);
int8_t sjson_get_value_by_key_and_position(
 sjsonList _sjson_list,
 const char *_key,
 int _pos,
 char* _value_result
);
int8_t sjson_get_value_by_key_and_prevcond(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 char* _value_result
);
char *sjson_get_value_by_key_as_string_n(
 sjsonList _sjson_list,
 const char *_key,
 int _pos
);
char *sjson_get_value_by_key_as_string(
 sjsonList _sjson_list,
 const char *_key
);
int sjson_get_value_by_key_as_int_n(
 sjsonList _sjson_list,
 const char *_key,
 int _pos,
 int _return_value_if_fail
);
int sjson_get_value_by_key_as_int(
 sjsonList _sjson_list,
 const char *_key,
 int _return_value_if_fail
);
long sjson_get_value_by_key_as_long_n(
 sjsonList _sjson_list,
 const char *_key,
 int _pos,
 long _return_value_if_fail
);
long sjson_get_value_by_key_as_long(
 sjsonList _sjson_list,
 const char *_key,
 long _return_value_if_fail
);
long long sjson_get_value_by_key_as_long_long_n(
 sjsonList _sjson_list,
 const char *_key,
 int _pos,
 long long _return_value_if_fail
);
long long sjson_get_value_by_key_as_long_long(
 sjsonList _sjson_list,
 const char *_key,
 long long _return_value_if_fail
);
char *sjson_get_value_by_prev_cond_as_string_n(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 int _pos
);
char *sjson_get_value_by_prev_cond_string(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key
);
int sjson_get_value_by_prev_cond_int_n(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 int _pos,
 int _return_value_if_fail
);
int sjson_get_value_by_prev_cond_as_int(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 int _return_value_if_fail
);
long sjson_get_value_by_prev_cond_as_long_n(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 int _pos,
 long _return_value_if_fail
);
long sjson_get_value_by_prev_cond_as_long(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 long _return_value_if_fail
);
long long sjson_get_value_by_prev_cond_as_long_long_n(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 int _pos,
 long long _return_value_if_fail
);
long long sjson_get_value_by_prev_cond_as_long_long(
 sjsonList _sjson_list,
 const char *_prev_key,
 const char *_prev_value,
 const char *_key,
 long long _return_value_if_fail
);
void sjson_free(sjsonList *_sjson_list);
int8_t sjson_get_specific_data(
 const char *_buff_source,
 uint16_t size_of_source,
 const char *_key,
 char *_data
);

#endif