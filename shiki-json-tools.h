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
uint16_t sjson_count_data_by_key(sjsonList _sjson_list, char *_key);
int8_t sjson_get_value_by_key_and_position(sjsonList _sjson_list, char *_key, int _pos, char* _value_result);
int8_t sjson_get_value_by_key_and_prevcond(sjsonList _sjson_list, char *_prev_key, char *_prev_value, char *_key, char* _value_result);
void sjson_free(sjsonList *_sjson_list);
int8_t sjson_get_specific_data(char *buff_source, uint16_t size_of_source, char *_key, char *_data);

#endif