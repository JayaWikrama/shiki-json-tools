#ifndef __SHIKI_JSON_TOOLS__
#define __SHIKI_JSON_TOOLS__

#include <stdint.h>
#include "../shiki-linked-list/shiki-linked-list.h"

#define JSON_DEBUG_ON 1
#define JSON_DEBUG_OFF 0

typedef SHLink sjsonList;

long sjson_get_version(char *_version);
void sjson_view_version();

int8_t sjson_set_debug_mode(int8_t mode);
int8_t sjson_get_list(sjsonList *sjson_list, char *buff_source, uint16_t size_of_source);
int8_t sjson_get_specific_data(char *buff_source, uint16_t size_of_source, char *_key, char *_data);

#endif