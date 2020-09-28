/*
    lib info    : SHIKI_LIB_GROUP - JSON TOOLS
    ver         : 2.00.20.07.28
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2020 HANA,. Jaya Wikrama
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "shiki-json-tools.h"

#define SJSON_VERSION "2.00.20.07.28"

typedef enum {
  SJSON_DEBUG_INFO = 0x00,
  SJSON_DEBUG_VERSION = 0x01,
  SJSON_DEBUG_WARNING = 0x02,
  SJSON_DEBUG_ERROR = 0x03,
  SJSON_DEBUG_CRITICAL = 0x04
} sjson_debug_type;

typedef enum {
  SJSON_PARRENT_NULL = 0x00,
  SJSON_PARRENT_OBJECT = 0x01,
  SJSON_PARRENT_ARRAY = 0x02
} sjson_parrent_type;

int8_t json_debug_mode_status = 0x00;

static void sjson_debug(const char *_function_name, sjson_debug_type _debug_type, char *_debug_msg, ...){
  if (json_debug_mode_status || _debug_type != SJSON_DEBUG_INFO){
    struct tm *d_tm = NULL;
    struct timeval tm_debug;
    uint16_t msec = 0;
    gettimeofday(&tm_debug, NULL);
    d_tm = localtime(&tm_debug.tv_sec);
    msec = tm_debug.tv_usec/1000;
    #ifdef __linux__
    if (_debug_type == SJSON_DEBUG_INFO)
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SJSON\033[1;32m INFO\033[0m %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _function_name
      );
    else if (_debug_type == SJSON_DEBUG_VERSION)
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SJSON\033[1;32m VERSION\033[0m %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _function_name
      );
    else if (_debug_type == SJSON_DEBUG_WARNING)
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SJSON\033[1;33m WARNING\033[0m %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _function_name
      );
    else if (_debug_type == SJSON_DEBUG_ERROR)
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SJSON\033[1;31m ERROR\033[0m %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _function_name
      );
    else if (_debug_type == SJSON_DEBUG_CRITICAL)
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m SJSON\033[1;31m CRITICAL\033[0m %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _function_name
      );
    #else
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d [%02x]: %s: ",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, _debug_type, _function_name
      );
    #endif

    va_list aptr;
    va_start(aptr, _debug_msg);
	  vfprintf(stdout, _debug_msg, aptr);
	  va_end(aptr);
  }
}

static SHLDataTypes sjson_check_value_type(char *_buff){
  uint16_t idx_buffer = 0;
  uint8_t dot_flags = 0;
  uint8_t min_flags = 0;
  if (_buff[0] == '-' || _buff[0] == '+'){
    idx_buffer = 1;
  }
  else {
    if(strcmp(_buff, "null") == 0){
      return SL_POINTER;
    }
    else if (strcmp(_buff, "true") == 0){
      strcpy(_buff, "1");
      return SL_BOOLEAN;
    }
    else if (strcmp(_buff, "false") == 0){
      strcpy(_buff, "0");
    }
  }
  uint16_t i = 0;
  uint16_t len = (uint16_t) strlen(_buff);
  for (i = idx_buffer; i < len; i++){
    if (_buff[i] != '0' &&
     _buff[i] != '1' &&
     _buff[i] != '2' &&
     _buff[i] != '3' &&
     _buff[i] != '4' &&
     _buff[i] != '5' &&
     _buff[i] != '6' &&
     _buff[i] != '7' &&
     _buff[i] != '8' &&
     _buff[i] != '9'
    ){
      if (_buff[i] == '-' && (min_flags || !i)){
        return SL_TEXT;
      }
      else if (_buff[i] == '-'){
        min_flags = 0x01;
      }
      else if (_buff[i] == '.' && dot_flags){
        return SL_TEXT;
      }
      else if (_buff[i] == '.'){
        dot_flags = 0x01;
      }
      else {
        return SL_TEXT;
      }
    }
  }
  if (dot_flags){
    return SL_FLOAT;
  }
  return SL_NUMERIC;
}

int8_t sjson_set_debug_mode(int8_t mode){
  json_debug_mode_status = mode;
  return 0;
}

long sjson_get_version(char *_version){
    strcpy(_version, SJSON_VERSION);
    long version_in_long = 0;
    uint8_t idx_ver = 0;
    uint8_t multiplier = 10;
    while(idx_ver < 13){
        if(SJSON_VERSION[idx_ver] != '.' && SJSON_VERSION[idx_ver] != 0x00){
            if (version_in_long == 0){
                version_in_long = SJSON_VERSION[idx_ver] - '0';
            }
            else{
                version_in_long = (version_in_long*multiplier) + (SJSON_VERSION[idx_ver] - '0');
            }
        }
        else if (SJSON_VERSION[idx_ver] == 0x00){
            break;
        }
        idx_ver++;
    }
    return version_in_long;
}

void sjson_view_version(){
  sjson_debug(__func__, SJSON_DEBUG_VERSION, "%s\n", SJSON_VERSION);
}

void sjson_remove_whitespace_from_json_string(char *_buff, size_t _buff_length){
  size_t idx_buff = 0;
  size_t idx_new_buff = 0;
  int8_t char_x = 0;
  for (idx_buff = 0; idx_buff < _buff_length; idx_buff++){
    if (char_x){
      _buff[idx_new_buff] = _buff[idx_buff];
      idx_new_buff++;
    }
    else {
      if (_buff[idx_buff] != 0x20 &&
       _buff[idx_buff] != 0x0d &&
       _buff[idx_buff] != 0x0a &&
       _buff[idx_buff] != '\t'
      ){
        _buff[idx_new_buff] = _buff[idx_buff];
        idx_new_buff++;
      }
    }
    if (_buff[idx_buff] == '\"'){
      char_x = !char_x;
    }
  }
  _buff[idx_new_buff] = 0x00;
}

int16_t sjson_get_list(sjsonList *sjson_list, char *buff_source, uint16_t size_of_source){
  uint8_t cnt_data = 0x00;
  uint8_t cnt_switch = 0x00;
  uint16_t cnt_tmp = 0;
  uint16_t sjson_key_size = 8;
  uint16_t sjson_value_size = 8;
  SHLinkCustomData sjson_data;

  uint16_t i = 0;
  uint16_t start_bytes = 0;
  uint8_t store_state = 0x00;
  uint8_t array_anomaly = 0x00;
  uint8_t store_numeric = 0x00;

  uint8_t obj_counter = 0x00;
  uint8_t arr_counter = 0x00;

  SHLDataTypes json_types = SL_POINTER;

  sjson_parrent_type sjson_parrent_list[16];
  memset(sjson_parrent_list, SJSON_PARRENT_NULL, sizeof(sjson_parrent_type));
  uint8_t sjson_parrent_position = 0;

  while (buff_source[start_bytes] != '{' && buff_source[start_bytes] != '[' && buff_source[start_bytes] != 0x00){
    start_bytes++;
  }

  if (buff_source[start_bytes] == '['){
    sjson_parrent_list[0] = SJSON_PARRENT_ARRAY;
  }
  else {
    sjson_parrent_list[0] = SJSON_PARRENT_OBJECT;
  }

  if (buff_source[start_bytes] == 0x00){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid json format\n");
    return -1;
  }

  sjson_remove_whitespace_from_json_string(buff_source + start_bytes, (size_of_source - start_bytes));
  size_of_source = strlen(buff_source);

  char *buff_key_tmp = NULL;
  buff_key_tmp = (char *) malloc(sjson_key_size * sizeof(char));
  if (buff_key_tmp == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "failed to allocate buff_key_tmp memory\n");
    return -2;
  }
  char *buff_value_tmp = NULL;
  buff_value_tmp = (char *) malloc(sjson_value_size * sizeof(char));
  if (buff_value_tmp == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "failed to allocate buff_value_tmp memory\n");
    free(buff_key_tmp);
    buff_key_tmp = NULL;
    return -2;
  }

  char *buff_check = NULL;
  start_bytes++;

  for (i=start_bytes; i<size_of_source; i++){
    if (buff_source[i] == ']'){
      if (sjson_parrent_list[sjson_parrent_position] != SJSON_PARRENT_ARRAY){
        sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid structure (1)");
        goto sjson_get_list_err;
      }
      sjson_parrent_list[sjson_parrent_position] = SJSON_PARRENT_NULL;
      sjson_parrent_position--;
      if (buff_source[i + 1] == '{' ||
       buff_source[i + 1] == '['
      ){
        sjson_debug(__func__, SJSON_DEBUG_ERROR, "find problem for \",\" invalid possition (1)");
        goto sjson_get_list_err;
      }
    }
    else if (buff_source[i] == '['){
      if (i >= 2){
        if (!((buff_source[i - 1] == ',' && buff_source[i - 2] == ']') ||
         buff_source[i - 1] == ':' ||
         buff_source[i - 1] == '[')
        ){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid structure (1.1)");
          goto sjson_get_list_err;
        }
      }
      sjson_parrent_position++;
      sjson_parrent_list[sjson_parrent_position] = SJSON_PARRENT_ARRAY;
    }
    if ((buff_source[i]!='{' && buff_source[i]!='}' && (buff_source[i]!='\"' || array_anomaly)) || i == (size_of_source-1)){
      if (!cnt_switch){
        if ((buff_source[i] == ':' && (buff_source[i+1] == '{' || buff_source[i+1] == '[')) ||
         (buff_source[i] == ']')
        ){
          if (cnt_tmp){
            buff_key_tmp[cnt_tmp] = 0x00;
            buff_value_tmp[0] = 0x00;
            if (buff_source[i+1] == '{'){
              sprintf(buff_value_tmp, "obj_%i", obj_counter);
              obj_counter++;
            }
            else if (buff_source[i+1] == '['){
              sprintf(buff_value_tmp, "arr_%i", arr_counter);
              arr_counter++;
            }
            shilink_fill_custom_data(
             &sjson_data,
             (void *) buff_key_tmp, 
             (uint16_t) strlen(buff_key_tmp),
             (void *) buff_value_tmp,
             (uint16_t) strlen(buff_value_tmp),
             SL_POINTER);
            shilink_append(sjson_list, sjson_data);

            if (sjson_key_size != 8){
              sjson_key_size = 8;
              buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
            }
            if (sjson_value_size != 8){
              sjson_value_size = 8;
              buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
            }
            cnt_data++;
          }
          store_state = 0x00;
          cnt_switch = 0x00;
          cnt_tmp = 0;
          buff_check = NULL;
        }
        else if(buff_source[i] == ':'){
          buff_key_tmp[cnt_tmp] = 0x00;
          cnt_switch = 0x01;
          cnt_tmp = 0;
        }
        else if (buff_source[i] != '[' && buff_source[i] != ',' && store_state == 1) {
          if ((sjson_key_size - 2) == cnt_tmp){
            sjson_key_size += 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          buff_key_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
        else if (!store_state &&
         sjson_parrent_list[sjson_parrent_position] == SJSON_PARRENT_OBJECT &&
         buff_source[i - 1] != ']'
        ){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "key problem (0) after key: %s\n", buff_key_tmp);
          goto sjson_get_list_err;
        }
      }
      else {
        if((buff_source[i] == ',' && array_anomaly == 0) ||
         (buff_source[i] == ']' && array_anomaly == 0) ||
         (buff_source[i] == '[' && store_state == 0) ||
         i == (size_of_source-1)
        ){
          buff_value_tmp[cnt_tmp] = 0x00;
          json_types = SL_TEXT;
          if (buff_source[i] == '{'){
            sprintf(buff_value_tmp, "obj_%i", obj_counter);
            obj_counter++;
            json_types = SL_POINTER;
          }
          else if (buff_source[i] == '['){
            sprintf(buff_value_tmp, "arr_%i", arr_counter);
            arr_counter++;
            json_types = SL_POINTER;
          }
          if (json_types != SL_POINTER){
            if (buff_check == NULL){
              buff_check = buff_source + i - strlen(buff_value_tmp);
            }
            if ((buff_check - 1)[0] == '\"'){
              if (buff_check[strlen(buff_value_tmp)] == '\"'){
                json_types = SL_TEXT;
              }
              else {
                sjson_debug(__func__, SJSON_DEBUG_ERROR, "find problem for (0)");
                goto sjson_get_list_err;
              }
            }
            else {
              json_types = sjson_check_value_type(buff_value_tmp);
              if (json_types == SL_TEXT){
                sjson_debug(__func__, SJSON_DEBUG_ERROR, "find problem for (1)");
                goto sjson_get_list_err;
              }
            }
          }
          if (json_types == SL_POINTER && !strcmp(buff_value_tmp, "null")){
            shilink_fill_custom_data(
             &sjson_data,
             (void *) buff_key_tmp, 
             (uint16_t) strlen(buff_key_tmp),
             NULL,
             (uint16_t) 0,
             SL_TEXT);
          }
          else {
            shilink_fill_custom_data(
             &sjson_data,
             (void *) buff_key_tmp, 
             (uint16_t) strlen(buff_key_tmp),
             (void *) buff_value_tmp,
             (uint16_t) strlen(buff_value_tmp),
             json_types);
          }
          shilink_append(sjson_list, sjson_data);

          if (sjson_key_size != 8){
            sjson_key_size = 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          if (sjson_value_size != 8){
            sjson_value_size = 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          cnt_data++;
          cnt_switch = 0x00;
          cnt_tmp = 0;
          store_state = 0x00;
          store_numeric = 0x00;
          array_anomaly = 0x00;
          buff_check = NULL;
        }
        else if (store_state){
          if (buff_source[i] == '['){
            array_anomaly = 0x01;
          }
          else if(buff_source[i] == ']'){
            array_anomaly = 0x00;
          }
          if ((sjson_value_size - 2) == cnt_tmp){
            sjson_value_size += 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          if (!(store_numeric &&
           (buff_source[i] == 0x20 ||
            buff_source[i] == 0x2d ||
            buff_source[i] == 0x0a
           ))
          ){
            buff_value_tmp[cnt_tmp] = buff_source[i];
            cnt_tmp++;
          }
        }
        else if (!store_state &&
         (
          (buff_source[i] >= 'a' && buff_source[i] <= 'z') ||
          (buff_source[i] >= 'A' && buff_source[i] <= 'Z') ||
          (buff_source[i] >= '0' && buff_source[i] <= '9') ||
          (buff_source[i] == '-') ||
          (buff_source[i] == '+')
         )
        ){
          store_state = 0x01;
          store_numeric = 0x01;
          if ((sjson_value_size - 2) == cnt_tmp){
            sjson_value_size += 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          buff_value_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
      }
    }
    else if (buff_source[i]=='\"'){
      if (!store_state){
        store_state = 1;
      }
      else if (!array_anomaly){
        store_state = 0;
        if (buff_source[i + 1] == '\"'){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "key problem (1) after key: %s\n", buff_key_tmp);
          goto sjson_get_list_err;
        }
      }
      if (cnt_switch && cnt_tmp){
        if (buff_source[i + 1] == '\"'){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "key problem (2) after key: %s\n", buff_key_tmp);
          goto sjson_get_list_err;
        }
        buff_check = buff_source + i - cnt_tmp;
      }
    }
    else if (buff_source[i]=='{' || buff_source[i] == '}'){
      if (buff_source[i] == '}'){
        if (sjson_parrent_list[sjson_parrent_position] != SJSON_PARRENT_OBJECT){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid structure (0)");
          goto sjson_get_list_err;
        }
        sjson_parrent_list[sjson_parrent_position] = SJSON_PARRENT_NULL;
        sjson_parrent_position--;
        if (buff_source[i + 1] == '{' ||
         buff_source[i + 1] == '['
        ){
          sjson_debug(__func__, SJSON_DEBUG_ERROR, "find problem for \",\" invalid possition (0)");
          goto sjson_get_list_err;
        }
        if (cnt_tmp){
          buff_value_tmp[cnt_tmp] = 0x00;
          if (buff_check != NULL){
            json_types = SL_TEXT;
          }
          else {
            json_types = sjson_check_value_type(buff_value_tmp);
            if (json_types == SL_TEXT){
              sjson_debug(__func__, SJSON_DEBUG_ERROR, "find problem for (3)");
              goto sjson_get_list_err;
            }
          }
          if (json_types == SL_POINTER && !strcmp(buff_value_tmp, "null")){
            shilink_fill_custom_data(
             &sjson_data,
             (void *) buff_key_tmp, 
             (uint16_t) strlen(buff_key_tmp),
             NULL,
             (uint16_t) 0,
             SL_TEXT);
          }
          else {
            shilink_fill_custom_data(
             &sjson_data,
             (void *) buff_key_tmp, 
             (uint16_t) strlen(buff_key_tmp),
             (void *) buff_value_tmp,
             (uint16_t) strlen(buff_value_tmp),
             json_types);
          }
          shilink_append(sjson_list, sjson_data);

          if (sjson_key_size != 8){
            sjson_key_size = 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          if (sjson_value_size != 8){
            sjson_value_size = 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }

          cnt_data++;
          cnt_tmp = 0;
          store_state = 0x00;
          store_numeric = 0x00;
        }
      }
      else {
        if (i >= 2){
          if (!((buff_source[i - 1] == ',' && buff_source[i - 2] == '}') ||
           buff_source[i - 1] == ':' ||
           buff_source[i - 1] == '[')
          ){
            sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid structure (0.1)");
            goto sjson_get_list_err;
          }
        }
        sjson_parrent_position++;
        sjson_parrent_list[sjson_parrent_position] = SJSON_PARRENT_OBJECT;
      }
      cnt_switch = 0x00;
      buff_check = NULL;
    }
  }
  goto sjson_get_list_end;

  sjson_get_list_err:
    sjson_debug(__func__, SJSON_DEBUG_WARNING, "process stoped until:\n");
    shilink_print(*sjson_list);
    shilink_free(sjson_list);
    *sjson_list = NULL;
    cnt_data = -1;
  sjson_get_list_end:
    free(buff_key_tmp);
    free(buff_value_tmp);
    buff_key_tmp = NULL;
    buff_value_tmp = NULL;
    return cnt_data;
}

uint16_t sjson_count_data_by_key(sjsonList _sjson_list, char *_key){
  return shilink_count_data_by_key(_sjson_list, (void *)_key, (uint16_t) strlen(_key));
}

int8_t sjson_get_value_by_key_and_position(sjsonList _sjson_list, char *_key, int _pos, char* _value_result){
  if (_sjson_list == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "_sjson_list is NULL\n");
    return -1;
  }
  SHLinkCustomData sjson_data;
  if (shilink_search_data_by_position(
   _sjson_list,
   (void *) _key,
   (uint16_t) strlen(_key),
   _pos, &sjson_data) != 0){
    return -2;
    sjson_debug(__func__, SJSON_DEBUG_WARNING, "data not found\n");
  }
  strcpy(_value_result, sjson_data.sl_value);
  return 0;
}

int8_t sjson_get_value_by_key_and_prevcond(sjsonList _sjson_list, char *_prev_key, char *_prev_value, char *_key, char* _value_result){
  if (_sjson_list == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "_sjson_list is NULL\n");
    return -1;
  }
  SHLinkCustomData sjson_data, sjson_cond;
  shilink_fill_custom_data(
   &sjson_cond, 
   (void *) _prev_key,
   (uint16_t) strlen(_prev_key),
   (void *) _prev_value,
   (uint16_t) strlen(_prev_value),
   SL_TEXT);
  if (shilink_search_data_by_prev_cond(_sjson_list, (void *) _key, (uint16_t) strlen(_key), &sjson_cond, &sjson_data) != 0){
    return -2;
    sjson_debug(__func__, SJSON_DEBUG_WARNING, "data not found\n");
  }
  strcpy(_value_result, sjson_data.sl_value);
  return 0;
}

void sjson_free(sjsonList *_sjson_list){
  shilink_free(_sjson_list);
}

int8_t sjson_get_specific_data(char *buff_source, uint16_t size_of_source, char *_key, char *_data){
  uint8_t cnt_switch = 0;
  uint16_t cnt_tmp = 0;
  uint16_t sjson_key_size = 8;
  uint16_t sjson_value_size = 8;

  uint16_t i = 0;
  uint16_t start_bytes = 0;
  uint8_t store_state = 0;
  uint8_t array_anomaly = 0;

  uint8_t obj_counter = 0;
  uint8_t arr_counter = 0;

  while (buff_source[start_bytes] != '{' && buff_source[start_bytes] != '[' && buff_source[start_bytes] != 0x00){
    start_bytes++;
  }

  if (buff_source[start_bytes] == 0x00){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "invalid json format\n");
    return -1;
  }

  char *buff_key_tmp = NULL;
  buff_key_tmp = (char *) malloc(sjson_key_size * sizeof(char));
  if (buff_key_tmp == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "failed to allocate buff_key_tmp memory\n");
    return -2;
  }
  char *buff_value_tmp = NULL;
  buff_value_tmp = (char *) malloc(sjson_value_size * sizeof(char));
  if (buff_value_tmp == NULL){
    sjson_debug(__func__, SJSON_DEBUG_ERROR, "failed to allocate buff_value_tmp memory\n");
    free(buff_key_tmp);
    buff_key_tmp = NULL;
    return -2;
  }

  for (i=start_bytes; i<size_of_source; i++){
    if ((buff_source[i]!='{' && buff_source[i]!='}' && (buff_source[i]!='\"' || array_anomaly ==  1)) || i == (size_of_source-1)){
      if (cnt_switch == 0){
        if (buff_source[i] == ':' && (buff_source[i+1] == '{' || buff_source[i+1] == '[')){
          buff_key_tmp[cnt_tmp] = 0x00;
          if (buff_source[i+1] == '{'){
            sprintf(buff_value_tmp, "obj_%i", obj_counter);
            obj_counter++;
          }
          else if (buff_source[i+1] == '['){
            sprintf(buff_value_tmp, "arr_%i", arr_counter);
            arr_counter++;
          }
          if (strcmp(buff_key_tmp, _key) == 0){
            strcpy(_data, buff_value_tmp);
            free(buff_key_tmp);
            free(buff_value_tmp);
            buff_key_tmp = NULL;
            buff_value_tmp = NULL;
            return 0;
          }

          sjson_key_size = sjson_value_size = 8;
          buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          
          store_state = 0;
          cnt_switch = 0;
          cnt_tmp = 0;
        }
        else if(buff_source[i] == ':'){
          buff_key_tmp[cnt_tmp] = 0x00;
          cnt_switch = 1;
          cnt_tmp = 0;
        }
        else if (buff_source[i] != '[' && buff_source[i] != ',' && store_state == 1) {
          if ((sjson_key_size - 2) == cnt_tmp){
            sjson_key_size += 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          buff_key_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
        else if (store_state == 0 &&
         (
          (buff_source[i] >= 'a' && buff_source[i] <= 'z') ||
          (buff_source[i] >= 'A' && buff_source[i] <= 'Z') ||
          (buff_source[i] >= '0' && buff_source[i] <= '9') ||
          (buff_source[i] == '-') ||
          (buff_source[i] == '+')
         )
        ){
          store_state = 1;
          if ((sjson_key_size - 2) == cnt_tmp){
            sjson_key_size += 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          buff_key_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
      }
      else {
        if((buff_source[i] == ',' && array_anomaly == 0 && store_state == 0) ||
         (buff_source[i] == ']' && array_anomaly == 0) ||
         (buff_source[i] == '[' && store_state == 0) ||
         (buff_source[i] == '\n' && buff_source[i-1] == '{' && i > 3) ||
         i == (size_of_source-1)
        ){
          buff_value_tmp[cnt_tmp] = 0x00;
          if (buff_source[i] == '{'){
            sprintf(buff_value_tmp, "obj_%i", obj_counter);
            obj_counter++;
          }
          else if (buff_source[i] == '['){
            sprintf(buff_value_tmp, "arr_%i", arr_counter);
            arr_counter++;
          }
          if (strcmp(buff_key_tmp, _key) == 0){
            strcpy(_data, buff_value_tmp);
            free(buff_key_tmp);
            free(buff_value_tmp);
            buff_key_tmp = NULL;
            buff_value_tmp = NULL;
            return 0;
          }

          sjson_key_size = sjson_value_size = 8;
          buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          
          cnt_switch = 0;
          cnt_tmp = 0;
          store_state = 0;
          array_anomaly = 0;
        }
        else if (store_state == 1){
          if (buff_source[i] == '['){
            array_anomaly = 1;
          }
          else if(buff_source[i] == ']'){
            array_anomaly = 0;
          }
          if ((sjson_value_size - 2) == cnt_tmp){
            sjson_value_size += 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          buff_value_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
        else if (store_state == 0 &&
         (
          (buff_source[i] >= 'a' && buff_source[i] <= 'z') ||
          (buff_source[i] >= 'A' && buff_source[i] <= 'Z') ||
          (buff_source[i] >= '0' && buff_source[i] <= '9') ||
          (buff_source[i] == '-') ||
          (buff_source[i] == '+')
         )
        ){
          store_state = 1;
          if ((sjson_value_size - 2) == cnt_tmp){
            sjson_value_size += 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          buff_value_tmp[cnt_tmp] = buff_source[i];
          cnt_tmp++;
        }
      }
    }
    else if (buff_source[i]=='\"'){
      if (store_state == 0){
        store_state = 1;
      }
      else if (array_anomaly == 0){
        store_state = 0;
      }
    }
    else if (buff_source[i]=='{' || buff_source[i] == '}'){
      if (buff_source[i] == '}'){
        if (cnt_tmp > 0){
          buff_value_tmp[cnt_tmp] = 0x00;

          if (strcmp(buff_key_tmp, _key) == 0){
            strcpy(_data, buff_value_tmp);
            free(buff_key_tmp);
            free(buff_value_tmp);
            buff_key_tmp = NULL;
            buff_value_tmp = NULL;
            return 0;
          }

          if (sjson_key_size != 8){
            sjson_key_size = 8;
            buff_key_tmp = (char *) realloc(buff_key_tmp, sjson_key_size * sizeof(char));
          }
          if (sjson_value_size != 8){
            sjson_value_size = 8;
            buff_value_tmp = (char *) realloc(buff_value_tmp, sjson_value_size * sizeof(char));
          }
          cnt_tmp = 0;
        }
      }
      cnt_switch = 0;
    }
  }
  sjson_debug(__func__, SJSON_DEBUG_WARNING, "not found match key\n");
  free(buff_key_tmp);
  free(buff_value_tmp);
  buff_key_tmp = NULL;
  buff_value_tmp = NULL;
  return -3;
}