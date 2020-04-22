/*
    lib info    : SHIKI_LIB_GROUP - JSON TOOLS
    ver         : 2.00.20.04.22
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

#define SJSON_VERSION "2.00.20.04.22"

int8_t json_debug_mode_status = 0;

static void sjson_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (json_debug_mode_status == 1){
    struct tm *d_tm;
    struct timeval tm_debug;
    uint16_t msec = 0;
    va_list aptr;

    gettimeofday(&tm_debug, NULL);
    d_tm = localtime(&tm_debug.tv_sec);
    msec = tm_debug.tv_usec/1000;

    char* tmp_debug_msg;
    tmp_debug_msg = (char *) malloc(256*sizeof(char));
    if (tmp_debug_msg == NULL){
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03i ERROR: %s: failed to allocate debug variable memory",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, msec, __func__
      );
      return;
    }
	  va_start(aptr, debug_msg);
	  vsprintf(tmp_debug_msg, debug_msg, aptr);
	  va_end(aptr);
    #ifdef __linux__
      if (strcmp(debug_type, "INFO")==0)
        printf("\033[1;32m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m SJSON\033[1;32m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
         msec, debug_type, function_name, tmp_debug_msg
        );
      else if (strcmp(debug_type, "WARNING")==0)
        printf("\033[1;33m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m SJSON\033[1;33m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
         msec, debug_type, function_name, tmp_debug_msg
        );
      else if (strcmp(debug_type, "ERROR")==0)
        printf("\033[1;31m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m SJSON\033[1;31m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
         msec, debug_type, function_name, tmp_debug_msg
        );
      else if (strcmp(debug_type, "CRITICAL")==0)
        printf("\033[1;31m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m SJSON\033[1;31m %s: %s: %s\033[0m",
         d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
         msec, debug_type, function_name, tmp_debug_msg
        );
    #else
      printf("%02d-%02d-%04d %02d:%02d:%02d.%03d %s: %s: %s",
       d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
       msec, debug_type, function_name, tmp_debug_msg
      );
    #endif
    free(tmp_debug_msg);
    tmp_debug_msg = NULL;
  }
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
    sjson_debug(__func__, "VERSION", "%s\n", SJSON_VERSION);
}

int8_t sjson_get_list(sjsonList *sjson_list, char *buff_source, uint16_t size_of_source){
  uint8_t cnt_data = 0;
  uint8_t cnt_switch = 0;
  uint16_t cnt_tmp = 0;
  uint16_t sjson_key_size = 8;
  uint16_t sjson_value_size = 8;
  SHLinkCustomData sjson_data;

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
    sjson_debug(__func__, "ERROR", "invalid json format\n");
    return -1;
  }

  char *buff_key_tmp = NULL;
  buff_key_tmp = (char *) malloc(sjson_key_size * sizeof(char));
  if (buff_key_tmp == NULL){
    sjson_debug(__func__, "ERROR", "failed to allocate buff_key_tmp memory\n");
    return -2;
  }
  char *buff_value_tmp = NULL;
  buff_value_tmp = (char *) malloc(sjson_value_size * sizeof(char));
  if (buff_value_tmp == NULL){
    sjson_debug(__func__, "ERROR", "failed to allocate buff_value_tmp memory\n");
    free(buff_key_tmp);
    buff_key_tmp = NULL;
    return -2;
  }

  for (i=start_bytes; i<size_of_source; i++){
    if ((buff_source[i]!='{' && buff_source[i]!='}' && (buff_source[i]!='\"' || array_anomaly ==  1)) || i == (size_of_source-1)){
      if (cnt_switch == 0){
        if (buff_source[i] == ':' && (buff_source[i+1] == '{' || buff_source[i+1] == '[')){
          if (cnt_tmp > 0){
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
            shilink_fill_custom_data(&sjson_data, buff_key_tmp, buff_value_tmp, SL_TEXT);
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
          (buff_source[i] >= '0' && buff_source[i] <= '9')
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
        if(buff_source[i] == ',' ||
         (buff_source[i] == ']' && array_anomaly == 0) ||
         (buff_source[i] == '[' && store_state == 0) ||
         (buff_source[i] == '\n' && buff_source[i-1] == '{' && i > 3) ||
         i == (size_of_source-1)
        ){
          if (strlen(buff_key_tmp) > 0){
            buff_value_tmp[cnt_tmp] = 0x00;
            if (buff_source[i] == '{'){
              sprintf(buff_value_tmp, "obj_%i", obj_counter);
              obj_counter++;
            }
            else if (buff_source[i] == '['){
              sprintf(buff_value_tmp, "arr_%i", arr_counter);
              arr_counter++;
            }
            shilink_fill_custom_data(&sjson_data, buff_key_tmp, buff_value_tmp, SL_TEXT);
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
          (buff_source[i] >= '0' && buff_source[i] <= '9')
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

          shilink_fill_custom_data(&sjson_data, buff_key_tmp, buff_value_tmp, SL_TEXT);
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
        }
      }
      cnt_switch = 0;
    }
  }
  sjson_debug(__func__, "INFO", "find %d data\n", cnt_data);
  free(buff_key_tmp);
  free(buff_value_tmp);
  buff_key_tmp = NULL;
  buff_value_tmp = NULL;
  return cnt_data;
}

uint16_t sjson_count_data_by_key(sjsonList _sjson_list, char *_key){
  return shilink_count_data_by_key(_sjson_list, _key);
}

int8_t sjson_get_value_by_key_and_position(sjsonList _sjson_list, char *_key, int _pos, char* _value_result){
  if (_sjson_list == NULL){
    sjson_debug(__func__, "ERROR", "_sjson_list is NULL\n");
    return -1;
  }
  SHLinkCustomData sjson_data;
  if (shilink_search_data_by_position(_sjson_list, _key, _pos, &sjson_data) != 0){
    return -2;
    sjson_debug(__func__, "WARNING", "data not found\n");
  }
  strcpy(_value_result, sjson_data.sl_value);
  return 0;
}

int8_t sjson_get_value_by_key_and_prevcond(sjsonList _sjson_list, char *_prev_key, char *_prev_value, char *_key, char* _value_result){
  if (_sjson_list == NULL){
    sjson_debug(__func__, "ERROR", "_sjson_list is NULL\n");
    return -1;
  }
  SHLinkCustomData sjson_data, sjson_cond;
  shilink_fill_custom_data(&sjson_cond, _prev_key, _prev_value, SL_TEXT);
  if (shilink_search_data_by_prev_cond(_sjson_list, _key, &sjson_cond, &sjson_data) != 0){
    return -2;
    sjson_debug(__func__, "WARNING", "data not found\n");
  }
  strcpy(_value_result, sjson_data.sl_value);
  return 0;
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
    sjson_debug(__func__, "ERROR", "invalid json format\n");
    return -1;
  }

  char *buff_key_tmp = NULL;
  buff_key_tmp = (char *) malloc(sjson_key_size * sizeof(char));
  if (buff_key_tmp == NULL){
    sjson_debug(__func__, "ERROR", "failed to allocate buff_key_tmp memory\n");
    return -2;
  }
  char *buff_value_tmp = NULL;
  buff_value_tmp = (char *) malloc(sjson_value_size * sizeof(char));
  if (buff_value_tmp == NULL){
    sjson_debug(__func__, "ERROR", "failed to allocate buff_value_tmp memory\n");
    free(buff_key_tmp);
    buff_key_tmp = NULL;
    return -2;
  }

  for (i=start_bytes; i<size_of_source; i++){
    if ((buff_source[i]!='{' && buff_source[i]!='}' && (buff_source[i]!='\"' || array_anomaly ==  1)) || i == (size_of_source-1)){
      if (cnt_switch == 0){
        if (buff_source[i] == ':' && (buff_source[i+1] == '{' || buff_source[i+1] == '[')){
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
          (buff_source[i] >= '0' && buff_source[i] <= '9')
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
        if(buff_source[i] == ',' ||
         (buff_source[i] == ']' && array_anomaly == 0) ||
         (buff_source[i] == '[' && store_state == 0) ||
         (buff_source[i] == '\n' && buff_source[i-1] == '{' && i > 3) ||
         i == (size_of_source-1)
        ){
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
          (buff_source[i] >= '0' && buff_source[i] <= '9')
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
  sjson_debug(__func__, "WARNING", "not found match key\n");
  free(buff_key_tmp);
  free(buff_value_tmp);
  buff_key_tmp = NULL;
  buff_value_tmp = NULL;
  return -3;
}