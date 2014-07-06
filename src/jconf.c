#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "jconf.h"
#include "json.h"
#include "string.h"

static char *to_string(const json_value *value)
{
    if (value->type == json_string)
    {
        return ss_strndup(value->u.string.ptr, value->u.string.length);
    }
    else if (value->type == json_integer)
    {
#ifdef __MINGW32__
        return strdup(ss_itoa(value->u.integer));
#else
        return strdup(itoa(value->u.integer));
#endif
    }
    else if (value->type == json_null)
    {
        return "null";
    }
    else
    {
        LOGE("%d", value->type);
        FATAL("Invalid config format.");
    }
    return 0;
}

jconf_t *read_jconf(const char* file)
{

    static jconf_t conf;

    char *buf;
    json_value *obj;

    FILE *f = fopen(file, "r");
    if (f == NULL) FATAL("Invalid config path.");

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (pos >= MAX_CONF_SIZE) FATAL("Too large config file.");

    buf = malloc(pos + 1);
    if (buf == NULL) FATAL("No enough memory.");

    fread(buf, pos, 1, f);
    fclose(f);

    buf[pos] = '\0'; // end of string

    json_settings settings = { 0 };
    char error_buf[512];
    obj = json_parse_ex(&settings, buf, pos, error_buf);

    if (obj == NULL)
    {
        FATAL(error_buf);
    }

    if (obj->type == json_object)
    {
        int i, j;
        for (i = 0; i < obj->u.object.length; i++)
        {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "fake_dns_addr") == 0)
            {
                if (value->type == json_array)
                {
                    for (j = 0; j < value->u.array.length; j++)
                    {
                        if (j >= MAX_FAKE_ADDR_NUM) break;
                        json_value *v = value->u.array.values[j];
                        conf.fake_dns_addr[j] = to_string(v);
                        conf.fake_addr_num = j + 1;
                    }
                } else {
                    break;
                }
            }
            else if (strcmp(name, "udp_dns_server") == 0)
            {
                conf.udp_dns_server = to_string(value);
            }
            else if (strcmp(name, "tcp_dns_server") == 0)
            {
                conf.tcp_dns_server = to_string(value);
            }
        }
    }
    else
    {
        FATAL("Invalid config file");
    }

    free(buf);
    json_value_free(obj);
    return &conf;

}
