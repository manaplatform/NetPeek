#include <stdio.h>
#include "version.h"

void cmd_version(void)
{
    printf("NetPeek %s\n", NETPEEK_VERSION_STRING);
}