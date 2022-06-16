#include <stdio.h>

#include "app_wsbrd/commandline.h"

void __real_print_help_br(FILE *stream);
void __wrap_print_help_br(FILE *stream)
{
    __real_print_help_br(stream);
    fprintf(stream, "\n");
    fprintf(stream, "Extra options:\n");
    fprintf(stream, "  --capture=FILE        Record raw data received on UART and TUN interfaces, and save it to\n");
    fprintf(stream, "                          FILE. Also write additional timer information for replay.\n");
    fprintf(stream, "  --replay=FILE         Replay a sequence captured using --capture\n");
}
