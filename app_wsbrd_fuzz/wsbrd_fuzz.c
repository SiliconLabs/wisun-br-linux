#include "app_wsbrd/libwsbrd.h"
#include "commandline.h"

int main(int argc, char *argv[])
{
    argc = fuzz_parse_commandline(argv);
    return wsbr_main(argc, argv);
}
