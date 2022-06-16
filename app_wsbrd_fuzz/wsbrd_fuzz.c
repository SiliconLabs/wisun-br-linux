#include "app_wsbrd/libwsbrd.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"

struct fuzz_ctxt g_fuzz_ctxt = { };

int main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
