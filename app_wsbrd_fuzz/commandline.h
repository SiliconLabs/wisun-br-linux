#ifndef FUZZ_COMMANDLINE_H
#define FUZZ_COMMANDLINE_H

struct fuzz_ctxt;

int fuzz_parse_commandline(struct fuzz_ctxt *ctxt, char **argv);

#endif
