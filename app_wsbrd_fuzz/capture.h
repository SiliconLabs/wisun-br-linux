#ifndef FUZZ_CAPTURE_H
#define FUZZ_CAPTURE_H

#include <stddef.h>

struct fuzz_ctxt;

void fuzz_capture(struct fuzz_ctxt *ctxt, const void *data, size_t size);
void fuzz_capture_timers(struct fuzz_ctxt *ctxt);
void fuzz_capture_interface(struct fuzz_ctxt *ctxt, uint8_t interface, const void *data, size_t size);

#endif
