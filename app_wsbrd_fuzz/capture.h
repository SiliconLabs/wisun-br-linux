#ifndef FUZZ_CAPTURE_H
#define FUZZ_CAPTURE_H

struct fuzz_ctxt;

void fuzz_capture(struct fuzz_ctxt *ctxt, const void *data, size_t size);
void fuzz_capture_timers(struct fuzz_ctxt *ctxt);

#endif
