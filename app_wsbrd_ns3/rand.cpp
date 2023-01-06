#include <sys/types.h>

#include <ns3/random-variable-stream.h>

extern "C" ssize_t __wrap_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    static ns3::Ptr<ns3::UniformRandomVariable> rand_source =
        ns3::CreateObject<ns3::UniformRandomVariable>();

    for (size_t i = 0; i < buflen; i++)
        ((uint8_t *)buf)[i] = rand_source->GetInteger(0, 255);

    return buflen;
}
