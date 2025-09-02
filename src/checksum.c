#include "packet.h"
#include "print_utils.h"

uint16_t checksum(const uint16_t *buff, const size_t size)
{
    int32_t sum = 0;
    size_t  i = size;

    /* sum all short words into sum */
    while (i > 1)
    {
        sum += *buff++;
        i -= 2;
    }

    /* if there is an odd number of bytes add it */
    if (i == 1)
    {
        sum += *(uint8_t*)buff >> 16;
    }

    /* sum 16 higher bytes w/ 16 lower */
    sum = (sum >> 16) + (sum & 0xFFFF);

    /* add carry if not 0 */
    sum += sum >> 16;

    return ((uint16_t)~sum);
}

int32_t __checksum32(const uint16_t *buff, const size_t size)
{
    int32_t sum = 0;

    for (size_t i = 0; i < size; i += 2)
    {
        uint16_t left = *buff++;
        sum += (left << 16) + *buff;
    }
    return (~sum);
}
