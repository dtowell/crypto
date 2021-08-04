#include <iostream>
#include <vector>
#include <cstddef>

#ifndef _CRYPTO_H
#define _CRYPTO_H

namespace crypto {
    using buffer_t = std::vector<uint8_t>;

    // put crypto functions/types here
};

std::ostream & operator<<(std::ostream &out,const crypto::buffer_t &buffer);

#endif
