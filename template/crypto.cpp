#include "crypto.h"
#include <iomanip>

// NOTICE: there is NOT using namespace std here on purpose

std::ostream & operator<<(std::ostream &out,const crypto::buffer_t &buffer) {
    for (size_t i=0; i<buffer.size(); i++) {
        if (i%16 == 0)
            out << std::setw(4) << std::setfill(' ') << std::hex << i << ":";
        out << " " << std::setw(2) << std::setfill('0') << std::hex << +buffer[i];
        if (i%16 == 15)
            out << "\n";
    }
    if (buffer.size()%16)
        out << "\n";
    return out;
}

namespace crypto {

    // put crypto functions here

};
