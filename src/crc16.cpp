#include "tlm/crc16.hpp"

namespace tlm {

std::uint16_t crc16(std::span<const std::uint8_t> data) {
    std::uint16_t crc = 0xFFFF;
    for (std::uint8_t byte : data) {
        // Bring the next byte into the top of the register, then process its
        // 8 bits one at a time: shift left, and whenever a 1 falls off the top,
        // XOR in the polynomial. (A lookup table is faster; this loop is the
        // same math, written so each step is visible.)
        crc = static_cast<std::uint16_t>(crc ^ (byte << 8));
        for (int bit = 0; bit < 8; ++bit) {
            const bool top_bit_set = (crc & 0x8000) != 0;
            crc = static_cast<std::uint16_t>(crc << 1);
            if (top_bit_set) {
                crc = static_cast<std::uint16_t>(crc ^ 0x1021);
            }
        }
    }
    return crc;
}

}  // namespace tlm
