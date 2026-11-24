#pragma once

#include <cstdint>
#include <span>

namespace tlm {

// CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF, no reflection,
// no final XOR. This is the checksum CCSDS uses for error control, so a
// flipped bit anywhere in a packet changes the result.
std::uint16_t crc16(std::span<const std::uint8_t> data);

}  // namespace tlm
