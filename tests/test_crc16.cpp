#include <gtest/gtest.h>

#include <string_view>
#include <vector>

#include "tlm/crc16.hpp"

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) { return {s.begin(), s.end()}; }

// Every published CRC variant lists a "check value": its CRC of the ASCII
// string "123456789". Matching it proves we implemented the same variant
// CCSDS specifies, not just something internally consistent.
TEST(Crc16, MatchesPublishedCheckValue) {
    EXPECT_EQ(tlm::crc16(bytes_of("123456789")), 0x29B1);
}

TEST(Crc16, EmptyInputIsTheInitialValue) {
    EXPECT_EQ(tlm::crc16({}), 0xFFFF);
}

TEST(Crc16, SingleFlippedBitChangesTheResult) {
    auto data = bytes_of("telemetry");
    const auto original = tlm::crc16(data);
    data[3] ^= 0x01;
    EXPECT_NE(tlm::crc16(data), original);
}

}  // namespace
