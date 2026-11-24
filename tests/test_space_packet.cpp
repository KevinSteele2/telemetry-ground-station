#include <gtest/gtest.h>

#include <array>
#include <stdexcept>
#include <vector>

#include "tlm/space_packet.hpp"

namespace {

using tlm::DecodeStatus;
using tlm::PacketType;
using tlm::PrimaryHeader;

// ---------- Header bit layout ----------

// Worked by hand from the field table in space_packet.hpp:
//   APID 0x123 = 001 0010 0011 -> top 3 bits (001) end byte 0, low 8 (0x23) are byte 1
//   flags 0b11 + count 5       -> 11 000000 | 00000101 = 0xC0 0x05
//   data length 9              -> 0x00 0x09
TEST(Header, EncodesKnownBytes) {
    PrimaryHeader h;
    h.apid = 0x123;
    h.sequence_count = 5;
    h.data_length = 9;
    const std::array<std::uint8_t, 6> expected{0x01, 0x23, 0xC0, 0x05, 0x00, 0x09};
    EXPECT_EQ(tlm::encode_header(h), expected);
}

TEST(Header, TelecommandSetsTheTypeBit) {
    PrimaryHeader h;
    h.type = PacketType::Telecommand;
    EXPECT_EQ(tlm::encode_header(h)[0], 0x10);  // 000 1 0 000
}

TEST(Header, SecondaryHeaderFlagIsBit3) {
    PrimaryHeader h;
    h.secondary_header = true;
    EXPECT_EQ(tlm::encode_header(h)[0], 0x08);  // 000 0 1 000
}

// Maximum values fill every bit of their fields, so a wrong shift or mask
// would bleed into a neighbor and break the round trip.
TEST(Header, RoundTripsMaximumValues) {
    PrimaryHeader h;
    h.version = tlm::kMaxVersion;
    h.type = PacketType::Telecommand;
    h.secondary_header = true;
    h.apid = tlm::kMaxApid;
    h.sequence_flags = 0b11;
    h.sequence_count = tlm::kMaxSequenceCount;
    h.data_length = 0xFFFF;
    const auto bytes = tlm::encode_header(h);
    EXPECT_EQ(tlm::decode_header(bytes), h);
}

TEST(Header, RoundTripsAllZeros) {
    PrimaryHeader h;
    h.sequence_flags = 0;
    EXPECT_EQ(tlm::decode_header(tlm::encode_header(h)), h);
}

TEST(Header, RejectsFieldsTooBigForTheirBits) {
    PrimaryHeader apid;
    apid.apid = tlm::kMaxApid + 1;
    EXPECT_THROW(tlm::encode_header(apid), std::invalid_argument);

    PrimaryHeader count;
    count.sequence_count = tlm::kMaxSequenceCount + 1;
    EXPECT_THROW(tlm::encode_header(count), std::invalid_argument);

    PrimaryHeader version;
    version.version = tlm::kMaxVersion + 1;
    EXPECT_THROW(tlm::encode_header(version), std::invalid_argument);

    PrimaryHeader flags;
    flags.sequence_flags = 0b100;
    EXPECT_THROW(tlm::encode_header(flags), std::invalid_argument);
}

TEST(Header, DecodeNeedsSixBytes) {
    const std::array<std::uint8_t, 5> short_bytes{};
    EXPECT_THROW(tlm::decode_header(short_bytes), std::invalid_argument);
}

// ---------- Whole packets ----------

const std::vector<std::uint8_t> kPayload{0xDE, 0xAD, 0xBE, 0xEF};

TEST(Packet, RoundTripsPayloadAndHeader) {
    const auto bytes = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    ASSERT_EQ(bytes.size(), tlm::kHeaderSize + kPayload.size() + tlm::kCrcSize);

    const auto result = tlm::decode_packet(bytes);
    ASSERT_EQ(result.status, DecodeStatus::Ok);
    EXPECT_EQ(result.packet.payload, kPayload);
    EXPECT_EQ(result.packet.header.apid, 0x42);
    EXPECT_EQ(result.packet.header.sequence_count, 7);
    EXPECT_EQ(result.packet.header.type, PacketType::Telemetry);
    EXPECT_EQ(result.packet.header.sequence_flags, tlm::kUnsegmented);
}

TEST(Packet, DataLengthIsPayloadPlusCrcMinusOne) {
    const auto bytes = tlm::encode_packet(PacketType::Telemetry, 1, 0, kPayload);
    EXPECT_EQ(tlm::decode_header(bytes).data_length, kPayload.size() + tlm::kCrcSize - 1);
}

TEST(Packet, EmptyPayloadStillCarriesACrc) {
    const auto bytes = tlm::encode_packet(PacketType::Telecommand, 1, 0, {});
    ASSERT_EQ(bytes.size(), tlm::kHeaderSize + tlm::kCrcSize);
    const auto result = tlm::decode_packet(bytes);
    ASSERT_EQ(result.status, DecodeStatus::Ok);
    EXPECT_TRUE(result.packet.payload.empty());
}

TEST(Packet, RejectsOversizedPayload) {
    const std::vector<std::uint8_t> huge(tlm::kMaxPayloadSize + 1);
    EXPECT_THROW(tlm::encode_packet(PacketType::Telemetry, 1, 0, huge), std::invalid_argument);
}

TEST(Packet, LargestPayloadFits) {
    const std::vector<std::uint8_t> largest(tlm::kMaxPayloadSize, 0xAB);
    const auto bytes = tlm::encode_packet(PacketType::Telemetry, 1, 0, largest);
    EXPECT_EQ(tlm::decode_header(bytes).data_length, 0xFFFF);
    EXPECT_EQ(tlm::decode_packet(bytes).status, DecodeStatus::Ok);
}

// ---------- What the ground station will see on a lossy link ----------

// Flip each bit of the payload and CRC in turn: every one must be caught.
// (Header bits are covered below: flipping one there can change the version
// or length first, which is reported as that error instead.)
TEST(Corruption, EverySingleBitFlipAfterTheHeaderIsCaught) {
    const auto good = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    for (std::size_t byte = tlm::kHeaderSize; byte < good.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            auto bad = good;
            bad[byte] = static_cast<std::uint8_t>(bad[byte] ^ (1 << bit));
            EXPECT_EQ(tlm::decode_packet(bad).status, DecodeStatus::BadCrc)
                << "byte " << byte << " bit " << bit;
        }
    }
}

TEST(Corruption, FlippedApidBitIsCaughtByTheCrc) {
    auto bad = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    bad[1] ^= 0x01;  // APID 0x42 -> 0x43: still a valid-looking header
    EXPECT_EQ(tlm::decode_packet(bad).status, DecodeStatus::BadCrc);
}

TEST(Corruption, TruncatedPacketIsALengthMismatch) {
    auto bad = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    bad.pop_back();
    EXPECT_EQ(tlm::decode_packet(bad).status, DecodeStatus::LengthMismatch);
}

TEST(Corruption, ExtraTrailingBytesAreALengthMismatch) {
    auto bad = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    bad.push_back(0x00);
    EXPECT_EQ(tlm::decode_packet(bad).status, DecodeStatus::LengthMismatch);
}

TEST(Corruption, NonZeroVersionIsRejected) {
    auto bad = tlm::encode_packet(PacketType::Telemetry, 0x42, 7, kPayload);
    bad[0] |= 0x20;  // version 1
    EXPECT_EQ(tlm::decode_packet(bad).status, DecodeStatus::BadVersion);
}

TEST(Corruption, FewerBytesThanAHeaderAndCrcIsTooShort) {
    const std::vector<std::uint8_t> tiny{0x00, 0x01, 0xC0};
    EXPECT_EQ(tlm::decode_packet(tiny).status, DecodeStatus::TooShort);
    EXPECT_EQ(tlm::decode_packet({}).status, DecodeStatus::TooShort);
}

}  // namespace
