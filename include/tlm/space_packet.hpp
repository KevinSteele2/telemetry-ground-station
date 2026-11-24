#pragma once

// CCSDS Space Packets: the packet format spacecraft use for telemetry
// (spacecraft -> ground) and telecommands (ground -> spacecraft).
//
// Every packet starts with a 6-byte primary header, big-endian:
//
//   bits  field                 meaning
//   3     version               always 0
//   1     type                  0 = telemetry, 1 = telecommand
//   1     secondary header flag 1 if a secondary header follows (unused here)
//   11    APID                  which application/subsystem the packet belongs to
//   2     sequence flags        0b11 = unsegmented (the whole message in one packet)
//   14    sequence count        counts up per APID, wraps at 16383; gaps = lost packets
//   16    data length           bytes in the data field MINUS ONE
//
// The data field is our payload followed by a 2-byte CRC over everything
// before it, so the ground can tell a corrupted packet from a good one.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace tlm {

enum class PacketType : std::uint8_t { Telemetry = 0, Telecommand = 1 };

constexpr std::size_t kHeaderSize = 6;
constexpr std::size_t kCrcSize = 2;
constexpr std::uint8_t kMaxVersion = 0x7;          // 3 bits
constexpr std::uint16_t kMaxApid = 0x7FF;          // 11 bits
constexpr std::uint16_t kMaxSequenceCount = 0x3FFF;  // 14 bits
constexpr std::uint8_t kUnsegmented = 0b11;
// The data field (payload + CRC) holds at most 65536 bytes, since the length
// field stores size - 1 in 16 bits.
constexpr std::size_t kMaxPayloadSize = 65536 - kCrcSize;

struct PrimaryHeader {
    std::uint8_t version = 0;
    PacketType type = PacketType::Telemetry;
    bool secondary_header = false;
    std::uint16_t apid = 0;
    std::uint8_t sequence_flags = kUnsegmented;
    std::uint16_t sequence_count = 0;
    std::uint16_t data_length = 0;  // data field size minus one

    bool operator==(const PrimaryHeader&) const = default;
};

struct Packet {
    PrimaryHeader header;
    std::vector<std::uint8_t> payload;  // without the CRC
};

// Packs the fields into 6 bytes. Throws std::invalid_argument if a field is
// too big for its bits: that's a bug in the caller, not bad data.
std::array<std::uint8_t, kHeaderSize> encode_header(const PrimaryHeader& header);

// Unpacks 6 bytes into fields. Needs at least kHeaderSize bytes (throws
// std::invalid_argument otherwise); any 6 bytes decode to some header.
PrimaryHeader decode_header(std::span<const std::uint8_t> bytes);

// Builds a complete packet: header, payload, CRC. Fills in data_length.
std::vector<std::uint8_t> encode_packet(PacketType type, std::uint16_t apid,
                                        std::uint16_t sequence_count,
                                        std::span<const std::uint8_t> payload);

// Why a packet was rejected. Bad packets are expected (they arrive over a
// lossy link), so decoding reports them instead of throwing.
enum class DecodeStatus {
    Ok,
    TooShort,        // not even a header plus a CRC
    BadVersion,      // version field isn't 0: not a packet we understand
    LengthMismatch,  // the length field disagrees with the bytes received
    BadCrc,          // contents changed in transit
};

struct DecodeResult {
    DecodeStatus status;
    Packet packet;  // only meaningful when status == DecodeStatus::Ok
};

// Checks and unpacks one whole packet (one UDP datagram = one packet).
DecodeResult decode_packet(std::span<const std::uint8_t> bytes);

}  // namespace tlm
