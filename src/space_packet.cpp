#include "tlm/space_packet.hpp"

#include <stdexcept>
#include <string>

#include "tlm/crc16.hpp"

namespace tlm {

namespace {

std::uint8_t u8(unsigned value) { return static_cast<std::uint8_t>(value & 0xFF); }

void check_range(const char* field, unsigned value, unsigned max) {
    if (value > max) {
        throw std::invalid_argument(std::string(field) + " " + std::to_string(value) +
                                    " doesn't fit (max " + std::to_string(max) + ")");
    }
}

}  // namespace

std::array<std::uint8_t, kHeaderSize> encode_header(const PrimaryHeader& h) {
    // Range checks first: without them, an APID of 0x800 would silently spill
    // into the neighboring bits and corrupt the type and version fields.
    check_range("version", h.version, kMaxVersion);
    check_range("apid", h.apid, kMaxApid);
    check_range("sequence_flags", h.sequence_flags, 0b11);
    check_range("sequence_count", h.sequence_count, kMaxSequenceCount);

    const unsigned type = static_cast<unsigned>(h.type);
    const unsigned secondary = h.secondary_header ? 1u : 0u;

    // Each field is shifted to its bit position and OR'd in. Big-endian
    // ("network byte order"): the most significant byte goes first.
    return {
        // version (3) | type (1) | secondary header flag (1) | top 3 bits of APID
        u8((unsigned{h.version} << 5) | (type << 4) | (secondary << 3) | (unsigned{h.apid} >> 8)),
        u8(h.apid),  // low 8 bits of APID
        // sequence flags (2) | top 6 bits of the sequence count
        u8((unsigned{h.sequence_flags} << 6) | (unsigned{h.sequence_count} >> 8)),
        u8(h.sequence_count),  // low 8 bits of the sequence count
        u8(unsigned{h.data_length} >> 8),
        u8(h.data_length),
    };
}

PrimaryHeader decode_header(std::span<const std::uint8_t> b) {
    if (b.size() < kHeaderSize) {
        throw std::invalid_argument("a header needs 6 bytes, got " + std::to_string(b.size()));
    }
    // The reverse of encode_header: shift each field down and mask off its
    // neighbors (0x07 keeps 3 bits, 0x3F keeps 6).
    PrimaryHeader h;
    h.version = u8(b[0] >> 5);
    h.type = static_cast<PacketType>((b[0] >> 4) & 0x1);
    h.secondary_header = ((b[0] >> 3) & 0x1) != 0;
    h.apid = static_cast<std::uint16_t>(((b[0] & 0x07) << 8) | b[1]);
    h.sequence_flags = u8(b[2] >> 6);
    h.sequence_count = static_cast<std::uint16_t>(((b[2] & 0x3F) << 8) | b[3]);
    h.data_length = static_cast<std::uint16_t>((b[4] << 8) | b[5]);
    return h;
}

std::vector<std::uint8_t> encode_packet(PacketType type, std::uint16_t apid,
                                        std::uint16_t sequence_count,
                                        std::span<const std::uint8_t> payload) {
    if (payload.size() > kMaxPayloadSize) {
        throw std::invalid_argument("payload of " + std::to_string(payload.size()) +
                                    " bytes is too large (max " +
                                    std::to_string(kMaxPayloadSize) + ")");
    }
    PrimaryHeader h;
    h.type = type;
    h.apid = apid;
    h.sequence_count = sequence_count;
    // The data field is payload + CRC, and the field stores its size minus
    // one (so a 1-byte data field is 0 and the full 16 bits are usable).
    h.data_length = static_cast<std::uint16_t>(payload.size() + kCrcSize - 1);

    const auto header = encode_header(h);
    std::vector<std::uint8_t> out(header.begin(), header.end());
    out.insert(out.end(), payload.begin(), payload.end());

    // The CRC covers the header too, so a flipped bit in the APID or the
    // length is caught just like one in the payload.
    const std::uint16_t crc = crc16(out);
    out.push_back(u8(crc >> 8));
    out.push_back(u8(crc));
    return out;
}

DecodeResult decode_packet(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kHeaderSize + kCrcSize) {
        return {DecodeStatus::TooShort, {}};
    }
    const PrimaryHeader h = decode_header(bytes);
    if (h.version != 0) {
        return {DecodeStatus::BadVersion, {}};
    }
    // One datagram should hold exactly one packet. If the length field says
    // otherwise, either bytes were lost/added or the length itself was
    // corrupted; either way, nothing after the header can be trusted.
    if (bytes.size() != kHeaderSize + std::size_t{h.data_length} + 1) {
        return {DecodeStatus::LengthMismatch, {}};
    }
    const std::size_t crc_at = bytes.size() - kCrcSize;
    const std::uint16_t received = static_cast<std::uint16_t>((bytes[crc_at] << 8) | bytes[crc_at + 1]);
    if (crc16(bytes.first(crc_at)) != received) {
        return {DecodeStatus::BadCrc, {}};
    }
    Packet packet{h, std::vector<std::uint8_t>(bytes.begin() + kHeaderSize, bytes.begin() + crc_at)};
    return {DecodeStatus::Ok, std::move(packet)};
}

}  // namespace tlm
