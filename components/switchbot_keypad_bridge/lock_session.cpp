#include "lock_session.h"

#include <cstring>

#include <esp_random.h>

#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "aes_ctr.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.session";

// Encrypted protocol framing.
constexpr uint8_t PROTOCOL_MAGIC = 0x57;

// Session IV negotiation. Most keypads send this after connect; some reconnect
// and continue with the IV they already have.
// Shape: 57 00 00 00 0F 21 03 <key_id>
constexpr size_t SESSION_IV_REQ_MIN = 8;

constexpr size_t IV_RESPONSE_HEADER = 4;  // iv_response_ prefix before the IV bytes

}  // namespace

void LockSession::reset() {
  for (auto &generation : this->generations_) {
    generation = CryptoContext{};
  }
  this->serial_counter_ = 0;
  this->reset_transport();
}

void LockSession::reset_transport() {
  this->plaintext_size_ = 0;
  this->header_ = FrameHeader{};
  this->command_ = DecodedCommand{};
  this->response_iv_valid_ = false;
}

LockSession::Action LockSession::process_frame(const std::string &frame) {
  // Never expose stale decoded bytes or a stale response IV after a dropped
  // frame. The bridge may relay plaintext asynchronously after COMMAND.
  this->reset_transport();

  ESP_LOGV(TAG, "RX WIRE %zu bytes: %s", frame.size(),
           format_hex_pretty(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()).c_str());

  if (this->is_iv_request_(frame)) {
    // The IV request advertises which key_id the keypad will use for the
    // rest of the session (`57 00 00 00 0F 21 03 <key_id>`). Adapt to it —
    // Original/Touch uses 0x88, Vision/Vision Pro uses 0xC6.
    const uint8_t requested_slot = static_cast<uint8_t>(frame[7]);
    if (requested_slot != this->slot_id_) {
      ESP_LOGI(TAG, "Token slot: 0x%02X", requested_slot);
      this->slot_id_ = requested_slot;
    }
    ESP_LOGD(TAG, "IV request");
    // Add a generation instead of replacing one. Vision-family keypads can
    // renegotiate several times in a row and still finish frames from an
    // earlier generation afterwards.
    this->negotiate_new_iv_();
    return Action::SEND_IV;
  }

  if (frame.size() <= HEADER_LEN ||
      static_cast<uint8_t>(frame[0]) != PROTOCOL_MAGIC) {
    ESP_LOGD(TAG, "Ignoring non-protocol frame (size=%zu)", frame.size());
    return Action::NONE;
  }

  this->header_ = FrameHeader{static_cast<uint8_t>(frame[1]), static_cast<uint8_t>(frame[2]),
                              static_cast<uint8_t>(frame[3])};

  if (this->header_.key_id != this->slot_id_) {
    ESP_LOGD(TAG, "Ignoring frame with unexpected key_id=0x%02X", this->header_.key_id);
    return Action::NONE;
  }

  // Refuse encrypted frames before any IV has been negotiated for this key.
  // BLE reconnects may preserve active_, but a fresh boot/reset must not
  // decrypt against a zero or unrelated IV.
  if (!this->any_generation_valid_()) {
    ESP_LOGW(TAG, "Dropping encrypted frame: no IV negotiated");
    return Action::NONE;
  }

  // The protocol echoes IV[0..1] as seq_a/seq_b, so the seq pair selects the
  // generation. negotiate_new_iv_() guarantees the pair is unique across all
  // live generations.
  CryptoContext *generation = this->find_generation_(this->header_);
  if (generation == nullptr) {
    ESP_LOGW(TAG, "Dropping frame: seq_a/seq_b mismatch (cross-session replay?)");
    return Action::NONE;
  }
  CryptoContext &context = *generation;

  const size_t ct_len = frame.size() - HEADER_LEN;
  if (ct_len > MAX_PAYLOAD) {
    ESP_LOGW(TAG, "Dropping frame with invalid payload length: %zu", ct_len);
    return Action::NONE;
  }

  const uint8_t *ciphertext = reinterpret_cast<const uint8_t *>(frame.data() + HEADER_LEN);

  // Intra-session replay protection for state-changing actions: under a
  // fixed session IV, identical plaintexts produce identical ciphertexts.
  // We only flag duplicates that decode to a side-effecting command — state
  // polls are idempotent and a legitimate keypad emits them repeatedly.
  const bool ciphertext_seen =
      this->is_replayed_ciphertext_(context, ciphertext, ct_len);

  uint8_t plaintext[MAX_PAYLOAD];
  if (!this->xcrypt_(context.iv, ciphertext, ct_len, plaintext)) {
    return Action::NONE;  // error already logged
  }

  ESP_LOGD(TAG, "RX %s", format_hex_pretty(plaintext, ct_len).c_str());

  this->command_ = decode_lock_command(plaintext, ct_len);

  // A generation is superseded only once the keypad has *proved* it moved on
  // by sending a frame under a newer IV. From that point the old generation is
  // accepted for idempotent state polls only, so a delayed or captured lock or
  // unlock can never cross the hand-off boundary even if its ciphertext was
  // not present in the small replay ring. Merely advertising the next IV does
  // not supersede anything: the keypad routinely keeps using the current
  // generation after asking for a new one, and dropping those frames left it
  // without an answer.
  const bool superseded = this->has_newer_used_generation_(context);
  if (superseded && this->command_.type != CommandType::STATE_POLL) {
    ESP_LOGW(TAG, "Dropping non-poll frame under superseded IV");
    this->command_ = DecodedCommand{};
    return Action::NONE;
  }

  if (this->command_.type == CommandType::UNKNOWN) {
    ESP_LOGI(TAG, "Unhandled command: %s", format_hex_pretty(plaintext, ct_len).c_str());
  }

  // DOORBELL is deliberately left out of the replay filter: under a fixed
  // session IV a second legitimate press in the same connection produces the
  // exact same ciphertext, and dropping it would swallow real rings. Worst
  // case for a replayed doorbell frame is a spurious chime; a replayed
  // lock/unlock changes security state, so only those are filtered.
  if (this->command_.type == CommandType::LOCK || this->command_.type == CommandType::UNLOCK) {
    if (ciphertext_seen) {
      ESP_LOGW(TAG, "Dropping action: ciphertext replay within session");
      return Action::NONE;
    }
    this->record_ciphertext_(context, ciphertext, ct_len);
  }

  std::memcpy(this->plaintext_.data(), plaintext, ct_len);
  this->plaintext_size_ = ct_len;
  this->response_iv_ = context.iv;
  this->response_iv_valid_ = true;

  if (!context.used) {
    context.used = true;
    ESP_LOGV(TAG, "Keypad switched to IV generation %u",
             static_cast<unsigned>(context.serial));
  } else if (superseded) {
    ESP_LOGD(TAG, "Accepted delayed state poll under superseded IV");
  }

  return Action::COMMAND;
}

bool LockSession::is_iv_request_(const std::string &frame) const {
  return frame.size() >= SESSION_IV_REQ_MIN &&
         static_cast<uint8_t>(frame[0]) == PROTOCOL_MAGIC &&
         static_cast<uint8_t>(frame[1]) == 0x00 &&
         static_cast<uint8_t>(frame[5]) == 0x21 &&
         static_cast<uint8_t>(frame[6]) == 0x03;
}

size_t LockSession::encrypt_response(const FrameHeader &header, const uint8_t *plaintext,
                                     size_t length, uint8_t out[MAX_PACKET]) {
  if (length > MAX_PAYLOAD) {
    ESP_LOGE(TAG, "Response payload too large (%zu > %zu)", length, MAX_PAYLOAD);
    return 0;
  }
  out[0] = 0x01;
  out[1] = header.key_id;
  out[2] = header.seq_a;
  out[3] = header.seq_b;
  if (!this->response_iv_valid_ ||
      header.seq_a != this->response_iv_[0] ||
      header.seq_b != this->response_iv_[1]) {
    ESP_LOGE(TAG, "Cannot encrypt response: no matching RX IV context");
    return 0;
  }
  if (!this->xcrypt_(this->response_iv_, plaintext, length, out + HEADER_LEN)) {
    return 0;
  }
  return HEADER_LEN + length;
}

bool LockSession::xcrypt_(const std::array<uint8_t, AES_IV_SIZE> &iv,
                          const uint8_t *input, size_t length, uint8_t *output) {
  return aes_ctr_xcrypt(this->aes_key_, iv.data(), input, output, length);
}

void LockSession::negotiate_new_iv_() {
  CryptoContext &slot = this->allocate_generation_();
  slot = CryptoContext{};  // invalid while we search, so it never matches itself
  auto fill_iv = [&slot]() {
    for (size_t i = 0; i < AES_IV_SIZE; i += 4) {
      const uint32_t value = esp_random();
      std::memcpy(slot.iv.data() + i, &value, 4);
    }
  };
  fill_iv();

  // seq_a/seq_b are the only generation selector carried on the wire, so the
  // pair must be unique across every live generation. Bound the RNG retries so
  // a broken RNG cannot stall the BLE task, then fall back to a deterministic
  // scan of seq_b, which always finds a free pair: at most GENERATIONS - 1
  // other generations are live and 256 candidates exist.
  size_t retries = 0;
  while (this->seq_in_use_(slot.iv[0], slot.iv[1]) && retries++ < 4) {
    fill_iv();
  }
  if (this->seq_in_use_(slot.iv[0], slot.iv[1])) {
    for (uint16_t delta = 1; delta <= 0xFF; ++delta) {
      const uint8_t candidate = static_cast<uint8_t>(slot.iv[1] ^ delta);
      if (!this->seq_in_use_(slot.iv[0], candidate)) {
        slot.iv[1] = candidate;
        break;
      }
    }
  }

  slot.serial = ++this->serial_counter_;
  slot.valid = true;
  std::memcpy(this->iv_response_.data() + IV_RESPONSE_HEADER,
              slot.iv.data(), AES_IV_SIZE);
  ESP_LOGV(TAG, "New IV (generation %u): %s", static_cast<unsigned>(slot.serial),
           format_hex_pretty(slot.iv.data(), AES_IV_SIZE).c_str());
}

bool LockSession::seq_in_use_(uint8_t seq_a, uint8_t seq_b) const {
  for (const auto &generation : this->generations_) {
    if (generation.valid && generation.iv[0] == seq_a && generation.iv[1] == seq_b) {
      return true;
    }
  }
  return false;
}

bool LockSession::any_generation_valid_() const {
  for (const auto &generation : this->generations_) {
    if (generation.valid) {
      return true;
    }
  }
  return false;
}

bool LockSession::has_newer_used_generation_(const CryptoContext &context) const {
  for (const auto &generation : this->generations_) {
    if (generation.valid && generation.used && generation.serial > context.serial) {
      return true;
    }
  }
  return false;
}

LockSession::CryptoContext *LockSession::find_generation_(const FrameHeader &header) {
  CryptoContext *match = nullptr;
  for (auto &generation : this->generations_) {
    if (this->seq_matches_(generation, header) &&
        (match == nullptr || generation.serial > match->serial)) {
      match = &generation;
    }
  }
  return match;
}

// Free slot first; then the oldest generation the keypad never adopted, since
// an advertised-but-unused IV carries no live traffic; only if every slot is
// in use does the oldest adopted generation get recycled. Without the
// unused-first rule a keypad that asks for a new IV on every reconnect but
// keeps talking under the one it already has would evict its own live
// generation after GENERATIONS handshakes.
LockSession::CryptoContext &LockSession::allocate_generation_() {
  CryptoContext *oldest = nullptr;
  CryptoContext *oldest_unused = nullptr;
  for (auto &generation : this->generations_) {
    if (!generation.valid) {
      return generation;
    }
    if (oldest == nullptr || generation.serial < oldest->serial) {
      oldest = &generation;
    }
    if (!generation.used && (oldest_unused == nullptr || generation.serial < oldest_unused->serial)) {
      oldest_unused = &generation;
    }
  }
  CryptoContext *victim = oldest_unused != nullptr ? oldest_unused : oldest;
  ESP_LOGD(TAG, "Recycling IV generation %u", static_cast<unsigned>(victim->serial));
  return *victim;
}

bool LockSession::is_replayed_ciphertext_(const CryptoContext &context,
                                          const uint8_t *ciphertext,
                                          size_t length) const {
  if (length == 0 || length > MAX_PAYLOAD) {
    return false;
  }
  for (const auto &entry : context.replay_history) {
    if (entry.length == length && std::memcmp(entry.data.data(), ciphertext, length) == 0) {
      return true;
    }
  }
  return false;
}

void LockSession::record_ciphertext_(CryptoContext &context,
                                     const uint8_t *ciphertext, size_t length) {
  if (length == 0 || length > MAX_PAYLOAD) {
    return;
  }
  ReplayEntry &slot = context.replay_history[context.replay_head];
  std::memcpy(slot.data.data(), ciphertext, length);
  slot.length = length;
  context.replay_head = (context.replay_head + 1) % REPLAY_HISTORY_SIZE;
}

bool LockSession::seq_matches_(const CryptoContext &context,
                               const FrameHeader &header) const {
  return context.valid && header.seq_a == context.iv[0] &&
         header.seq_b == context.iv[1];
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
