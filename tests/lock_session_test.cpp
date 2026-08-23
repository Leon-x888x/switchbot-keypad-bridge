#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "components/switchbot_keypad_bridge/aes_ctr.h"
#include "components/switchbot_keypad_bridge/lock_session.h"

namespace {

using esphome::switchbot_keypad_bridge::CommandType;
using esphome::switchbot_keypad_bridge::LockSession;

constexpr psa_key_id_t TEST_KEY = 0x42;
constexpr uint8_t SLOT = 0xC6;
constexpr std::array<uint8_t, 4> STATE_POLL = {0x0F, 0x4F, 0x81, 0x00};
constexpr std::array<uint8_t, 8> LOCK = {0x0F, 0x4E, 0x01, 0x03,
                                         0x00, 0x00, 0x00, 0x00};
constexpr std::array<uint8_t, 8> UNLOCK = {0x0F, 0x4E, 0x01, 0x03,
                                           0x04, 0x80, 0x0B, 0x00};
constexpr std::array<uint8_t, 2> DOORBELL = {0x01, 0x03};

std::deque<uint32_t> random_values;

std::array<uint8_t, 16> make_iv(uint8_t first) {
  std::array<uint8_t, 16> iv{};
  for (size_t i = 0; i < iv.size(); ++i) {
    iv[i] = static_cast<uint8_t>(first + i);
  }
  return iv;
}

void queue_iv(const std::array<uint8_t, 16> &iv) {
  for (size_t i = 0; i < iv.size(); i += sizeof(uint32_t)) {
    uint32_t word;
    std::memcpy(&word, iv.data() + i, sizeof(word));
    random_values.push_back(word);
  }
}

std::string iv_request() {
  const uint8_t bytes[8] = {0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03, SLOT};
  return {reinterpret_cast<const char *>(bytes), sizeof(bytes)};
}

std::array<uint8_t, 16> response_iv(const LockSession &session) {
  std::array<uint8_t, 16> iv{};
  std::memcpy(iv.data(), session.iv_response() + 4, iv.size());
  return iv;
}

template<size_t N>
std::string encrypted_frame(const std::array<uint8_t, 16> &iv,
                            const std::array<uint8_t, N> &plaintext) {
  std::vector<uint8_t> wire(LockSession::HEADER_LEN + plaintext.size());
  wire[0] = 0x57;
  wire[1] = SLOT;
  wire[2] = iv[0];
  wire[3] = iv[1];
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), plaintext.data(), wire.data() + LockSession::HEADER_LEN,
      plaintext.size());
  assert(ok);
  return {reinterpret_cast<const char *>(wire.data()), wire.size()};
}

void assert_response_uses_iv(LockSession &session,
                             const std::array<uint8_t, 16> &iv) {
  const uint8_t plaintext[3] = {0x81, 0x08, 0x08};
  uint8_t packet[LockSession::MAX_PACKET]{};
  const size_t size = session.encrypt_response(session.header(), plaintext,
                                                sizeof(plaintext), packet);
  assert(size == LockSession::HEADER_LEN + sizeof(plaintext));

  uint8_t decoded[sizeof(plaintext)]{};
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), packet + LockSession::HEADER_LEN, decoded,
      sizeof(decoded));
  assert(ok);
  assert(std::memcmp(decoded, plaintext, sizeof(plaintext)) == 0);
}

void test_iv_handoff_and_replay() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto first_iv = make_iv(0x10);
  queue_iv(first_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == first_iv);

  const std::string first_poll = encrypted_frame(first_iv, STATE_POLL);
  assert(session.process_frame(first_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);

  // A BLE reconnect clears only transient transport state. The logical crypto
  // generation and its replay history stay alive.
  session.reset_transport();
  assert(session.process_frame(first_poll) == LockSession::Action::COMMAND);

  // Two further handshakes without the keypad ever switching. Both generations
  // are retained; neither supersedes the one actually in use.
  const auto second_iv = make_iv(0x30);
  queue_iv(second_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == second_iv);

  const auto third_iv = make_iv(0x50);
  queue_iv(third_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == third_iv);

  // The reported Vision Pro race: finish an old state poll after advertising
  // the next IV, and encrypt the reply with the old generation.
  assert(session.process_frame(first_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);
  assert_response_uses_iv(session, first_iv);

  // Regression: an advertised-but-unadopted IV must not swallow a real unlock
  // that the keypad is still sending under the generation it kept using.
  assert(session.process_frame(encrypted_frame(first_iv, UNLOCK)) ==
         LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::UNLOCK);
  assert(session.command().credential_index == 1);

  // Regression: a frame under the middle generation is not a cross-session
  // replay. Accepting it is what proves the keypad switched.
  assert(session.process_frame(encrypted_frame(second_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // From here the first generation is superseded by a *used* newer one: an
  // in-flight poll still gets answered, side effects no longer do.
  assert(session.process_frame(first_poll) == LockSession::Action::COMMAND);
  assert(session.process_frame(encrypted_frame(first_iv, DOORBELL)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(first_iv, LOCK)) ==
         LockSession::Action::NONE);

  // Per-generation replay history still rejects a repeated side effect.
  const std::string third_lock = encrypted_frame(third_iv, LOCK);
  assert(session.process_frame(third_lock) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::LOCK);
  assert(session.process_frame(third_lock) == LockSession::Action::NONE);

  // Doorbell remains intentionally outside the side-effect replay filter.
  const std::string doorbell = encrypted_frame(third_iv, DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);

  // Generations are a bounded ring: enough later handshakes evict the oldest.
  for (uint8_t base = 0x80; base < 0xC0; base = static_cast<uint8_t>(base + 0x10)) {
    queue_iv(make_iv(base));
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(make_iv(base), STATE_POLL)) ==
           LockSession::Action::COMMAND);
  }
  // The first frame under a generation the bridge no longer holds is answered
  // with a fresh IV so the keypad can resynchronise without timing out; the
  // next unmatched frame in the same connection is simply dropped.
  const auto resync_iv = make_iv(0xC0);
  queue_iv(resync_iv);
  assert(session.process_frame(first_poll) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == resync_iv);
  assert(session.process_frame(first_poll) == LockSession::Action::NONE);

  // The offer is renewed once per BLE connection.
  session.reset_transport();
  const auto resync_iv2 = make_iv(0xD0);
  queue_iv(resync_iv2);
  assert(session.process_frame(first_poll) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == resync_iv2);

  // And the keypad can pick that offer up.
  assert(session.process_frame(encrypted_frame(resync_iv2, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);

  // A full crypto reset (unpair/re-key) rejects every live IV.
  session.reset();
  assert(session.process_frame(encrypted_frame(resync_iv2, STATE_POLL)) ==
         LockSession::Action::NONE);
}

// A Vision Pro that renegotiates on every BLE reconnect but keeps talking
// under the IV it already has must never be starved: its unlock has to be
// answered no matter how many IV responses it ignored.
void test_keypad_that_ignores_new_ivs_is_still_served() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto iv = make_iv(0x20);
  queue_iv(iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  for (uint8_t base = 0x40; base != 0x00; base = static_cast<uint8_t>(base + 0x10)) {
    queue_iv(make_iv(base));
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    session.reset_transport();  // BLE reconnect between handshakes
  }

  assert(session.process_frame(encrypted_frame(iv, UNLOCK)) ==
         LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::UNLOCK);
  assert_response_uses_iv(session, iv);
}

void test_seq_collision_is_resolved() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x70);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Simulate a broken RNG returning the same IV for every bounded retry.
  for (size_t i = 0; i < 5; ++i) {
    queue_iv(active_iv);
  }
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  const auto pending_iv = response_iv(session);
  assert(pending_iv[0] != active_iv[0] || pending_iv[1] != active_iv[1]);
}

}  // namespace

uint32_t esp_random() {
  assert(!random_values.empty());
  const uint32_t value = random_values.front();
  random_values.pop_front();
  return value;
}

namespace esphome {
namespace switchbot_keypad_bridge {

bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    output[i] = input[i] ^ iv[i % 16] ^ static_cast<uint8_t>(key);
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome

int main() {
  test_iv_handoff_and_replay();
  test_keypad_that_ignores_new_ivs_is_still_served();
  test_seq_collision_is_resolved();
  assert(random_values.empty());
  return 0;
}
