#include <vector>
#include <iostream>
#include <sodium.h>
#include <cstring>

#include "lib/crc16.h"
#include "lib/basen.h"

#define MESSAGE (const unsigned char *)"test"
#define MESSAGE_LEN 4

enum VersionByte : uint8_t {
  PUBLIC_KEY = (6 << 3),
  SEED = (18 << 3)
};

std::string encode(const VersionByte &versionByte, std::vector<uint8_t> &data) {
  std::vector<uint8_t> bytes;

  bytes.push_back(versionByte);
  bytes.insert(bytes.end(), data.begin(), data.end());

  uint16_t crc = crc16((char *) bytes.data(), bytes.size());

  bytes.emplace_back(static_cast<uint8_t>(crc & 0xFF));
  bytes.emplace_back(static_cast<uint8_t>((crc >> 8) & 0xFF));

  return bn::encode_b32(bytes);
}

inline bool hasSuffix(const std::string &input, const std::string &suffix) {
  return input.substr(input.size() - suffix.size()) == suffix;
}

int main(int argc, char* argv[]) {
  if (argc == 1) {
    std::cerr << "Usage: " << argv[0] << " <suffix>\n\n";
    return 1;
  }

  if (sodium_init() == -1) {
    return 1;
  }

  std::string suffix(argv[1]);

  for (int count = 1; true; count++) {
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    std::vector<uint8_t> seed(crypto_sign_SEEDBYTES);

    crypto_sign_keypair(pk.data(), sk.data());
    crypto_sign_ed25519_sk_to_seed(seed.data(), sk.data());

    std::string encodedPk = encode(PUBLIC_KEY, pk);

    if (hasSuffix(encodedPk, suffix)) {
      std::string encodedSeed = encode(SEED, seed);
      std::cout << "\a\n\nFOUND!\n\nP: " << encodedPk << std::endl
                << "S: " << encodedSeed << "\n\n";
      break;
    }

    if (count % 5000 == 0) {
      std::cout << count << " tries.\r" << std::flush;
    }
  }

  return 0;
}
