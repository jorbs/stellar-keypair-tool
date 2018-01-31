#include <vector>
#include <iostream>
#include <sodium.h>
#include <unistd.h>
#include <algorithm>

#include "lib/crc16.h"
#include "lib/basen.h"

enum VersionByte : uint8_t {
  PUBLIC_KEY = (6 << 3),
  SEED = (18 << 3)
};

const std::string base32Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

char checkInvalidChar(const std::string &input) {
  for (const char& c : input)
    if (base32Dictionary.find(c) == std::string::npos)
      return c;

  return -1;
}

std::string encode(const VersionByte &versionByte, std::vector<uint8_t> &data) {
  std::vector<uint8_t> bytes;

  bytes.push_back(versionByte);
  bytes.insert(bytes.end(), data.begin(), data.end());

  uint16_t crc = crc16((char *) bytes.data(), bytes.size());

  bytes.emplace_back(static_cast<uint8_t>(crc & 0xFF));
  bytes.emplace_back(static_cast<uint8_t>((crc >> 8) & 0xFF));

  return bn::encode_b32(bytes);
}

inline bool hasSuffix(const std::string &input, const std::string &term) {
  return input.substr(input.size() - term.size()) == term;
}

inline bool hasPrefix(const std::string &input, const std::string &term) {
  return input.substr(0, term.size()) == term;
}

inline bool hasSubstr(const std::string &input, const std::string &term) {
  return input.find(term) != std::string::npos;
}

void usage(const char* exec) {
  std::cerr << "Usage: " << exec << " [-p|-m|-s] <term>\n\n";
}

int main(int argc, char* argv[]) {
  if (argc == 1) {
    usage(argv[0]);
    return 1;
  }

  bool (*matches)(const std::string &input, const std::string &suffix);
  std::string term;
  int c;

  while ((c = getopt(argc, argv, "p:m:s:")) != -1) {
    switch (c) {
      case 'p':
        if (optarg[0] != 'g' && optarg[0] != 'G') {
          std::cout << "Prepending 'G' to the search term.\n";
          term = "G";
        }

        term += optarg;
        matches = &hasPrefix;
        break;
      case 's':
        term = optarg;
        matches = &hasSuffix;
        break;
      case 'm':
        term = optarg;
        matches = &hasSubstr;
        break;
      case '?':
      default:
        usage(argv[0]);
        return 0;
    }
  }

  std::transform(term.begin(), term.end(), term.begin(), ::toupper);

  char invalidChar = checkInvalidChar(term);

  if (invalidChar != -1) {
    std::cerr << "\"" << invalidChar << "\" is not allowed. The search term must be scoped to:\n\t"
              << base32Dictionary << std::endl;
    return 0;
  }

  if (sodium_init() == -1) {
    std::cerr << "Unable to init libsodium.\n";
    return 1;
  }

  for (int count = 1; true; count++) {
    std::cout << count << " tries.\r" << std::flush;

    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);

    crypto_sign_keypair(pk.data(), sk.data());

    std::string encodedPk = encode(PUBLIC_KEY, pk);

    if (matches(encodedPk, term)) {
      std::vector<uint8_t> seed(crypto_sign_SEEDBYTES);

      crypto_sign_ed25519_sk_to_seed(seed.data(), sk.data());

      std::cout << "\nFOUND!\n\n"
                << encodedPk << std::endl
                << encode(SEED, seed) << "\n\n\a";
      break;
    }
  }

  return 0;
}
