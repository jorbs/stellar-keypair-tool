#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <unistd.h>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __LINUX__
#include <sstream>
#endif

#include "lib/crc16.h"
#include "lib/basen.h"

enum VersionByte : uint8_t {
  PUBLIC_KEY = (6 << 3),
  SEED = (18 << 3)
};

const std::string base32Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
std::atomic<bool> found{false};
std::atomic<int> count{0};

char checkInvalidChar(const std::string &input) {
  for (const char& c : input)
    if (base32Dictionary.find(c) == std::string::npos)
      return c;

  return -1;
}

int getProcessingUnits() {
  int units = std::thread::hardware_concurrency();

  if (units > 0)
    return units;

#ifdef _SC_NPROCESSORS_CONF
  units = sysconf(_SC_NPROCESSORS_CONF);
#endif

  if (units < 1) {
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);

    units = info.dwNumberOfProcessors;
#endif

#ifdef __LINUX__
    std::ifstream cpuinfo("/proc/cpuinfo", std::ifstream::in);

    if (cpuinfo.open())
      units = std::count(std::istream_iterator<std::string>(cpuinfo),
                        std::istream_iterator<std::string>(),
                        "processor");

    cpuinfo.close();
#endif
  }

  if (units < 1) {
    std::cout << "Unable to determine the number of CPUs. Running a single thread...\n";
    return 1;
  }

  return units;
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
  std::cerr << "Usage: " << exec << " [-p|-m|-s] <term> [-j <jobs>]\n\n";
}

void process(const std::string &term, bool (*matches)(const std::string &input, const std::string &suffix)) {
  std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
  std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);

  while (!found) {
    count++;

    crypto_sign_keypair(pk.data(), sk.data());

    std::string encodedPk = encode(PUBLIC_KEY, pk);

    if (matches(encodedPk, term)) {
      std::vector<uint8_t> seed(crypto_sign_SEEDBYTES);

      crypto_sign_ed25519_sk_to_seed(seed.data(), sk.data());

      if (!found) {
        found = true;
        std::cout << "FOUND!\n\n"
                  << encodedPk << std::endl
                  << encode(SEED, seed) << "\n\n\a";
      }

      break;
    }
  }
}

int main(int argc, char* argv[]) {
  if (argc == 1) {
    usage(argv[0]);
    return 1;
  }

  std::string term;
  int threadsCount = -1, c;
  bool (*matchFunction)(const std::string &input, const std::string &suffix);

  while ((c = getopt(argc, argv, "p:m:s:j:")) != -1) {
    switch (c) {
      case 'p':
        if (optarg[0] != 'g' && optarg[0] != 'G') {
          std::cout << "Prepending 'G' to the search term.\n";
          term = "G";
        }

        term += optarg;
        matchFunction = &hasPrefix;
        break;
      case 's':
        term = optarg;
        matchFunction = &hasSuffix;
        break;
      case 'm':
        term = optarg;
        matchFunction = &hasSubstr;
        break;
      case 'j':
        threadsCount = atoi(optarg);
        break;
      case '?':
      default:
        usage(argv[0]);
        return 0;
    }
  }

  if (threadsCount == -1) {
    threadsCount = getProcessingUnits();
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

  std::cout << "Searching...\n";

  std::vector<std::thread> threads(threadsCount);
  auto start = std::chrono::system_clock::now();

  for (int i = 0; i < threadsCount; i++)
    threads[i] = std::thread(process, term, matchFunction);

  std::for_each(threads.begin(), threads.end(), [](std::thread &t) { t.join(); });

  auto end = std::chrono::system_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;

  std::cout << count << " tries in " << elapsed_seconds.count() << "s\n";

  return 0;
}
