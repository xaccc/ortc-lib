#include "ortc_helpers.h"

#include <limits>
#define FEATURE_ENABLE_SSL

#include <openssl/rand.h>

//#include "talk/base/base64.h"
//#include "talk/base/basictypes.h"
//#include "talk/base/logging.h"
//#include "talk/base/scoped_ptr.h"
//#include "talk/base/timeutils.h"

#include "ortc_basictypes.h"
#include "boostTypes.h"

// Protect against max macro inclusion.
#undef max

namespace ortc
{
  namespace internal
  {
	// Base class for RNG implementations.
	class RandomGenerator {
	 public:
	  virtual ~RandomGenerator() {}
	  virtual bool Init(const void* seed, size_t len) = 0;
	  virtual bool Generate(void* buf, size_t len) = 0;
	};

#if defined(FEATURE_ENABLE_SSL)
	// The OpenSSL RNG. Need to make sure it doesn't run out of entropy.
	class SecureRandomGenerator : public RandomGenerator {
	 public:
	  SecureRandomGenerator() : inited_(false) {
	  }
	  ~SecureRandomGenerator() {
	  }
	  virtual bool Init(const void* seed, size_t len) {
		// By default, seed from the system state.
		if (!inited_) {
		  if (RAND_poll() <= 0) {
			return false;
		  }
		  inited_ = true;
		}
		// Allow app data to be mixed in, if provided.
		if (seed) {
		  RAND_seed(seed, len);
		}
		return true;
	  }
	  virtual bool Generate(void* buf, size_t len) {
		if (!inited_ && !Init(NULL, 0)) {
		  return false;
		}
		return (RAND_bytes(reinterpret_cast<unsigned char*>(buf), len) > 0);
	  }

	 private:
	  bool inited_;
	};

#elif !defined(FEATURE_ENABLE_SSL)

	// No SSL implementation -- use rand()
	class SecureRandomGenerator : public RandomGenerator {
	 public:
	  virtual bool Init(const void* seed, size_t len) {
		if (len >= 4) {
		  srand(*reinterpret_cast<const int*>(seed));
		} else {
		  srand(*reinterpret_cast<const char*>(seed));
		}
		return true;
	  }
	  virtual bool Generate(void* buf, size_t len) {
		char* bytes = reinterpret_cast<char*>(buf);
		for (size_t i = 0; i < len; ++i) {
		  bytes[i] = static_cast<char>(rand());
		}
		return true;
	  }
	};

#else
#error No SSL implementation has been selected!
#endif

	// A test random generator, for predictable output.
	class TestRandomGenerator : public RandomGenerator {
	 public:
	  TestRandomGenerator() : seed_(7) {
	  }
	  ~TestRandomGenerator() {
	  }
	  virtual bool Init(const void* seed, size_t len) {
		return true;
	  }
	  virtual bool Generate(void* buf, size_t len) {
		for (size_t i = 0; i < len; ++i) {
		  static_cast<uint8*>(buf)[i] = static_cast<uint8>(GetRandom());
		}
		return true;
	  }

	 private:
	  int GetRandom() {
		return ((seed_ = seed_ * 214013L + 2531011L) >> 16) & 0x7fff;
	  }
	  int seed_;
	};

	// TODO: Use Base64::Base64Table instead.
	static const char BASE64[64] = {
	  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
	};

	namespace {

		// This round about way of creating a global RNG is to safe-guard against
		// indeterminant static initialization order.
		boost::shared_ptr<RandomGenerator>& GetGlobalRng() {
		  LIBJINGLE_DEFINE_STATIC_LOCAL(boost::shared_ptr<RandomGenerator>, global_rng,
										(new SecureRandomGenerator()));
		  return global_rng;
		}

		RandomGenerator& Rng() {
		  return *GetGlobalRng();
		}

	}  // namespace

	void SetRandomTestMode(bool test) {
	  if (!test) {
		GetGlobalRng().reset(new SecureRandomGenerator());
	  } else {
		GetGlobalRng().reset(new TestRandomGenerator());
	  }
	}

	bool InitRandom(int seed) {
	  return InitRandom(reinterpret_cast<const char*>(&seed), sizeof(seed));
	}

	bool InitRandom(const char* seed, size_t len) {
	  if (!Rng().Init(seed, len)) {
		std::cout << "Failed to init random generator!";
		return false;
	  }
	  return true;
	}

	std::string CreateRandomString(size_t len) {
	  std::string str;
	  CreateRandomString(len, &str);
	  return str;
	}

	bool CreateRandomString(size_t len,
							const char* table, int table_size,
							std::string* str) {
	  str->clear();
	  boost::shared_ptr<uint8[]> bytes(new uint8[len]);
	  if (!Rng().Generate(bytes.get(), len)) {
		std::cout << "Failed to generate random string!";
		return false;
	  }
	  str->reserve(len);
	  for (size_t i = 0; i < len; ++i) {
		str->push_back(table[bytes[i] % table_size]);
	  }
	  return true;
	}

	bool CreateRandomString(size_t len, std::string* str) {
	  return CreateRandomString(len, BASE64, 64, str);
	}

	bool CreateRandomString(size_t len, const std::string& table,
							std::string* str) {
	  return CreateRandomString(len, table.c_str(),
								static_cast<int>(table.size()), str);
	}

	uint32 CreateRandomId() {
	  uint32 id;
	  if (!Rng().Generate(&id, sizeof(id))) {
		std::cout << "Failed to generate random id!";
	  }
	  return id;
	}

	uint64 CreateRandomId64() {
	  return static_cast<uint64>(CreateRandomId()) << 32 | CreateRandomId();
	}

	uint32 CreateRandomNonZeroId() {
	  uint32 id;
	  do {
		id = CreateRandomId();
	  } while (id == 0);
	  return id;
	}

	double CreateRandomDouble() {
	  return CreateRandomId() / (std::numeric_limits<uint32>::max() +
		  std::numeric_limits<double>::epsilon());
	}
  }
}
