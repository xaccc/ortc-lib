#ifndef TALK_BASE_HELPERS_H_
#define TALK_BASE_HELPERS_H_

#include <string>
#include "ortc_basictypes.h"

namespace ortc
{
  namespace internal
  {
	// For testing, we can return predictable data.
	void SetRandomTestMode(bool test);

	// Initializes the RNG, and seeds it with the specified entropy.
	bool InitRandom(int seed);
	bool InitRandom(const char* seed, size_t len);

	// Generates a (cryptographically) random string of the given length.
	// We generate base64 values so that they will be printable.
	// WARNING: could silently fail. Use the version below instead.
	std::string CreateRandomString(size_t length);

	// Generates a (cryptographically) random string of the given length.
	// We generate base64 values so that they will be printable.
	// Return false if the random number generator failed.
	bool CreateRandomString(size_t length, std::string* str);

	// Generates a (cryptographically) random string of the given length,
	// with characters from the given table. Return false if the random
	// number generator failed.
	bool CreateRandomString(size_t length, const std::string& table,
							std::string* str);

	// Generates a random id.
	uint32 CreateRandomId();

	// Generates a 64 bit random id.
	uint64 CreateRandomId64();

	// Generates a random id > 0.
	uint32 CreateRandomNonZeroId();

	// Generates a random double between 0.0 (inclusive) and 1.0 (exclusive).
	double CreateRandomDouble();
  }
}

#endif  // TALK_BASE_HELPERS_H_
