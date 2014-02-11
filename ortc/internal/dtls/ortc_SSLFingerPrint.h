#ifndef TALK_BASE_SSLFINGERPRINT_H_
#define TALK_BASE_SSLFINGERPRINT_H_

#include <ctype.h>
#include <string>

//#include "talk/base/buffer.h"
//#include "talk/base/helpers.h"
//#include "talk/base/messagedigest.h"
//#include "talk/base/sslidentity.h"
//#include "talk/base/stringencode.h"

#include "ortc_helpers.h"
#include "ortc_messagedigest.h"
#include "ortc_SSLIdentity.h"
#include "ortc_stringencode.h"
#include "ortc_buffer.h"

namespace ortc
{
   namespace internal
   {
	struct SSLFingerprint {
	  static SSLFingerprint* Create(const std::string& algorithm,
									const SSLIdentity* identity) {
		if (!identity) {
		  return NULL;
		}

		return Create(algorithm, &(identity->certificate()));
	  }

	  static SSLFingerprint* Create(const std::string& algorithm,
									const SSLCertificate* cert) {
		uint8 digest_val[64];
		size_t digest_len;
		bool ret = cert->ComputeDigest(
			algorithm, digest_val, sizeof(digest_val), &digest_len);
		if (!ret) {
		  return NULL;
		}

		return new SSLFingerprint(algorithm, digest_val, digest_len);
	  }

	  static SSLFingerprint* CreateFromRfc4572(const std::string& algorithm,
											   const std::string& fingerprint) {
		if (algorithm.empty())
		  return NULL;

		if (fingerprint.empty())
		  return NULL;

		size_t value_len;
		char value[MessageDigest::kMaxSize];
		value_len = hex_decode_with_delimiter(value, sizeof(value),
														 fingerprint.c_str(),
														 fingerprint.length(),
														 ':');
		if (!value_len)
		  return NULL;

		return new SSLFingerprint(algorithm,
								  reinterpret_cast<uint8*>(value),
								  value_len);
	  }

	  SSLFingerprint(const std::string& algorithm, const uint8* digest_in,
					 size_t digest_len) : algorithm(algorithm) {
		digest.SetData(digest_in, digest_len);
	  }
	  SSLFingerprint(const SSLFingerprint& from)
		  : algorithm(from.algorithm), digest(from.digest) {}
	  bool operator==(const SSLFingerprint& other) const {
		return algorithm == other.algorithm &&
			   digest == other.digest;
	  }

	  std::string GetRfc4572Fingerprint() const {
		std::string fingerprint =
			hex_encode_with_delimiter(
				digest.data(), digest.length(), ':');
		std::transform(fingerprint.begin(), fingerprint.end(),
					   fingerprint.begin(), ::toupper);
		return fingerprint;
	  }

	  std::string algorithm;
	  Buffer digest;
	};
   }
}  // namespace talk_base

#endif  // TALK_BASE_SSLFINGERPRINT_H_
