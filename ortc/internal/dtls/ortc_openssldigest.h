#ifndef TALK_BASE_OPENSSLDIGEST_H_
#define TALK_BASE_OPENSSLDIGEST_H_

#include <openssl/evp.h>

//#include "talk/base/messagedigest.h"
#include "ortc_messagedigest.h"

namespace ortc
{
  namespace internal
  {
	// An implementation of the digest class that uses OpenSSL.
	class OpenSSLDigest : public MessageDigest {
	 public:
	  // Creates an OpenSSLDigest with |algorithm| as the hash algorithm.
	  explicit OpenSSLDigest(const std::string& algorithm);
	  ~OpenSSLDigest();
	  // Returns the digest output size (e.g. 16 bytes for MD5).
	  virtual size_t Size() const;
	  // Updates the digest with |len| bytes from |buf|.
	  virtual void Update(const void* buf, size_t len);
	  // Outputs the digest value to |buf| with length |len|.
	  virtual size_t Finish(void* buf, size_t len);

	  // Helper function to look up a digest's EVP by name.
	  static bool GetDigestEVP(const std::string &algorithm,
							   const EVP_MD** md);
	  // Helper function to look up a digest's name by EVP.
	  static bool GetDigestName(const EVP_MD* md,
								std::string* algorithm);
	  // Helper function to get the length of a digest.
	  static bool GetDigestSize(const std::string &algorithm,
								size_t* len);

	 private:
	  EVP_MD_CTX ctx_;
	  const EVP_MD* md_;
	};
  }
}
#endif
