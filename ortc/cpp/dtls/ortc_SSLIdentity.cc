// Handling of certificates and keypairs for SSLStreamAdapter's peer mode.
#if HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H

//#include "talk/base/sslidentity.h"
//
//#include <string>
//
//#include "talk/base/base64.h"
//#include "talk/base/logging.h"
//#include "talk/base/sslconfig.h"
//
//#include "talk/base/opensslidentity.h"

#include "ortc_SSLIdentity.h"
#include "ortc_opensslidentity.h"
#include "ortc_base64.h"


namespace ortc
{
  namespace internal
  {
	const char kPemTypeCertificate[] = "CERTIFICATE";
	const char kPemTypeRsaPrivateKey[] = "RSA PRIVATE KEY";

	bool SSLIdentity::PemToDer(const std::string& pem_type,
							   const std::string& pem_string,
							   std::string* der) {
	  // Find the inner body. We need this to fulfill the contract of
	  // returning pem_length.
	  size_t header = pem_string.find("-----BEGIN " + pem_type + "-----");
	  if (header == std::string::npos)
		return false;

	  size_t body = pem_string.find("\n", header);
	  if (body == std::string::npos)
		return false;

	  size_t trailer = pem_string.find("-----END " + pem_type + "-----");
	  if (trailer == std::string::npos)
		return false;

	  std::string inner = pem_string.substr(body + 1, trailer - (body + 1));

	  *der = Base64::Decode(inner, Base64::DO_PARSE_WHITE |
							Base64::DO_PAD_ANY |
							Base64::DO_TERM_BUFFER);
	  return true;
	}

	std::string SSLIdentity::DerToPem(const std::string& pem_type,
									  const unsigned char* data,
									  size_t length) {
	  std::stringstream result;

	  result << "-----BEGIN " << pem_type << "-----\n";

	  std::string b64_encoded;
	  Base64::EncodeFromArray(data, length, &b64_encoded);

	  // Divide the Base-64 encoded data into 64-character chunks, as per
	  // 4.3.2.4 of RFC 1421.
	  static const size_t kChunkSize = 64;
	  size_t chunks = (b64_encoded.size() + (kChunkSize - 1)) / kChunkSize;
	  for (size_t i = 0, chunk_offset = 0; i < chunks;
		   ++i, chunk_offset += kChunkSize) {
		result << b64_encoded.substr(chunk_offset, kChunkSize);
		result << "\n";
	  }

	  result << "-----END " << pem_type << "-----\n";

	  return result.str();
	}

	SSLCertificate* SSLCertificate::FromPEMString(const std::string& pem_string) {
	  return OpenSSLCertificate::FromPEMString(pem_string);
	}

	SSLIdentity* SSLIdentity::Generate(const std::string& common_name) {
	  return OpenSSLIdentity::Generate(common_name);
	}

	SSLIdentity* SSLIdentity::GenerateForTest(const SSLIdentityParams& params) {
	  return OpenSSLIdentity::GenerateForTest(params);
	}

	SSLIdentity* SSLIdentity::FromPEMStrings(const std::string& private_key,
											 const std::string& certificate) {
	  return OpenSSLIdentity::FromPEMStrings(private_key, certificate);
	}
  }
}
