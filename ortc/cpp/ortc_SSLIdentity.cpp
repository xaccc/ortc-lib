#include "ortc/internal/ortc_SSLIdentity.h"
#include <android/log.h>
#if HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openpeer/services/internal/services_Helper.h>
#define _DEBUG

namespace ortc
{
  namespace internal
  {
    // From RFC 4572.
	const char DIGEST_MD5[]     = "md5";
	const char DIGEST_SHA_1[]   = "sha-1";
	const char DIGEST_SHA_224[] = "sha-224";
	const char DIGEST_SHA_256[] = "sha-256";
	const char DIGEST_SHA_384[] = "sha-384";
	const char DIGEST_SHA_512[] = "sha-512";
	
	static const size_t kBlockSize = 64;  // valid for SHA-256 and down

///////////////////////// Message Digest //////////////////////////////////
	
	MessageDigest* MessageDigestFactory::Create(const String& alg) {
	  MessageDigest* digest = new OpenSSLDigest(alg);
	  if (digest->Size() == 0) {  // invalid algorithm
		delete digest;
		digest = NULL;
	  }
	  return digest;
	}
	
	size_t ComputeDigest(MessageDigest* digest, const void* input, size_t in_len,
						 void* output, size_t out_len) {
	  digest->Update(input, in_len);
	  return digest->Finish(output, out_len);
	}
	
	size_t ComputeDigest(const String& alg, const void* input, size_t in_len,
						 void* output, size_t out_len) {
	  boost::shared_ptr<MessageDigest> digest(MessageDigestFactory::Create(alg));
	  return (digest) ?
		  ComputeDigest(digest.get(), input, in_len, output, out_len) :
		  0;
	}

	String ComputeDigest(MessageDigest* digest, const String& input) {
	  boost::shared_ptr<char[]> output(new char[digest->Size()]);
	  ComputeDigest(digest, input.data(), input.size(),
					output.get(), digest->Size());
	 return openpeer::services::IHelper::convertToHex((zsLib::BYTE*)output.get(),digest->Size());
	}
	
	bool ComputeDigest(const String& alg, const String& input,
					   String* output) {	 	
	  boost::shared_ptr<MessageDigest> digest(MessageDigestFactory::Create(alg));
	  if (!digest) {
		return false;
	  }
	  *output = ComputeDigest(digest.get(), input);
	  return true;
	}
	
	String ComputeDigest(const String& alg, const String& input) {
	  String output;
	  ComputeDigest(alg, input, &output);
	  return output;
	}
	
	size_t ComputeHmac(MessageDigest* digest,
					   const void* key, size_t key_len,
					   const void* input, size_t in_len,
					   void* output, size_t out_len) {
	  // We only handle algorithms with a 64-byte blocksize.
	  // TODO: Add BlockSize() method to MessageDigest.
	  size_t block_len = kBlockSize;
	  if (digest->Size() > 32) {
		return 0;
	  }
	  // Copy the key to a block-sized buffer to simplify padding.
	  // If the key is longer than a block, hash it and use the result instead.
	  boost::shared_ptr<UCHAR[]> new_key(new UCHAR[block_len]);
	  if (key_len > block_len) {
		ComputeDigest(digest, key, key_len, new_key.get(), block_len);
		memset(new_key.get() + digest->Size(), 0, block_len - digest->Size());
	  } else {
		memcpy(new_key.get(), key, key_len);
		memset(new_key.get() + key_len, 0, block_len - key_len);
	  }
	  // Set up the padding from the key, salting appropriately for each padding.
	  boost::shared_ptr<UCHAR[]> o_pad(new UCHAR[block_len]), i_pad(new UCHAR[block_len]);
	  for (size_t i = 0; i < block_len; ++i) {
		o_pad[i] = 0x5c ^ new_key[i];
		i_pad[i] = 0x36 ^ new_key[i];
	  }
	  // Inner hash; hash the inner padding, and then the input buffer.
	  boost::shared_ptr<UCHAR[]> inner(new UCHAR[digest->Size()]);
	  digest->Update(i_pad.get(), block_len);
	  digest->Update(input, in_len);
	  digest->Finish(inner.get(), digest->Size());
	  // Outer hash; hash the outer padding, and then the result of the inner hash.
	  digest->Update(o_pad.get(), block_len);
	  digest->Update(inner.get(), digest->Size());
	  return digest->Finish(output, out_len);
	}
	
	size_t ComputeHmac(const String& alg, const void* key, size_t key_len,
					   const void* input, size_t in_len,
					   void* output, size_t out_len) {
	  boost::shared_ptr<MessageDigest> digest(MessageDigestFactory::Create(alg));
	  if (!digest) {
		return 0;
	  }
	  return ComputeHmac(digest.get(), key, key_len,
						 input, in_len, output, out_len);
	}
	
	String ComputeHmac(MessageDigest* digest, const String& key,
							const String& input) {			
	  boost::shared_ptr<char[]> output(new char[digest->Size()]);
	  ComputeHmac(digest, key.data(), key.size(),
				  input.data(), input.size(), output.get(), digest->Size());
	  return openpeer::services::IHelper::convertToHex((zsLib::BYTE*)output.get(),digest->Size());
	}
	
	bool ComputeHmac(const String& alg, const String& key,
					 const String& input, String* output) {	
	  boost::shared_ptr<MessageDigest> digest(MessageDigestFactory::Create(alg));
	  if (!digest) {
		return false;
	  }
	  *output = ComputeHmac(digest.get(), key, input);
	  return true;
	}
	
	String ComputeHmac(const String& alg, const String& key,
							const String& input) {		
	  String output;
	  ComputeHmac(alg, key, input, &output);
	  return output;
	}
	
///////////////////////// Openssl Digest //////////////////////////////////	
	OpenSSLDigest::OpenSSLDigest(const String& algorithm) {
	  EVP_MD_CTX_init(&ctx_);
	  if (GetDigestEVP(algorithm, &md_)) {
		EVP_DigestInit_ex(&ctx_, md_, NULL);
	  } else {
		md_ = NULL;
	  }
	}
	
	OpenSSLDigest::~OpenSSLDigest() {
	  EVP_MD_CTX_cleanup(&ctx_);
	}

	size_t OpenSSLDigest::Size() const {
	  if (!md_) {
		return 0;
	  }
	  return EVP_MD_size(md_);
	}

	void OpenSSLDigest::Update(const void* buf, size_t len) {
	  if (!md_) {
		return;
	  }
	  EVP_DigestUpdate(&ctx_, buf, len);
	}

	size_t OpenSSLDigest::Finish(void* buf, size_t len) {
	  if (!md_ || len < Size()) {
		return 0;
	  }
	  unsigned int md_len;
	  EVP_DigestFinal_ex(&ctx_, static_cast<unsigned char*>(buf), &md_len);
	  EVP_DigestInit_ex(&ctx_, md_, NULL);  // prepare for future Update()s
	  ASSERT(md_len == Size());
	  return md_len;
	}

	bool OpenSSLDigest::GetDigestEVP(const String& algorithm,
									 const EVP_MD** mdp) {
	  const EVP_MD* md;
	  if (algorithm == DIGEST_MD5) {
		md = EVP_md5();
	  } else if (algorithm == DIGEST_SHA_1) {
		md = EVP_sha1();
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
	  } else if (algorithm == DIGEST_SHA_224) {
		md = EVP_sha224();
	  } else if (algorithm == DIGEST_SHA_256) {
		md = EVP_sha256();
	  } else if (algorithm == DIGEST_SHA_384) {
		md = EVP_sha384();
	  } else if (algorithm == DIGEST_SHA_512) {
		md = EVP_sha512();
#endif
	  } else {
		return false;
	  }

	  // Can't happen
	  ASSERT(EVP_MD_size(md) >= 16);
	  *mdp = md;
	  return true;
	}
	
	bool OpenSSLDigest::GetDigestName(const EVP_MD* md,
									  String* algorithm) { 									  
	  ASSERT(md != NULL);
	  ASSERT(algorithm != NULL);

	  int md_type = EVP_MD_type(md);
	  if (md_type == NID_md5) {
		*algorithm = DIGEST_MD5;
	  } else if (md_type == NID_sha1) {
		*algorithm = DIGEST_SHA_1;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
	  } else if (md_type == NID_sha224) {
		*algorithm = DIGEST_SHA_224;
	  } else if (md_type == NID_sha256) {
		*algorithm = DIGEST_SHA_256;
	  } else if (md_type == NID_sha384) {
		*algorithm = DIGEST_SHA_384;
	  } else if (md_type == NID_sha512) {
		*algorithm = DIGEST_SHA_512;
#endif
	  } else {
		algorithm->clear();
		return false;
	  }

	  return true;
	}
	
	bool OpenSSLDigest::GetDigestSize(const String& algorithm,
									  size_t* length) {
	  const EVP_MD *md;
	  if (!GetDigestEVP(algorithm, &md))
		return false;

	  *length = EVP_MD_size(md);
	  return true;
	}
	
///////////////////////// SSL Identity //////////////////////////////////	

	const char kPemTypeCertificate[] = "CERTIFICATE";
	const char kPemTypeRsaPrivateKey[] = "RSA PRIVATE KEY";

	SSLIdentity* SSLIdentity::Generate(const String& common_name) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,Generate()......!!!!");
	  return OpenSSLIdentity::Generate(common_name);
	}
	
	SSLIdentity* SSLIdentity::GenerateForTest(const SSLIdentityParams& params) {
      __android_log_print(ANDROID_LOG_INFO, "Tag", "Param common name used to generate key/certi = %s", params.common_name.c_str());
	  return OpenSSLIdentity::GenerateForTest(params);
	}

	
///////////////////////// OpenSSL Identity //////////////////////////////////	

	static const int KEY_LENGTH = 1024;// Strength of generated keys. Those are RSA.
	static const int SERIAL_RAND_BITS = 64;// Random bits for certificate serial number
	static const int CERTIFICATE_LIFETIME = 60*60*24*30;// Certificate validity lifetime,30 days arbritarily
	static const int CERTIFICATE_WINDOW = -60*60*24;//// This is to compensate for slightly incorrect system clocks.
	
	static EVP_PKEY* MakeKey() {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeKey()......!!!!");
	  std::cout << "Making key pair";
      EVP_PKEY* pkey = EVP_PKEY_new();//allocates an empty EVP_PKEY structure which is used by OpenSSL to store private keys.
#if OPENSSL_VERSION_NUMBER < 0x00908000l
	  // Only RSA_generate_key is available. Use that.
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdenity_feb7.cpp,MakeKey(),using RSA_generate_key......!!!!");
	  RSA* rsa = RSA_generate_key(KEY_LENGTH, 0x10001, NULL, NULL);
	  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		EVP_PKEY_free(pkey);
		RSA_free(rsa);
		return NULL;
	  }
#else
	  // RSA_generate_key is deprecated. Use _ex version.
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeKey(),RSA_generate_key is deprecated,use _ex version......!!!!");
	  BIGNUM* exponent = BN_new();
	  RSA* rsa = RSA_new();
	  if (!pkey || !exponent || !rsa ||
		  !BN_set_word(exponent, 0x10001) ||  // 65537 RSA exponent
		  !RSA_generate_key_ex(rsa, KEY_LENGTH, exponent, NULL) ||
		  !EVP_PKEY_assign_RSA(pkey, rsa)) {
		EVP_PKEY_free(pkey);
		BN_free(exponent);
		RSA_free(rsa);
		return NULL;
	  }
	  // ownership of rsa struct was assigned, don't free it.
	  BN_free(exponent);
#endif
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeKey(),returning key pair......!!!!");
	  std::cout << "Returning key pair";
	  return pkey;
	}
	
	static X509* MakeCertificate(EVP_PKEY* pkey, const SSLIdentityParams& params) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeCertificate()......!!!!");
	  std::cout << "Making certificate for " << params.common_name;
	  X509* x509 = NULL;
	  BIGNUM* serial_number = NULL;
	  X509_NAME* name = NULL;

	  if ((x509=X509_new()) == NULL)
		goto error;

	  if (!X509_set_pubkey(x509, pkey))
		goto error;

	  // serial number
	  // temporary reference to serial number inside x509 struct
	  ASN1_INTEGER* asn1_serial_number;
	  if ((serial_number = BN_new()) == NULL ||
		  !BN_pseudo_rand(serial_number, SERIAL_RAND_BITS, 0, 0) ||
		  (asn1_serial_number = X509_get_serialNumber(x509)) == NULL ||
		  !BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
		goto error;

	  if (!X509_set_version(x509, 0L))  // version 1
		goto error;

	  // There are a lot of possible components for the name entries. In
	  // our P2P SSL mode however, the certificates are pre-exchanged
	  // (through the secure XMPP channel), and so the certificate
	  // identification is arbitrary. It can't be empty, so we set some
	  // arbitrary common_name. Note that this certificate goes out in
	  // clear during SSL negotiation, so there may be a privacy issue in
	  // putting anything recognizable here.
	  if ((name = X509_NAME_new()) == NULL ||
		  !X509_NAME_add_entry_by_NID(
			  name, NID_commonName, MBSTRING_UTF8,
			  (unsigned char*)params.common_name.c_str(), -1, -1, 0) ||
		  !X509_set_subject_name(x509, name) ||
		  !X509_set_issuer_name(x509, name))
		goto error;

	  if (!X509_gmtime_adj(X509_get_notBefore(x509), params.not_before) ||
		  !X509_gmtime_adj(X509_get_notAfter(x509), params.not_after))
		goto error;

	  if (!X509_sign(x509, pkey, EVP_sha1()))
		goto error;

	  BN_free(serial_number);
	  X509_NAME_free(name);
	  std::cout << "Returning certificate";
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeCertificate(),returning certificate......!!!!");
	  return x509;

	 error:
	  BN_free(serial_number);
	  X509_NAME_free(name);
	  X509_free(x509);
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,MakeCertificate(),inside error......!!!!");
	  return NULL;
	}
	
	static void LogSSLErrors(const String& prefix) {
	  char error_buf[200];
      ULONG err;
	  while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, error_buf, sizeof(error_buf));
		std::cout << prefix << ": " << error_buf << "\n";
	  }
	}
	
	OpenSSLKeyPair* OpenSSLKeyPair::Generate() {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLKeyPair::Generate	()......!!!!");
      EVP_PKEY* pkey = MakeKey();
	  if (!pkey) {
		LogSSLErrors("Generating key pair");
		return NULL;
	  }
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity.cpp,OpenSSLKeyPair::Generate() SUCCESSFUL......!!!!");
	  return new OpenSSLKeyPair(pkey);
	}
	
	OpenSSLKeyPair::~OpenSSLKeyPair() {
	  EVP_PKEY_free(pkey_);
	}
	
	void OpenSSLKeyPair::AddReference() {
	  CRYPTO_add(&pkey_->references, 1, CRYPTO_LOCK_EVP_PKEY);
	}
	
#ifdef _DEBUG
	// Print a certificate to the log, for debugging.
	static void PrintCert(X509* x509) {
        __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,PrintCert().....!!!!");
	  BIO* temp_memory_bio = BIO_new(BIO_s_mem());
	  if (!temp_memory_bio) {
		std::cout << "Failed to allocate temporary memory bio";
		return;
	  }
	  X509_print_ex(temp_memory_bio, x509, XN_FLAG_SEP_CPLUS_SPC, 0);
      BIO_write(temp_memory_bio, "\0", 1);
	  char* buffer;
	  BIO_get_mem_data(temp_memory_bio, &buffer);
      __android_log_print(ANDROID_LOG_INFO,"Tag","Trying to print certi %s",buffer);
	  std::cout << buffer;
	  BIO_free(temp_memory_bio);
	}
#endif

	OpenSSLCertificate* OpenSSLCertificate::Generate(
		OpenSSLKeyPair* key_pair, const SSLIdentityParams& params) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLCertificate::Generate()......!!!!");
	  SSLIdentityParams actual_params(params);
	  if (actual_params.common_name.empty()) {
		// Use a random string, arbitrarily 8chars long.
		actual_params.common_name = openpeer::services::IHelper::convertToBase64("abcdefgh");
	  }
	  X509* x509 = MakeCertificate(key_pair->pkey(), actual_params);
	  if (!x509) {
		LogSSLErrors("Generating certificate");
		return NULL;
	  }
#ifdef _DEBUG
	  PrintCert(x509);
#endif
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLCertificate::Generate() SUCCESSFUL......!!!!");
	  OpenSSLCertificate* ret = new OpenSSLCertificate(x509);
	  X509_free(x509);
	  return ret;
	}

	bool OpenSSLCertificate::GetSignatureDigestAlgorithm(
	String* algorithm) const {
	  return OpenSSLDigest::GetDigestName(
		  EVP_get_digestbyobj(x509_->sig_alg->algorithm), algorithm);
	}

	bool OpenSSLCertificate::ComputeDigest(const String &algorithm,
										   unsigned char *digest,
										   std::size_t size,
										   std::size_t *length) const {
	  return ComputeDigest(x509_, algorithm, digest, size, length);
	}
	
	bool OpenSSLCertificate::ComputeDigest(const X509 *x509,
										   const String &algorithm,	
										   unsigned char *digest,
										   std::size_t size,
										   std::size_t *length) {
	  const EVP_MD *md;
	  unsigned int n;

	  if (!OpenSSLDigest::GetDigestEVP(algorithm, &md))
		return false;

	  if (size < static_cast<size_t>(EVP_MD_size(md)))
		return false;

	  X509_digest(x509, md, digest, &n);

	  *length = n;

	  return true;
	}
	
	OpenSSLCertificate::~OpenSSLCertificate() {
	  X509_free(x509_);
	}


	void OpenSSLCertificate::AddReference() const {
	  ASSERT(x509_ != NULL);
	  CRYPTO_add(&x509_->references, 1, CRYPTO_LOCK_X509);
	}
	
	OpenSSLIdentity* OpenSSLIdentity::GenerateInternal(
		const SSLIdentityParams& params) {
       __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLIdentity::GenerateInternal()!!!!");
	  OpenSSLKeyPair *key_pair = OpenSSLKeyPair::Generate();
	  if (key_pair) {
		OpenSSLCertificate *certificate = OpenSSLCertificate::Generate(
			key_pair, params);
		if (certificate)
		  return new OpenSSLIdentity(key_pair, certificate);
		delete key_pair;
	  }
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLIdentity::GenerateInternal(),Identity generation failed!!!!");
	  std::cout << "Identity generation failed";
	  return NULL;
	}
	
	OpenSSLIdentity* OpenSSLIdentity::Generate(const String& common_name) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,OpenSSLCertificate::Generate()!!!!");
	  SSLIdentityParams params;
	  params.common_name = common_name;
	  params.not_before = CERTIFICATE_WINDOW;
	  params.not_after = CERTIFICATE_LIFETIME;
      return GenerateInternal(params);
	}
	
	OpenSSLIdentity* OpenSSLIdentity::GenerateForTest(
		const SSLIdentityParams& params) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,GenerateForTest()......!!!!");
	  return GenerateInternal(params);
	}


	bool OpenSSLIdentity::ConfigureIdentity(SSL_CTX* ctx) {
      __android_log_write(ANDROID_LOG_INFO,"Tag","Inside ortc_SSLIdentity_feb7.cpp,ConfigureIdentity()......!!!!");
	  if (SSL_CTX_use_certificate(ctx, certificate_->x509()) != 1 ||
		 SSL_CTX_use_PrivateKey(ctx, key_pair_->pkey()) != 1) {
		LogSSLErrors("Configuring key and certificate");
		return false;
	  }
	  return true;
	}
  } //namepsace internal	
}//namespace ortc	
