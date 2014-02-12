#ifndef TALK_BASE_SSLIDENTITY_H_
#define TALK_BASE_SSLIDENTITY_H_

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <ortc/internal/ortc_Helper.h>
#include <string>
#include <zsLib/types.h>
#include <zsLib/Proxy.h>
#include <zsLib/IPAddress.h>
#include <algorithm>
#include <vector>
#include <ortc/internal/types.h>
#include <boost/noncopyable.hpp>

typedef struct ssl_ctx_st SSL_CTX;

#define ARRAY_SIZE(x) (static_cast<DWORD>(sizeof(x) / sizeof(x[0])))

#ifndef UNUSED
#define UNUSED(x) Unused(static_cast<const void*>(&x))
#define UNUSED2(x, y) Unused(static_cast<const void*>(&x)); \
    Unused(static_cast<const void*>(&y))
#define UNUSED3(x, y, z) Unused(static_cast<const void*>(&x)); \
    Unused(static_cast<const void*>(&y)); \
    Unused(static_cast<const void*>(&z))
#define UNUSED4(x, y, z, a) Unused(static_cast<const void*>(&x)); \
    Unused(static_cast<const void*>(&y)); \
    Unused(static_cast<const void*>(&z)); \
    Unused(static_cast<const void*>(&a))
#define UNUSED5(x, y, z, a, b) Unused(static_cast<const void*>(&x)); \
    Unused(static_cast<const void*>(&y)); \
    Unused(static_cast<const void*>(&z)); \
    Unused(static_cast<const void*>(&a)); \
    Unused(static_cast<const void*>(&b))
inline void Unused(const void*) {}
#endif  // UNUSED

#ifndef ASSERT
#define ASSERT(x) \
    (void)ortc::internal::Assert((x), __FUNCTION__, __FILE__, __LINE__, #x)
#endif

#ifndef ASSERT
#define ASSERT(x) (void)0
#endif
    
namespace ortc
{
  using zsLib::string;
  using zsLib::String;
  using zsLib::ULONG;
  using zsLib::UCHAR;
  using zsLib::UINT;
  
  namespace internal
  {
    //// Definitions for the digest algorithms.
	extern const char DIGEST_MD5[];
	extern const char DIGEST_SHA_1[];
	extern const char DIGEST_SHA_224[];
	extern const char DIGEST_SHA_256[];
	extern const char DIGEST_SHA_384[];
	extern const char DIGEST_SHA_512[];
	
	void LogAssert(const char* function, const char* file, DWORD line,
				   const char* expression);
    
	inline bool Assert(bool result, const char* function, const char* file,
						DWORD line, const char* expression) {
	  if (!result) {
		return false;
	  }
	  return true;
	}
	
	static const char BASE64[64] = {
	  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
	};	
	
	// Forward declaration due to circular dependency with SSLCertificate.
	class SSLCertChain;
	
	class MessageDigest {
	 public:
	  enum { kMaxSize = 64 };  // Maximum known size (SHA-512)
	  virtual ~MessageDigest() {}
	  // Returns the digest output size (e.g. 16 bytes for MD5).
	  virtual size_t Size() const = 0;
	  // Updates the digest with |len| bytes from |buf|.
	  virtual void Update(const void* buf, size_t len) = 0;
	  // Outputs the digest value to |buf| with length |len|.
	  // Returns the number of bytes written, i.e., Size().
	  virtual size_t Finish(void* buf, size_t len) = 0;
	};
	
	// A factory class for creating digest objects.
	class MessageDigestFactory {
	 public:
	  static MessageDigest* Create(const String& alg);
	  
	};
	
	// Functions to create hashes.
	size_t ComputeDigest(MessageDigest* digest, const void* input, size_t in_len,
						 void* output, size_t out_len);
	size_t ComputeDigest(const String& alg, const void* input, size_t in_len,
						 void* output, size_t out_len);
	String ComputeDigest(MessageDigest* digest, const String& input);
	String ComputeDigest(const String& alg, const String& input);
	bool ComputeDigest(const String& alg, const String& input,
					   String* output);
	inline String MD5(const String& input) {
	  return ComputeDigest(DIGEST_MD5, input);
	}				   
	
	// Functions to compute RFC 2104 HMACs
	size_t ComputeHmac(MessageDigest* digest, const void* key, size_t key_len,
					   const void* input, size_t in_len,
					   void* output, size_t out_len);
	size_t ComputeHmac(const String& alg, const void* key, size_t key_len,
					   const void* input, size_t in_len,
					   void* output, size_t out_len);
	String ComputeHmac(MessageDigest* digest, const String& key,
							const String& input);
	String ComputeHmac(const String& alg, const String& key,
							const String& input);
	bool ComputeHmac(const String& alg, const String& key,
					 const String& input, String* output);	
					 
	class OpenSSLDigest : public MessageDigest {
	public:
		explicit OpenSSLDigest(const String& algorithm);
		~OpenSSLDigest();
		virtual size_t Size() const;
		virtual void Update(const void* buf, size_t len);
		virtual size_t Finish(void* buf, size_t len);
		static bool GetDigestEVP(const String &algorithm,
							   const EVP_MD** md);
		static bool GetDigestName(const EVP_MD* md,
								String* algorithm);
		static bool GetDigestSize(const String &algorithm,
								size_t* len);
	private:
	  EVP_MD_CTX ctx_;
	  const EVP_MD* md_;
	};  					   
	
	class SSLCertificate {
	public:
		static SSLCertificate* FromPEMString(const String& pem_string);
	    virtual ~SSLCertificate() {}
	    virtual SSLCertificate* GetReference() const = 0;
	    virtual bool GetChain(SSLCertChain** chain) const = 0;
	    virtual bool GetSignatureDigestAlgorithm(String* algorithm) const = 0;
	    virtual bool ComputeDigest(const String &algorithm,
								 unsigned char* digest, std::size_t size,
								 std::size_t* length) const = 0;
								 
	};
	
	class SSLCertChain : private boost::noncopyable {
	public:
		explicit SSLCertChain(const std::vector<SSLCertificate*>& certs) {
		ASSERT(!certs.empty());
		certs_.resize(certs.size());
		std::transform(certs.begin(), certs.end(), certs_.begin(), DupCert);
	  	}
	  	explicit SSLCertChain(const SSLCertificate* cert) {
		certs_.push_back(cert->GetReference());
	  	}
	  	~SSLCertChain() {
		std::for_each(certs_.begin(), certs_.end(), DeleteCert);
	    }
	    size_t GetSize() const { return certs_.size(); }
	    const SSLCertificate& Get(size_t pos) const { return *(certs_[pos]); }
	    SSLCertChain* Copy() const {
		return new SSLCertChain(certs_);
	  	}
	private:
		static SSLCertificate* DupCert(const SSLCertificate* cert) {
		return cert->GetReference();
	  	}
	    static void DeleteCert(SSLCertificate* cert) { delete cert; }
	    std::vector<SSLCertificate*> certs_;

	   
	};  

	struct SSLIdentityParams {
	  	String common_name;
	  	DWORD not_before;  // in seconds.
	  	DWORD not_after;
    };

	class SSLIdentity {
	public:
		static SSLIdentity* Generate(const String& common_name);
		static SSLIdentity* GenerateForTest(const SSLIdentityParams& params);
		virtual ~SSLIdentity() {}	
		virtual SSLIdentity* GetReference() const = 0;
		virtual const SSLCertificate& certificate() const = 0;
    };
    extern const char kPemTypeCertificate[];
	extern const char kPemTypeRsaPrivateKey[];

	class OpenSSLKeyPair : private boost::noncopyable {
	public:
		explicit OpenSSLKeyPair(EVP_PKEY* pkey) : pkey_(pkey) {
		ASSERT(pkey_ != NULL);
	    }
	    static OpenSSLKeyPair* Generate();
	    virtual ~OpenSSLKeyPair();
	    virtual OpenSSLKeyPair* GetReference() {
		AddReference();
		return new OpenSSLKeyPair(pkey_);
	  	}		
	  	EVP_PKEY* pkey() const { return pkey_; }	
	private:
	  	void AddReference();
	  	EVP_PKEY* pkey_;

	};  	
	
	class OpenSSLCertificate : public SSLCertificate, private boost::noncopyable  {
	public:
		explicit OpenSSLCertificate(X509* x509) : x509_(x509) {
		AddReference();
	  	}	
	  	static OpenSSLCertificate* Generate(OpenSSLKeyPair* key_pair,
										  const SSLIdentityParams& params);
		static OpenSSLCertificate* FromPEMString(const String& pem_string);
	    virtual ~OpenSSLCertificate();
	    virtual OpenSSLCertificate* GetReference() const {
		return new OpenSSLCertificate(x509_);
	  	}
	  	X509* x509() const { return x509_; }
	  	virtual bool ComputeDigest(const String &algorithm,
								 unsigned char *digest, std::size_t size,
								 std::size_t *length) const;
	 	static bool ComputeDigest(const X509 *x509,
								const String &algorithm,
								unsigned char *digest,
								std::size_t size,
								std::size_t *length);
		virtual bool GetSignatureDigestAlgorithm(String* algorithm) const;
	  	virtual bool GetChain(SSLCertChain** chain) const {
		return false;
	  }							
	private:
	  	void AddReference() const;
	  	X509* x509_;

	};
	
	class OpenSSLIdentity : public SSLIdentity, private boost::noncopyable {
	public:
		static OpenSSLIdentity* Generate(const String& common_name);
	  	static OpenSSLIdentity* GenerateForTest(const SSLIdentityParams& params);
		virtual ~OpenSSLIdentity() { }
	  	virtual const OpenSSLCertificate& certificate() const {
		return *certificate_;
	  	}
	  	virtual OpenSSLIdentity* GetReference() const {
	  	return new OpenSSLIdentity(key_pair_->GetReference(),
								   certificate_->GetReference());
	  	}
	  	bool ConfigureIdentity(SSL_CTX* ctx);
	private:
	  	OpenSSLIdentity(OpenSSLKeyPair* key_pair,
					  OpenSSLCertificate* certificate)
		  : key_pair_(key_pair), certificate_(certificate) {
		ASSERT(key_pair != NULL);
		ASSERT(certificate != NULL);
	  	}
	  	static OpenSSLIdentity* GenerateInternal(const SSLIdentityParams& params);
	  	boost::shared_ptr<OpenSSLKeyPair> key_pair_;
	  	boost::shared_ptr<OpenSSLCertificate> certificate_;

		};
  }	//namespace
}//ortc	
	
#endif	//TALK_BASE_SSLIDENTITY_H_
											
