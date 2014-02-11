/*

 Copyright (c) 2013, SMB Phone Inc. / Hookflash Inc.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are those
 of the authors and should not be interpreted as representing official policies,
 either expressed or implied, of the FreeBSD Project.
 
 */

//#include <ortc/internal/ortc_DTLSTransport.h>
#include <ortc/internal/ortc_SSLStreamManager.h>
#include <ortc/internal/ortc_RTPReceiver.h>
#include <ortc/internal/ortc_ORTC.h>
#include <zsLib/internal/types.h>

#include <openpeer/services/IHelper.h>

#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>

//openssl include files
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>

#include <vector>
#include <iostream>
#include <string>
#include <unistd.h>

#include "ortc_common.h"
#include "ortc_openssldigest.h"
#include "ortc_opensslidentity.h"
#include "ortc_stringutils.h"
#include "ortc_sslroots.h"

#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()

#if 1
struct CRYPTO_dynlock_value {
	  MUTEX_TYPE mutex;
};
static MUTEX_TYPE* mutex_buf = NULL;
    
static CRYPTO_dynlock_value* dyn_create_function(const char* file, int line) {
      CRYPTO_dynlock_value* value = new CRYPTO_dynlock_value;
      if (!value)
        return NULL;
      MUTEX_SETUP(value->mutex);
      return value;
}

static void dyn_lock_function(int mode, CRYPTO_dynlock_value* l,
                                  const char* file, int line) {
      if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(l->mutex);
      } else {
        MUTEX_UNLOCK(l->mutex);
      }
}

static void dyn_destroy_function(CRYPTO_dynlock_value* l,
                                     const char* file, int line) {
      MUTEX_CLEANUP(l->mutex);
      delete l;
}
#endif

namespace ortc { ZS_DECLARE_SUBSYSTEM(ortclib) }

namespace ortc {
  typedef openpeer::services::IHelper OPIHelper;

  namespace internal
  {
#if (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_SRTP)
    #define HAVE_DTLS_SRTP
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)  && !defined(OPENSSL_NO_DTLS)
    #define HAVE_DTLS
#endif

#ifdef HAVE_DTLS_SRTP
    // SRTP cipher suite table
    struct SrtpCipherMapEntry {
      const char* external_name;
      const char* internal_name;
    };

    // This isn't elegant, but it's better than an external reference
    static SrtpCipherMapEntry SrtpCipherMap[] = {
      {"AES_CM_128_HMAC_SHA1_80", "SRTP_AES128_CM_SHA1_80"},
      {"AES_CM_128_HMAC_SHA1_32", "SRTP_AES128_CM_SHA1_32"},
      {NULL, NULL}
    };
#endif

    //////////////////////////////////////////////////////////////////////
    // StreamBIO
    //////////////////////////////////////////////////////////////////////

    static int stream_write(BIO* h, const char* buf, int num);
    static int stream_read(BIO* h, char* buf, int size);
    static int stream_puts(BIO* h, const char* str);
    static long stream_ctrl(BIO* h, int cmd, long arg1, void* arg2);
    static int stream_new(BIO* h);
    static int stream_free(BIO* data);

    static BIO_METHOD methods_stream = {
      BIO_TYPE_BIO,
      "stream",
      stream_write,
      stream_read,
      stream_puts,
      0,
      stream_ctrl,
      stream_new,
      stream_free,
      NULL,
    };

    static BIO_METHOD* BIO_s_stream() { return(&methods_stream); }

    static BIO* BIO_new_stream(SSLStreamManagerPtr stream) {
      BIO* ret = BIO_new(BIO_s_stream());
      if (ret == NULL)
        return NULL;
      //ret->ptr = stream;
      ret->ptr = static_cast<void *>(stream.get());
      return ret;
    }

    // bio methods return 1 (or at least non-zero) on success and 0 on failure.

    static int stream_new(BIO* b) {
      b->shutdown = 0;
      b->init = 1;
      b->num = 0;  // 1 means end-of-stream
      b->ptr = 0;
      return 1;
    }

    static int stream_free(BIO* b) {
      if (b == NULL)
        return 0;
      return 1;
    }

    static int stream_read(BIO* b, char* out, int outl) {
      if (!out)
        return -1;
      //StreamInterface* stream = static_cast<StreamInterface*>(b->ptr);
    //  SSLStreamManagerWeakPtr sslstream = static_cast<SSLStreamManagerWeakPtr>(b->ptr);
      //SSLStreamManagerPtr sslstream = static_cast<SSLStreamManagerPtr>(b->ptr);
      SSLStreamManagerPtr sslstream = *(SSLStreamManagerPtr*)(b->ptr);
      BIO_clear_retry_flags(b);
      size_t read;
      int error;
      StreamResult result = sslstream->Read(out, outl, &read, &error);
      if (result == SR_SUCCESS) {
        return read;
      } else if (result == SR_EOS) {
        b->num = 1;
      } else if (result == SR_BLOCK) {
        BIO_set_retry_read(b);
      }
      return -1;
    }

    static int stream_write(BIO* b, const char* in, int inl) {
      if (!in)
        return -1;
      //StreamInterface* stream = static_cast<StreamInterface*>(b->ptr);
      //SSLStreamManagerPtr sslstream = static_cast<SSLStreamManagerPtr>(b->ptr);
      SSLStreamManagerPtr sslstream = *(SSLStreamManagerPtr*)(b->ptr);
    //  SSLStreamManagerWeakPtr sslstream = static_cast<SSLStreamManagerWeakPtr>(b->ptr);
      BIO_clear_retry_flags(b);
      size_t written;
      int error;
      StreamResult result = sslstream->Write(in, inl, &written, &error);
      if (result == SR_SUCCESS) {
        return written;
      } else if (result == SR_BLOCK) {
        BIO_set_retry_write(b);
      }
      return -1;
    }

    static int stream_puts(BIO* b, const char* str) {
      return stream_write(b, str, strlen(str));
    }

    static long stream_ctrl(BIO* b, int cmd, long num, void* ptr) {
      UNUSED(num);
      UNUSED(ptr);

      switch (cmd) {
        case BIO_CTRL_RESET:
          return 0;
        case BIO_CTRL_EOF:
          return b->num;
        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
          return 0;
        case BIO_CTRL_FLUSH:
          return 1;
        default:
          return 0;
      }
    }

    //ssl mutex code -- required for ssl initialization code
    // This array will store all of the mutexes available to OpenSSL.
    // _POSIX_THREADS is normally defined in unistd.h if pthreads are available
	// on your platform.
	#define MUTEX_TYPE pthread_mutex_t
	#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
	#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
	#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
	#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
	#define THREAD_ID pthread_self()

    struct CRYPTO_dynlock_value {
	  MUTEX_TYPE mutex;
	};

    static MUTEX_TYPE* mutex_buf = NULL;

    static void locking_function(int mode, int n, const char * file, int line) {
      if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(mutex_buf[n]);
      } else {
        MUTEX_UNLOCK(mutex_buf[n]);
      }
    }

    static unsigned long id_function() {  // NOLINT
      // Use old-style C cast because THREAD_ID's type varies with the platform,
      // in some cases requiring static_cast, and in others requiring
      // reinterpret_cast.
      return (unsigned long)THREAD_ID; // NOLINT
    }
#if 0
    static CRYPTO_dynlock_value* dyn_create_function(const char* file, int line) {
      CRYPTO_dynlock_value* value = new CRYPTO_dynlock_value;
      if (!value)
        return NULL;
      MUTEX_SETUP(value->mutex);
      return value;
    }

    static void dyn_lock_function(int mode, CRYPTO_dynlock_value* l,
                                  const char* file, int line) {
      if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(l->mutex);
      } else {
        MUTEX_UNLOCK(l->mutex);
      }
    }

    static void dyn_destroy_function(CRYPTO_dynlock_value* l,
                                     const char* file, int line) {
      MUTEX_CLEANUP(l->mutex);
      delete l;
    }
#endif
    //VerificationCallback OpenSSLAdapter::custom_verify_callback_ = NULL;

    //bool SSLStreamManager::InitializeSSL(VerificationCallback callback) {
    bool SSLStreamManager::InitializeSSL() {
      if (!InitializeSSLThread() || !SSL_library_init())
          return false;
    #if !defined(ADDRESS_SANITIZER) || !defined(OSX)
      // Loading the error strings crashes mac_asan.  Omit this debugging aid there.
      SSL_load_error_strings();
    #endif
      ERR_load_BIO_strings();
      OpenSSL_add_all_algorithms();
      RAND_poll();
      //custom_verify_callback_ = callback;
      return true;
    }

    bool SSLStreamManager::InitializeSSLThread() {
      mutex_buf = new MUTEX_TYPE[CRYPTO_num_locks()];
      if (!mutex_buf)
        return false;
      for (int i = 0; i < CRYPTO_num_locks(); ++i)
        MUTEX_SETUP(mutex_buf[i]);

      // we need to cast our id_function to return an unsigned long -- pthread_t is
      // a pointer
      CRYPTO_set_id_callback(id_function);
      CRYPTO_set_locking_callback(locking_function);
      CRYPTO_set_dynlock_create_callback(dyn_create_function);
      CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
      CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
      return true;
    }

    bool SSLStreamManager::CleanupSSL() {
      if (!mutex_buf)
        return false;
      CRYPTO_set_id_callback(NULL);
      CRYPTO_set_locking_callback(NULL);
      CRYPTO_set_dynlock_create_callback(NULL);
      CRYPTO_set_dynlock_lock_callback(NULL);
      CRYPTO_set_dynlock_destroy_callback(NULL);
      for (int i = 0; i < CRYPTO_num_locks(); ++i)
        MUTEX_CLEANUP(mutex_buf[i]);
      delete [] mutex_buf;
      mutex_buf = NULL;
      return true;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark (helpers)
    #pragma mark


    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager
    #pragma mark
    
    //-------------------------------------------------------------------------
    SSLStreamManager::SSLStreamManager(
                                 IMessageQueuePtr queue,
                                 ISSLStreamManagerDelegatePtr originalDelegate
                                 //ITransportStreamPtr transportStream
                                 ) :
      MessageQueueAssociator(queue),
      mCurrentState(SSLConnectionState_None),
      //mTransportStream(openpeer::services::ITransportStream::convert(transportStream)),
      //state_(SSL_NONE),
      role_(SSL_CLIENT),
      ssl_read_needs_write_(false), ssl_write_needs_read_(false),
      ssl_(NULL), ssl_ctx_(NULL),
      //custom_verification_succeeded_(false),
      //ignore_bad_cert_(false),
      ssl_mode_(SSL_MODE_TLS){
      ZS_LOG_DETAIL(debug("created"))

      mDefaultSubscription = mSubscriptions.subscribe(ISSLStreamManagerDelegateProxy::create(IORTCForInternal::queueDelegate(), originalDelegate), queue);
    }

    //-------------------------------------------------------------------------
    void SSLStreamManager::init()
    {
      mTransportStream =  openpeer::services::ITransportStream::create(mThisWeak.lock(),mThisWeak.lock());
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    SSLStreamManager::~SSLStreamManager()
    {
      if (isNoop()) return;

      ZS_LOG_DETAIL(log("destroyed"))
      mThisWeak.reset();

      //jingle api
      Cleanup();

      cancel();
    }

    //-------------------------------------------------------------------------
    SSLStreamManagerPtr SSLStreamManager::convert(ISSLStreamManagerPtr object)
    {
      return boost::dynamic_pointer_cast<SSLStreamManager>(object);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager => ISSLStreamManager
    #pragma mark
    
    //-------------------------------------------------------------------------
    ElementPtr SSLStreamManager::toDebug(ISSLStreamManagerPtr transport)
    {
      if (!transport) return ElementPtr();
      SSLStreamManagerPtr pThis = SSLStreamManager::convert(transport);
      return pThis->toDebug();
    }

    //-------------------------------------------------------------------------
    SSLStreamManagerPtr SSLStreamManager::create(
                                           ISSLStreamManagerDelegatePtr delegate
                                           //ITransportStreamPtr transportStream
                                           )
    {
      //SSLStreamManagerPtr pThis(new SSLStreamManager(IORTCForInternal::queueORTC(), delegate, transportStream));
      SSLStreamManagerPtr pThis(new SSLStreamManager(IORTCForInternal::queueORTC(), delegate));
      pThis->mThisWeak.lock();
      pThis->init();
      return pThis;
    }

    //-------------------------------------------------------------------------
    PUID SSLStreamManager::getID() const
    {
      return mID;
    }

    //-------------------------------------------------------------------------
    ISSLStreamManagerSubscriptionPtr SSLStreamManager::subscribe(ISSLStreamManagerDelegatePtr originalDelegate)
    {
      ZS_LOG_DETAIL(log("subscribing to transport state"))

      AutoRecursiveLock lock(getLock());
      if (!originalDelegate) return mDefaultSubscription;

      ISSLStreamManagerSubscriptionPtr subscription = mSubscriptions.subscribe(ISSLStreamManagerDelegateProxy::create(IORTCForInternal::queueDelegate(), originalDelegate));

      ISSLStreamManagerDelegatePtr delegate = mSubscriptions.delegate(subscription);

      if (delegate) {
        SSLStreamManagerPtr pThis = mThisWeak.lock();

        if (SSLConnectionState_None != mCurrentState) {
          delegate->onSSLStreamStateChanged(pThis, mCurrentState);
        }
      }

      if (isShutdown()) {
        mSubscriptions.clear();
      }

      return subscription;
    }

    //-------------------------------------------------------------------------
    ISSLStreamManager::CapabilitiesPtr SSLStreamManager::getCapabilities()
    {
      return CapabilitiesPtr();
    }

    //-------------------------------------------------------------------------
    ISSLStreamManager::SSLConnectionStates SSLStreamManager::getState(
                                                           WORD *outError,
                                                           String *outReason
                                                           )
    {
      AutoRecursiveLock lock(getLock());

      ZS_LOG_DEBUG(log("get state") + ZS_PARAM("current state", ISSLStreamManager::toString(mCurrentState)) + ZS_PARAM("error", mLastError) + ZS_PARAM("reason", mLastErrorReason))

      if (outError) {
        *outError = mLastError;
      }
      if (outReason) {
        *outReason = mLastErrorReason;
      }

      return mCurrentState;
    }
#if 1  //TBD -- Need to check compilation issue
    ISSLStreamManager::ITransportStreamPtr SSLStreamManager::getSSLTransportStream()
    {
    	return mTransportStream;
    }
#endif
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager => IWakeDelegate
    #pragma mark

    //-------------------------------------------------------------------------
    void SSLStreamManager::onWake()
    {
      ZS_LOG_DEBUG(log("wake"))

      step(); // do not call within lock
    }

    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager => ITransportStreamWriterDelegate
    #pragma mark

    //-----------------------------------------------------------------------
    void SSLStreamManager::onTransportStreamWriterReady(ITransportStreamWriterPtr writer)
    {
      AutoRecursiveLock lock(mLock);
      ZS_LOG_TRACE(log("on transport stream outer receive ready"))
      //mWireReceiveStream->notifyReaderReadyToRead();
      //get(mInformedWireSendReady) = true;
      //step();
    }

    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager => ITransportStreamReaderDelegate
    #pragma mark

    //-----------------------------------------------------------------------
    void SSLStreamManager::onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
    {
      AutoRecursiveLock lock(mLock);
      ZS_LOG_TRACE(log("on transport stream reader ready"))
      //step();
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager => (internal)
    #pragma mark

    //-------------------------------------------------------------------------
    Log::Params SSLStreamManager::log(const char *message) const
    {
      ElementPtr objectEl = Element::create("ortc::SSLStreamManager");
      OPIHelper::debugAppend(objectEl, "id", mID);
      return Log::Params(message, objectEl);
    }

    //-------------------------------------------------------------------------
    Log::Params SSLStreamManager::debug(const char *message) const
    {
      return Log::Params(message, toDebug());
    }

    //-------------------------------------------------------------------------
    ElementPtr SSLStreamManager::toDebug() const
    {
      ElementPtr resultEl = Element::create("ortc::SSLStreamManager");

      OPIHelper::debugAppend(resultEl, "id", mID);

      OPIHelper::debugAppend(resultEl, "graceful shutdown", (bool)mGracefulShutdownReference);

      OPIHelper::debugAppend(resultEl, "subscribers", mSubscriptions.size());
      OPIHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

      OPIHelper::debugAppend(resultEl, "state", ISSLStreamManager::toString(mCurrentState));
      OPIHelper::debugAppend(resultEl, "start called", mStartCalled);

      OPIHelper::debugAppend(resultEl, "error", mLastError);
      OPIHelper::debugAppend(resultEl, "error reason", mLastErrorReason);

      return resultEl;
    }

    //-------------------------------------------------------------------------
    bool SSLStreamManager::isShuttingDown() const
    {
      return (bool)mGracefulShutdownReference;
    }

    //-------------------------------------------------------------------------
    bool SSLStreamManager::isShutdown() const
    {
      if (mGracefulShutdownReference) return false;
      return SSLConnectionState_Closed == mCurrentState;
    }

    //-------------------------------------------------------------------------
    //step the state of sslstreammanager
    void SSLStreamManager::step()
    {
      ZS_LOG_DEBUG(debug("step"))
      {
        AutoRecursiveLock lock(getLock());

        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_DEBUG(debug("step forwarding to cancel"))
          cancel();
          return;
        }
      }

    }

    //-------------------------------------------------------------------------
    void SSLStreamManager::cancel()
    {
      //.......................................................................
      // start the shutdown process
      //.......................................................................
      // try to gracefully shutdown

      if (!mGracefulShutdownReference) mGracefulShutdownReference = mThisWeak.lock();

      setState(SSLConnectionState_Closed);

      // make sure to cleanup any final reference to self
      mGracefulShutdownReference.reset();

    }

    //-------------------------------------------------------------------------
    void SSLStreamManager::setState(SSLConnectionStates state)
    {
      if (state == mCurrentState) return;

      ZS_LOG_DETAIL(debug("state changed") + ZS_PARAM("old state", ISSLStreamManager::toString(mCurrentState)) + ZS_PARAM("new state", state))

      mCurrentState = state;

      SSLStreamManagerPtr pThis = mThisWeak.lock();
      if (pThis) {
        mSubscriptions.delegate()->onSSLStreamStateChanged(pThis, mCurrentState);
      }
    }

    //-------------------------------------------------------------------------
    void SSLStreamManager::setError(WORD errorCode, const char *inReason)
    {
      String reason(inReason);
      if (reason.isEmpty()) {
        reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
      }

      if (0 != mLastError) {
        ZS_LOG_WARNING(Detail, debug("error already set thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
        return;
      }

      get(mLastError) = errorCode;
      mLastErrorReason = reason;
      
      setState(SSLConnectionState_Error);
      
      ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("error", mLastError) + ZS_PARAM("reason", mLastErrorReason))
    }

	 //libjingle api's implemenattion
	  void SSLStreamManager::SetIdentity(SSLIdentity* identity) {
		ASSERT(!identity_);
		identity_.reset(static_cast<OpenSSLIdentity*>(identity));
	  }

	  void SSLStreamManager::SetServerRole(SSLRole role) {
		role_ = role;
	  }

	  void SSLStreamManager::SetPeerCertificate(SSLCertificate* cert) {
		ASSERT(!peer_certificate_);
		ASSERT(peer_certificate_digest_algorithm_.empty());
		ASSERT(ssl_server_name_.empty());
		peer_certificate_.reset(static_cast<OpenSSLCertificate*>(cert));
	  }

	  bool SSLStreamManager::GetPeerCertificate(SSLCertificate** cert) const {
		if (!peer_certificate_)
		  return false;

		*cert = peer_certificate_->GetReference();
		return true;
	  }

	  bool SSLStreamManager::SetPeerCertificateDigest(const std::string
														  &digest_alg,
														  const unsigned char*
														  digest_val,
														  size_t digest_len) {
		ASSERT(!peer_certificate_);
		ASSERT(peer_certificate_digest_algorithm_.size() == 0);
		ASSERT(ssl_server_name_.empty());
		size_t expected_len;

		if (!OpenSSLDigest::GetDigestSize(digest_alg, &expected_len)) {
		  std::cout << "Unknown digest algorithm: " << digest_alg;
		  return false;
		}
		if (expected_len != digest_len)
		  return false;

		peer_certificate_digest_value_.SetData(digest_val, digest_len);
		peer_certificate_digest_algorithm_ = digest_alg;

		return true;
	  }

	  // Key Extractor interface
	  bool SSLStreamManager::ExportKeyingMaterial(const std::string& label,
													  const uint8* context,
													  size_t context_len,
													  bool use_context,
													  uint8* result,
													  size_t result_len) {
	  #ifdef HAVE_DTLS_SRTP
		int i;

		i = SSL_export_keying_material(ssl_, result, result_len,
									   label.c_str(), label.length(),
									   const_cast<uint8 *>(context),
									   context_len, use_context);

		if (i != 1)
		  return false;

		return true;
	  #else
		return false;
	  #endif
	  }

	  bool SSLStreamManager::SetDtlsSrtpCiphers(
		  const std::vector<std::string>& ciphers) {
		std::string internal_ciphers;

		if (mCurrentState != SSLConnectionState_None)
		  return false;

	  #ifdef HAVE_DTLS_SRTP
		for (std::vector<std::string>::const_iterator cipher = ciphers.begin();
			 cipher != ciphers.end(); ++cipher) {
		  bool found = false;
		  for (SrtpCipherMapEntry *entry = SrtpCipherMap; entry->internal_name;
			   ++entry) {
			if (*cipher == entry->external_name) {
			  found = true;
			  if (!internal_ciphers.empty())
				internal_ciphers += ":";
			  internal_ciphers += entry->internal_name;
			  break;
			}
		  }

		  if (!found) {
			std::cout << "Could not find cipher: " << *cipher;
			return false;
		  }
		}

		if (internal_ciphers.empty())
		  return false;

		srtp_ciphers_ = internal_ciphers;
		return true;
	  #else
		return false;
	  #endif
	  }

	  bool SSLStreamManager::GetDtlsSrtpCipher(std::string* cipher) {
	  #ifdef HAVE_DTLS_SRTP
		ASSERT(mCurrentState == SSLConnectionState_Connected);
		if (mCurrentState != SSLConnectionState_Connected)
		  return false;

		SRTP_PROTECTION_PROFILE *srtp_profile =
			SSL_get_selected_srtp_profile(ssl_);

		if (!srtp_profile)
		  return false;

		for (SrtpCipherMapEntry *entry = SrtpCipherMap;
			 entry->internal_name; ++entry) {
		  if (!strcmp(entry->internal_name, srtp_profile->name)) {
			*cipher = entry->external_name;
			return true;
		  }
		}

		ASSERT(false);  // This should never happen

		return false;
	  #else
		return false;
	  #endif
	  }

	  int SSLStreamManager::StartSSLWithServer(const char* server_name) {
		ASSERT(server_name != NULL && server_name[0] != '\0');
		ssl_server_name_ = server_name;
		return StartSSL();
	  }

	  int SSLStreamManager::StartSSLWithPeer() {
		ASSERT(ssl_server_name_.empty());
		// It is permitted to specify peer_certificate_ only later.
		return StartSSL();
	  }

	  void SSLStreamManager::SetMode(SSLMode mode) {
		ASSERT(mCurrentState == SSLConnectionState_None);
		ssl_mode_ = mode;
	  }

	  //
	  // StreamInterface Implementation
	  //

	  StreamResult SSLStreamManager::Write(const void* data, size_t data_len,
											   size_t* written, int* error) {
		std::cout << "SSLStreamManager::Write(" << data_len << ")" << std::endl;

		switch (mCurrentState) {
		case SSLConnectionState_None:
		  // pass-through in clear text
		  //return StreamAdapterInterface::Write(data, data_len, written, error);
		  return SR_BLOCK;
		case SSLConnectionState_Wait:
		case SSLConnectionState_Connecting:
		  return SR_BLOCK;
		case SSLConnectionState_Connected:
		  break;
		case SSLConnectionState_Error:
		case SSLConnectionState_Closed:
		default:
		  if (error)
			*error = ssl_error_code_;
		  return SR_ERROR;
		}

		// OpenSSL will return an error if we try to write zero bytes
		if (data_len == 0) {
		  if (written)
			*written = 0;
		  return SR_SUCCESS;
		}

		ssl_write_needs_read_ = false;

		int code = SSL_write(ssl_, data, data_len);
		int ssl_error = SSL_get_error(ssl_, code);
		switch (ssl_error) {
		case SSL_ERROR_NONE:
		  std::cout << " -- success"<< std::endl;
		  ASSERT(0 < code && static_cast<unsigned>(code) <= data_len);
		  if (written)
			*written = code;
		  return SR_SUCCESS;
		case SSL_ERROR_WANT_READ:
		  std::cout << " -- error want read" << std::endl;
		  ssl_write_needs_read_ = true;
		  return SR_BLOCK;
		case SSL_ERROR_WANT_WRITE:
		  std::cout << " -- error want write" << std::endl;
		  return SR_BLOCK;

		case SSL_ERROR_ZERO_RETURN:
		default:
		  Error("SSL_write", (ssl_error ? ssl_error : -1), false);
		  if (error)
			*error = ssl_error_code_;
		  return SR_ERROR;
		}
		// not reached
	  }

	  StreamResult SSLStreamManager::Read(void* data, size_t data_len,
											  size_t* read, int* error) {
		std::cout << "SSLStreamManager::Read(" << data_len << ")" << std::endl;
		switch (mCurrentState) {
		  case SSLConnectionState_None:
			// pass-through in clear text
			//return StreamAdapterInterface::Read(data, data_len, read, error);
			  return SR_BLOCK;
		  case SSLConnectionState_Wait:
		  case SSLConnectionState_Connecting:
			return SR_BLOCK;

		  case SSLConnectionState_Connected:
			break;

		  case SSLConnectionState_Closed:
			return SR_EOS;

		  case SSLConnectionState_Error:
		  default:
			if (error)
			  *error = ssl_error_code_;
			return SR_ERROR;
		}

		// Don't trust OpenSSL with zero byte reads
		if (data_len == 0) {
		  if (read)
			*read = 0;
		  return SR_SUCCESS;
		}

		ssl_read_needs_write_ = false;

		int code = SSL_read(ssl_, data, data_len);
		int ssl_error = SSL_get_error(ssl_, code);
		switch (ssl_error) {
		  case SSL_ERROR_NONE:
			std::cout << " -- success" << std::endl;
			ASSERT(0 < code && static_cast<unsigned>(code) <= data_len);
			if (read)
			  *read = code;

			if (ssl_mode_ == SSL_MODE_DTLS) {
			  // Enforce atomic reads -- this is a short read
			  unsigned int pending = SSL_pending(ssl_);

			  if (pending) {
				std::cout << " -- short DTLS read. flushing" << std::endl;
				FlushInput(pending);
				if (error)
				  *error = SSE_MSG_TRUNC;
				return SR_ERROR;
			  }
			}
			return SR_SUCCESS;
		  case SSL_ERROR_WANT_READ:
			std::cout << " -- error want read" << std::endl;
			return SR_BLOCK;
		  case SSL_ERROR_WANT_WRITE:
			std::cout << " -- error want write"<< std::endl;
			ssl_read_needs_write_ = true;
			return SR_BLOCK;
		  case SSL_ERROR_ZERO_RETURN:
			std::cout << " -- remote side closed" << std::endl;
			return SR_EOS;
			break;
		  default:
			std::cout << " -- error " << code << std::endl;
			Error("SSL_read", (ssl_error ? ssl_error : -1), false);
			if (error)
			  *error = ssl_error_code_;
			return SR_ERROR;
		}
		// not reached
	  }


	  void SSLStreamManager::FlushInput(unsigned int left)
	  {
	    unsigned char buf[2048];

	    while (left) {
	      // This should always succeed
	      int toread = (sizeof(buf) < left) ? sizeof(buf) : left;
	      int code = SSL_read(ssl_, buf, toread);

	      int ssl_error = SSL_get_error(ssl_, code);
	      ASSERT(ssl_error == SSL_ERROR_NONE);

	      if (ssl_error != SSL_ERROR_NONE) {
	        std::cout << " -- error " << code;
	        Error("SSL_read", (ssl_error ? ssl_error : -1), false);
	        return;
	      }

	      std::cout << " -- flushed " << code << " bytes";
	      left -= code;
	    }
	  }


	  void SSLStreamManager::Close() {
		Cleanup();
		ASSERT(mCurrentState == SSLConnectionState_Closed || mCurrentState == SSLConnectionState_Error);
		//openpeer::services::ITransportStreamReader::cancel();
		//openpeer::services::ITransportStreamWriter::cancel();
		 setState(SSLConnectionState_Closed);
	  }

	////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////
	///private api's
	///////////////////////////////////////////////////////////////////

	  int SSLStreamManager::StartSSL() {
		ASSERT(mCurrentState == SSLConnectionState_None);

		//if (GetState() != SS_OPEN) {
#if 0 //TBD -- Need to be checked
		if (mCurrentState != SSLConnectionState_Connected) {
		  //mCurrentState = SSLConnectionState_Wait;
		  setState(SSLConnectionState_Wait);
		  return 0;
		}
#endif

		//state_ = SSL_CONNECTING;
		setState(SSLConnectionState_Connecting);
		if (int err = BeginSSL()) {
		  Error("BeginSSL", err, false);
		  return err;
		}

		return 0;
	  }

	  int SSLStreamManager::BeginSSL() {
		ASSERT(mCurrentState == SSL_CONNECTING);
		// The underlying stream has open. If we are in peer-to-peer mode
		// then a peer certificate must have been specified by now.

		//InitializeSSL(NULL);
		InitializeSSL();

		ASSERT(!ssl_server_name_.empty() ||
			   peer_certificate_ ||
			   !peer_certificate_digest_algorithm_.empty());
		std::cout << "BeginSSL: "
					 << (!ssl_server_name_.empty() ? ssl_server_name_ :
													 "with peer");

		BIO* bio = NULL;

		// First set up the context
		ASSERT(ssl_ctx_ == NULL);
		ssl_ctx_ = SetupSSLContext();
		if (!ssl_ctx_)
		  return -1;

		//bio = BIO_new_stream(static_cast<StreamInterface*>(stream()));
		bio = BIO_new_stream(mThisWeak.lock());
		if (!bio)
		  return -1;

		ssl_ = SSL_new(ssl_ctx_);
		if (!ssl_) {
		  BIO_free(bio);
		  return -1;
		}

		SSL_set_app_data(ssl_, this);

		SSL_set_bio(ssl_, bio, bio);  // the SSL object owns the bio now.

		SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		// Do the connect
		return ContinueSSL();
	  }

	  int SSLStreamManager::ContinueSSL() {
		std::cout << "ContinueSSL" << std::endl;
		ASSERT(mCurrentState == SSLConnectionState_Connecting);

		// Clear the DTLS timer
#if 0
		Thread::Current()->Clear(this, MSG_TIMEOUT);
#endif

		int code = (role_ == SSL_CLIENT) ? SSL_connect(ssl_) : SSL_accept(ssl_);
		int ssl_error;
		switch (ssl_error = SSL_get_error(ssl_, code)) {
		  case SSL_ERROR_NONE:
			std::cout << " -- success" << std::endl;

			if (!SSLPostConnectionCheck(ssl_, ssl_server_name_.c_str(),
										peer_certificate_ ?
											peer_certificate_->x509() : NULL,
										peer_certificate_digest_algorithm_)) {
			  std::cout << "TLS post connection check failed";
			  return -1;
			}

			//mCurrentState = SSL_CONNECTED;
			setState(SSLConnectionState_Connected);
			break;

		  case SSL_ERROR_WANT_READ: {
			  std::cout << " -- error want read" << std::endl;
	#if 0
	  #ifdef HAVE_DTLS
			  struct timeval timeout;
			  if (DTLSv1_get_timeout(ssl_, &timeout)) {
				int delay = timeout.tv_sec * 1000 + timeout.tv_usec/1000;

				Thread::Current()->PostDelayed(delay, this, MSG_TIMEOUT, 0);
			  }
	  #endif
	#endif
			}
			break;

		  case SSL_ERROR_WANT_WRITE:
			std::cout << " -- error want write" << std::endl;
			break;

		  case SSL_ERROR_ZERO_RETURN:
		  default:
			std::cout << " -- error " << code << std::endl;
			return (ssl_error != 0) ? ssl_error : -1;
		}

		return 0;
	  }

	  void SSLStreamManager::Error(const char* context, int err, bool signal) {
		std::cout << "SSLStreamManager::Error("
						<< context << ", " << err << ")" << std::endl;
		//mCurrentState = SSL_ERROR;
		setState(SSLConnectionState_Error);
		ssl_error_code_ = err;
		Cleanup();
	  }

	  void SSLStreamManager::Cleanup() {
		std::cout << "Cleanup";

		if (mCurrentState != SSLConnectionState_Error) {
		  //mCurrentState = SSL_CLOSED;
			setState(SSLConnectionState_Closed);
			ssl_error_code_ = 0;
		}

		if (ssl_) {
		  SSL_free(ssl_);
		  ssl_ = NULL;
		}
		if (ssl_ctx_) {
		  SSL_CTX_free(ssl_ctx_);
		  ssl_ctx_ = NULL;
		}
		identity_.reset();
		peer_certificate_.reset();

	#if 0
		// Clear the DTLS timer
		Thread::Current()->Clear(this, MSG_TIMEOUT);
	#endif
	  }

	#if 0
	  void SSLStreamManager::OnMessage(Message* msg) {
		// Process our own messages and then pass others to the superclass
		if (MSG_TIMEOUT == msg->message_id) {
		  std::cout << "DTLS timeout expired";
	  #ifdef HAVE_DTLS
		  DTLSv1_handle_timeout(ssl_);
	  #endif
		  ContinueSSL();
		} else {
		  StreamInterface::OnMessage(msg);
		}
	  }
	#endif

	  SSL_CTX* SSLStreamManager::SetupSSLContext() {
		SSL_CTX *ctx = NULL;

		if (role_ == SSL_CLIENT) {
	  #ifdef HAVE_DTLS
		  ctx = SSL_CTX_new(ssl_mode_ == SSL_MODE_DTLS ?
			  DTLSv1_client_method() : TLSv1_client_method());
	  #else
		  ctx = SSL_CTX_new(TLSv1_client_method());
	  #endif
		} else {
	  #ifdef HAVE_DTLS
		  ctx = SSL_CTX_new(ssl_mode_ == SSL_MODE_DTLS ?
			  DTLSv1_server_method() : TLSv1_server_method());
	  #else
		  ctx = SSL_CTX_new(TLSv1_server_method());
	  #endif
		}
		if (ctx == NULL)
		  return NULL;

		if (identity_ && !identity_->ConfigureIdentity(ctx)) {
		  SSL_CTX_free(ctx);
		  return NULL;
		}

		if (!peer_certificate_) {  // traditional mode
		  // Add the root cert to the SSL context
		  if (!ConfigureTrustedRootCertificates(ctx)) {
			SSL_CTX_free(ctx);
			return NULL;
		  }
		}

		if (peer_certificate_ && role_ == SSL_SERVER)
		  // we must specify which client cert to ask for
		  SSL_CTX_add_client_CA(ctx, peer_certificate_->x509());

	  #ifdef _DEBUG
		SSL_CTX_set_info_callback(ctx, SSLInfoCallback);
	  #endif

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						   SSLVerifyCallback);
		SSL_CTX_set_verify_depth(ctx, 4);
		SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	  #ifdef HAVE_DTLS_SRTP
		if (!srtp_ciphers_.empty()) {
		  if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_ciphers_.c_str())) {
			SSL_CTX_free(ctx);
			return NULL;
		  }
		}
	  #endif

		return ctx;
	  }

	#ifdef _DEBUG
	  void SSLStreamManager::SSLInfoCallback(const SSL* s, int where, int ret) {
		const char* str = "undefined";
		int w = where & ~SSL_ST_MASK;
		if (w & SSL_ST_CONNECT) {
		  str = "SSL_connect";
		} else if (w & SSL_ST_ACCEPT) {
		  str = "SSL_accept";
		}
		if (where & SSL_CB_LOOP) {
		  std::cout <<  str << ":" << SSL_state_string_long(s) << std::endl;
		} else if (where & SSL_CB_ALERT) {
		  str = (where & SSL_CB_READ) ? "read" : "write";
		  std::cout <<  "SSL3 alert " << str
			<< ":" << SSL_alert_type_string_long(ret)
			<< ":" << SSL_alert_desc_string_long(ret);
		} else if (where & SSL_CB_EXIT) {
		  if (ret == 0) {
			std::cout << str << ":failed in " << SSL_state_string_long(s);
		  } else if (ret < 0) {
			  std::cout << str << ":error in " << SSL_state_string_long(s);
		  }
		}
	  }

	  #endif  // _DEBUG


	  int SSLStreamManager::SSLVerifyCallback(int ok, X509_STORE_CTX* store) {
	  #if _DEBUG
		if (!ok) {
		  char data[256];
		  X509* cert = X509_STORE_CTX_get_current_cert(store);
		  int depth = X509_STORE_CTX_get_error_depth(store);
		  int err = X509_STORE_CTX_get_error(store);

		  std::cout << "Error with certificate at depth: " << depth;
		  X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
		  std::cout << "  issuer  = " << data;
		  X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
		  std::cout << "  subject = " << data;
		  std::cout << "  err     = " << err
			<< ":" << X509_verify_cert_error_string(err);
		}
	  #endif

		// Get our SSL structure from the store
		SSL* ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(
											  store,
											  SSL_get_ex_data_X509_STORE_CTX_idx()));

		SSLStreamManager* stream =
		  reinterpret_cast<SSLStreamManager*>(SSL_get_app_data(ssl));

		// In peer-to-peer mode, no root cert / certificate authority was
		// specified, so the libraries knows of no certificate to accept,
		// and therefore it will necessarily call here on the first cert it
		// tries to verify.
		if (!ok && stream->peer_certificate_) {
		  X509* cert = X509_STORE_CTX_get_current_cert(store);
		  int err = X509_STORE_CTX_get_error(store);
		  // peer-to-peer mode: allow the certificate to be self-signed,
		  // assuming it matches the cert that was specified.
		  if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
			  X509_cmp(cert, stream->peer_certificate_->x509()) == 0) {
			std::cout << "Accepted self-signed peer certificate authority";
			ok = 1;
		  }
		} else if (!ok && !stream->peer_certificate_digest_algorithm_.empty()) {
		  X509* cert = X509_STORE_CTX_get_current_cert(store);
		  int err = X509_STORE_CTX_get_error(store);

		  // peer-to-peer mode: allow the certificate to be self-signed,
		  // assuming it matches the digest that was specified.
		  if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
			unsigned char digest[EVP_MAX_MD_SIZE];
			std::size_t digest_length;

			if (OpenSSLCertificate::
			   ComputeDigest(cert,
							 stream->peer_certificate_digest_algorithm_,
							 digest, sizeof(digest),
							 &digest_length)) {
			  Buffer computed_digest(digest, digest_length);
			  if (computed_digest == stream->peer_certificate_digest_value_) {
				std::cout <<
					"Accepted self-signed peer certificate authority";
				ok = 1;

				// Record the peer's certificate.
				stream->peer_certificate_.reset(new OpenSSLCertificate(cert));
			  }
			}
		  }
		}
	#if 0
		else if (!ok && OpenSSLAdapter::custom_verify_callback_) {
		  // this applies only in traditional mode
		  void* cert =
			  reinterpret_cast<void*>(X509_STORE_CTX_get_current_cert(store));
		  if (OpenSSLAdapter::custom_verify_callback_(cert)) {
			stream->custom_verification_succeeded_ = true;
			std::cout << "validated certificate using custom callback";
			ok = 1;
		  }
		}

		if (!ok && stream->ignore_bad_cert()) {
		  std::cout << "Ignoring cert error while verifying cert chain";
		  ok = 1;
		}
	#endif
		return ok;
	  }

	  bool SSLStreamManager::SSLPostConnectionCheck(SSL* ssl,
														const char* server_name,
														const X509* peer_cert,
														const std::string &peer_digest)
	  {
		ASSERT(server_name != NULL);
		bool ok;
		if (server_name[0] != '\0') {  // traditional mode
		  //ok = VerifyServerName(ssl, server_name, ignore_bad_cert());
			ok = VerifyServerName(ssl, server_name);

		  if (ok) {
			//ok = (SSL_get_verify_result(ssl) == X509_V_OK ||
			  //    custom_verification_succeeded_);
			  ok = (SSL_get_verify_result(ssl) == X509_V_OK) ;
		  }
		} else {  // peer-to-peer mode
		  ASSERT((peer_cert != NULL) || (!peer_digest.empty()));
		  // no server name validation
		  ok = true;
		}

	  //if (!ok && ignore_bad_cert()) {
		if (!ok) {
		  std::cout << "SSL_get_verify_result(ssl) = "
						<< SSL_get_verify_result(ssl);
		  std::cout << "Other TLS post connection checks failed.";
		  ok = true;
		}

		return ok;
	  }

	  //bool SSLStreamManager::VerifyServerName(SSL* ssl, const char* host,
		//                                    bool ignore_bad_cert) {
	  bool SSLStreamManager::VerifyServerName(SSL* ssl, const char* host){

		if (!host)
		  return false;

		// Checking the return from SSL_get_peer_certificate here is not strictly
		// necessary.  With our setup, it is not possible for it to return
		// NULL.  However, it is good form to check the return.
		X509* certificate = SSL_get_peer_certificate(ssl);
		if (!certificate)
		  return false;

		// Logging certificates is extremely verbose. So it is disabled by default.
	  #ifdef LOG_CERTIFICATES
		{
		  std::cout << "Certificate from server:";
		  BIO* mem = BIO_new(BIO_s_mem());
		  X509_print_ex(mem, certificate, XN_FLAG_SEP_CPLUS_SPC, X509_FLAG_NO_HEADER);
		  BIO_write(mem, "\0", 1);
		  char* buffer;
		  BIO_get_mem_data(mem, &buffer);
		  std::cout << buffer;
		  BIO_free(mem);

		  char* cipher_description =
			SSL_CIPHER_description(SSL_get_current_cipher(ssl), NULL, 128);
		  std::cout << "Cipher: " << cipher_description;
		  OPENSSL_free(cipher_description);
		}
	  #endif

		bool ok = false;
		int extension_count = X509_get_ext_count(certificate);
		for (int i = 0; i < extension_count; ++i) {
		  X509_EXTENSION* extension = X509_get_ext(certificate, i);
		  int extension_nid = OBJ_obj2nid(X509_EXTENSION_get_object(extension));

		  if (extension_nid == NID_subject_alt_name) {
	  #if OPENSSL_VERSION_NUMBER >= 0x10000000L
			const X509V3_EXT_METHOD* meth = X509V3_EXT_get(extension);
	  #else
			X509V3_EXT_METHOD* meth = X509V3_EXT_get(extension);
	  #endif
			if (!meth)
			  break;

			void* ext_str = NULL;

			// We assign this to a local variable, instead of passing the address
			// directly to ASN1_item_d2i.
			// See http://readlist.com/lists/openssl.org/openssl-users/0/4761.html.
			unsigned char* ext_value_data = extension->value->data;

	  #if OPENSSL_VERSION_NUMBER >= 0x0090800fL
			const unsigned char **ext_value_data_ptr =
				(const_cast<const unsigned char **>(&ext_value_data));
	  #else
			unsigned char **ext_value_data_ptr = &ext_value_data;
	  #endif

			if (meth->it) {
			  ext_str = ASN1_item_d2i(NULL, ext_value_data_ptr,
									  extension->value->length,
									  ASN1_ITEM_ptr(meth->it));
			} else {
			  ext_str = meth->d2i(NULL, ext_value_data_ptr, extension->value->length);
			}

			STACK_OF(CONF_VALUE)* value = meth->i2v(meth, ext_str, NULL);
			for (int j = 0; j < sk_CONF_VALUE_num(value); ++j) {
			  CONF_VALUE* nval = sk_CONF_VALUE_value(value, j);
			  // The value for nval can contain wildcards
			  if (!strcmp(nval->name, "DNS") && string_match(host, nval->value)) {
				ok = true;
				break;
			  }
			}
			sk_CONF_VALUE_pop_free(value, X509V3_conf_free);
			value = NULL;

			if (meth->it) {
			  ASN1_item_free(reinterpret_cast<ASN1_VALUE*>(ext_str),
							 ASN1_ITEM_ptr(meth->it));
			} else {
			  meth->ext_free(ext_str);
			}
			ext_str = NULL;
		  }
		  if (ok)
			break;
		}

		char data[256];
		X509_name_st* subject;
		if (!ok
			&& ((subject = X509_get_subject_name(certificate)) != NULL)
			&& (X509_NAME_get_text_by_NID(subject, NID_commonName,
										  data, sizeof(data)) > 0)) {
		  data[sizeof(data)-1] = 0;
		  if (stricmp(data, host) == 0)
			ok = true;
		}

		X509_free(certificate);

		// This should only ever be turned on for debugging and development.
		 if (!ok) {
		  std::cout << "TLS certificate check FAILED.  "
			<< "Allowing connection anyway.";
		  ok = true;
		}

		return ok;
	  }

	  bool SSLStreamManager::ConfigureTrustedRootCertificates(SSL_CTX* ctx) {
		// Add the root cert that we care about to the SSL context
		int count_of_added_certs = 0;
		for (int i = 0; i < ARRAY_SIZE(kSSLCertCertificateList); i++) {
		  const unsigned char* cert_buffer = kSSLCertCertificateList[i];
		  size_t cert_buffer_len = kSSLCertCertificateSizeList[i];
		  X509* cert = d2i_X509(NULL, &cert_buffer, cert_buffer_len);
		  if (cert) {
			int return_value = X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);
			if (return_value == 0) {
			  std::cout << "Unable to add certificate.";
			} else {
			  count_of_added_certs++;
			}
			X509_free(cert);
		  }
		}
		return count_of_added_certs > 0;
		 }
  } // namespace -internal
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  #pragma mark
	  #pragma mark ISSLStreamManager
	  #pragma mark

	  //---------------------------------------------------------------------------
	  const char *ISSLStreamManager::toString(SSLConnectionStates state)
	  {
		switch (state) {
		  case SSLConnectionState_None:                             return "New";
		  case SSLConnectionState_Wait:                             return "Wait";
		  case SSLConnectionState_Connecting:                      return "Connecting";
		  case SSLConnectionState_Connected:                       return "Connected";
		  //case SSLConnectionState_ConnectedButTransportDetached:   return "Connected but transport detached";
		  case SSLConnectionState_Closed:                          return "Closed";
		  case SSLConnectionState_Error:							return "Error";
		}
		return "UNDEFINED";
	  }

	  //---------------------------------------------------------------------------
	  const char *ISSLStreamManager::toString(Options option)
	  {
		switch (option) {
		  case Option_Unknown:  return "Unknown";
		}
		return "UNDEFINED";
	  }


	  //---------------------------------------------------------------------------
	  ElementPtr ISSLStreamManager::toDebug(ISSLStreamManagerPtr transport)
	  {
		return internal::SSLStreamManager::toDebug(transport);
	  }

	  //---------------------------------------------------------------------------
	  ISSLStreamManagerPtr ISSLStreamManager::create(
											   ISSLStreamManagerDelegatePtr delegate
											   //ITransportStreamPtr transportStream
											   )
	  {
		//return internal::ISSLStreamManagerFactory::singleton().create(delegate, transportStream);
		  return internal::ISSLStreamManagerFactory::singleton().create(delegate);
	  }

	  //---------------------------------------------------------------------------
	  ISSLStreamManager::CapabilitiesPtr ISSLStreamManager::getCapabilities()
	  {
		return internal::SSLStreamManager::getCapabilities();
	  }

	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  #pragma mark
	  #pragma mark ISSLStreamManager::Capabilities
	  #pragma mark

	  //---------------------------------------------------------------------------
	  ISSLStreamManager::CapabilitiesPtr ISSLStreamManager::Capabilities::create()
	  {
		return CapabilitiesPtr(new Capabilities);
	  }

	  //---------------------------------------------------------------------------
	  ElementPtr ISSLStreamManager::Capabilities::toDebug() const
	  {
		if (mOptions.size() < 1) return ElementPtr();

		ElementPtr resultEl = Element::create("ISSLStreamManager::Capabilities");

		for (OptionsList::const_iterator iter = mOptions.begin(); iter != mOptions.end(); ++iter)
		{
		  const Options &option = (*iter);
		  OPIHelper::debugAppend(resultEl, "option", ISSLStreamManager::toString(option));
		}

		return resultEl;
	  }

	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  //---------------------------------------------------------------------------
	  #pragma mark
	  #pragma mark ISSLStreamManager::SSLStreamInfo
	  #pragma mark

	  //---------------------------------------------------------------------------
	  ISSLStreamManager::SSLStreamInfoPtr ISSLStreamManager::SSLStreamInfo::create()
	  {
		return SSLStreamInfoPtr(new SSLStreamInfo);
	  }

	  //---------------------------------------------------------------------------
	  ElementPtr ISSLStreamManager::SSLStreamInfo::toDebug() const
	  {
		ElementPtr resultEl = Element::create("ortc::ISSLStreamManager::SSLStreamInfo");

		return resultEl->hasChildren() ? resultEl : ElementPtr();
	  }

 } //namespace
