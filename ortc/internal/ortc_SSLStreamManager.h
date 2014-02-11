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

#pragma once

//ortc include files
#include <ortc/internal/types.h>
#include <ortc/ISSLStreamManager.h>
#include <openpeer/services/ITransportStream.h>
#include <ortc/internal/dtls/ortc_opensslidentity.h>
#include <openpeer/services/IWakeDelegate.h>
#include <zsLib/MessageQueueAssociator.h>
#include <boost/shared_ptr.hpp>
#include <boost/thread/thread.hpp>
#include <string>
#include <vector>

enum StreamState { SS_CLOSED, SS_OPENING, SS_OPEN };

namespace ortc
{
  namespace internal
  {
    enum { MSG_POST_EVENT = 0xF1F1, MSG_MAX = MSG_POST_EVENT };
    enum StreamResult { SR_ERROR, SR_SUCCESS, SR_BLOCK, SR_EOS };
    // Errors for Read -- in the high range so no conflict with OpenSSL.
    enum { SSE_MSG_TRUNC = 0xff0001 };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamManager
    #pragma mark
    
    class SSLStreamManager : public Noop,
                            public MessageQueueAssociator,
                            public ISSLStreamManager,
                            public IWakeDelegate,
                            public openpeer::services::ITransportStreamWriterDelegate,
                            public openpeer::services::ITransportStreamReaderDelegate

    {
    public:
      friend interaction ISSLStreamManager;
      friend interaction ISSLStreamManagerFactory;
      //static bool InitializeSSL(VerificationCallback callback);
      static bool InitializeSSL();
      static bool InitializeSSLThread();
      static bool CleanupSSL();

    protected:
      SSLStreamManager(
                    IMessageQueuePtr queue,
                    ISSLStreamManagerDelegatePtr delegate
                    //ITransportStreamPtr transportStream
                    );

      SSLStreamManager(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {}

      void init();

    public:
      virtual ~SSLStreamManager();

      static SSLStreamManagerPtr convert(ISSLStreamManagerPtr object);

    protected:
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => ISSLStreamManager
      #pragma mark

      static ElementPtr toDebug(ISSLStreamManagerPtr sslstreammanager);

      static SSLStreamManagerPtr create(
                                     ISSLStreamManagerDelegatePtr delegate
                                     //ITransportStreamPtr transportStream
                                     );

      virtual PUID getID() const;

      virtual ISSLStreamManagerSubscriptionPtr subscribe(ISSLStreamManagerDelegatePtr delegate);

      static CapabilitiesPtr getCapabilities();

      virtual SSLConnectionStates getState(
                                        WORD *outError = NULL,
                                        String *outReason = NULL
                                        ) ;
      virtual ITransportStreamPtr getSSLTransportStream();

    public:

      virtual void SetIdentity(SSLIdentity* identity);

      virtual void SetServerRole(SSLRole role = SSL_SERVER);

      // Do DTLS or TLS
      virtual void SetMode(SSLMode mode);

      virtual int StartSSLWithServer(const char* server_name);

      virtual int StartSSLWithPeer();

      virtual void SetPeerCertificate(SSLCertificate* cert);

      virtual bool SetPeerCertificateDigest(const std::string& digest_alg,
                                              const unsigned char* digest_val,
                                              size_t digest_len);

      virtual bool GetPeerCertificate(SSLCertificate** cert) const ;

      virtual bool ExportKeyingMaterial(const std::string& label,
                                          const uint8* context,
                                          size_t context_len,
                                          bool use_context,
                                          uint8* result,
                                          size_t result_len);


      // DTLS-SRTP interface
      virtual bool SetDtlsSrtpCiphers(const std::vector<std::string>& ciphers);

      virtual bool GetDtlsSrtpCipher(std::string* cipher);


      //Stream read-write api's
      virtual StreamResult Read(void* data, size_t data_len,
                                size_t* read, int* error);

      virtual StreamResult Write(const void* data, size_t data_len,
                                 size_t* written, int* error);

      virtual void Close();

    protected:
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => IWakeDelegate
      #pragma mark

      virtual void onWake();

      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => ITransportStreamWriterDelegate
      #pragma mark

      virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr writer);


      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => ITransportStreamReaderDelegate
      #pragma mark

      virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) ;

    protected:
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => (internal)
      #pragma mark

      Log::Params log(const char *message) const;
      Log::Params debug(const char *message) const;
      ElementPtr toDebug() const;

      virtual RecursiveLock &getLock() const {return mLock;}

      bool isShuttingDown() const;
      bool isShutdown() const;

      void step();
      //bool stepDTLSTransport();
      //bool stepSSLState();

      void cancel();

      void setState(SSLConnectionStates state);
      void setError(WORD error, const char *reason = NULL);

    protected:

      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark SSLStreamManager => (data)
      #pragma mark

      AutoPUID mID;
      mutable RecursiveLock mLock;
      SSLStreamManagerWeakPtr mThisWeak;
      SSLStreamManagerPtr mGracefulShutdownReference;

      //Transport stream reader/writer
	  ITransportStreamReaderPtr mWireReceiveStream;
      ITransportStreamWriterPtr mWireSendStream;
      
      AutoBool mInformedWireSendReady;

      ITransportStreamPtr mTransportStream;
      
	  //ITransportStreamWriterSubscriptionPtr mOuterReceiveStreamSubscription;
	  //ITransportStreamReaderSubscriptionPtr mOuterSendStreamSubscription;
      ITransportStreamReaderSubscriptionPtr mReceiveStreamSubscription;

      ISSLStreamManagerDelegateSubscriptions mSubscriptions;
      ISSLStreamManagerSubscriptionPtr mDefaultSubscription;

      SSLConnectionStates mCurrentState;
      AutoBool mStartCalled;

      AutoWORD mLastError;
      String mLastErrorReason;

    protected:

     // The following three methods return 0 on success and a negative
     // error code on failure. The error code may be from OpenSSL or -1
     // on some other error cases, so it can't really be interpreted
     // unfortunately.

     // Go from state SSL_NONE to either SSL_CONNECTING or SSL_WAIT,
     // depending on whether the underlying stream is already open or
     // not.
     int StartSSL();

     // Prepare SSL library, state is SSL_CONNECTING.
     int BeginSSL();

     // Perform SSL negotiation steps.
     int ContinueSSL();
     

     // Error handler helper. signal is given as true for errors in
     // asynchronous contexts (when an error method was not returned
     // through some other method), and in that case an SE_CLOSE event is
     // raised on the stream with the specified error.
     // A 0 error means a graceful close, otherwise there is not really enough
     // context to interpret the error code.
     void Error(const char* context, int err, bool signal);

     void Cleanup();

     // Override MessageHandler
     //virtual void OnMessage(Message* msg);

     // Flush the input buffers by reading left bytes (for DTLS)
     void FlushInput(unsigned int left);

     // SSL library configuration
     SSL_CTX* SetupSSLContext();

     //static bool VerifyServerName(SSL* ssl, const char* host,
       //                             bool ignore_bad_cert);

     static bool VerifyServerName(SSL* ssl, const char* host);

#if _DEBUG
  static void SSLInfoCallback(const SSL* s, int where, int ret);
#endif

     // SSL verification check
     bool SSLPostConnectionCheck(SSL* ssl, const char* server_name,
                                 const X509* peer_cert,
                                 const std::string& peer_digest);

     static bool ConfigureTrustedRootCertificates(SSL_CTX* ctx);

     // SSL certification verification error handler, called back from
     // the openssl library. Returns an int interpreted as a boolean in
     // the C style: zero means verification failure, non-zero means
     // passed.
     static int SSLVerifyCallback(int ok, X509_STORE_CTX* store);


     //SSLState state_;
     SSLRole role_;
     int ssl_error_code_;  // valid when state_ == SSL_ERROR or SSL_CLOSED
     // Whether the SSL negotiation is blocked on needing to read or
     // write to the wrapped stream.
     bool ssl_read_needs_write_;
     bool ssl_write_needs_read_;
     SSL* ssl_;
     SSL_CTX* ssl_ctx_;

     // Our key and certificate, mostly useful in peer-to-peer mode.
     boost::shared_ptr<OpenSSLIdentity> identity_;
     // in traditional mode, the server name that the server's certificate
     // must specify. Empty in peer-to-peer mode.
     std::string ssl_server_name_;
     // The certificate that the peer must present or did present. Initially
     // null in traditional mode, until the connection is established.
     boost::shared_ptr<OpenSSLCertificate> peer_certificate_;
     // In peer-to-peer mode, the digest of the certificate that
     // the peer must present.
     Buffer peer_certificate_digest_value_;
     std::string peer_certificate_digest_algorithm_;

     // OpenSSLAdapter::custom_verify_callback_ result
     //bool custom_verification_succeeded_;
     //bool ignore_bad_cert_;
     // The DtlsSrtp ciphers
     std::string srtp_ciphers_;

     // Do DTLS or not
     SSLMode ssl_mode_;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark ISSLStreamManagerFactory
    #pragma mark

    interaction ISSLStreamManagerFactory
    {
      static ISSLStreamManagerFactory &singleton();

      virtual SSLStreamManagerPtr create(
                                      ISSLStreamManagerDelegatePtr delegate
                                      //ISSLStreamManager::ITransportStreamPtr transportStream
                                      );
    };

  }
}
