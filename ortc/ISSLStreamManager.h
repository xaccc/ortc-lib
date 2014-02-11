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

#include <ortc/types.h>
#include "ortc/internal/dtls/ortc_SSLIdentity.h"


typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_store_ctx_st X509_STORE_CTX;

namespace ortc
{
  enum StreamEvent { SE_OPEN = 1, SE_READ = 2, SE_WRITE = 4, SE_CLOSE = 8 };
  enum SSLRole { SSL_CLIENT, SSL_SERVER };
  enum SSLMode { SSL_MODE_TLS, SSL_MODE_DTLS };
  
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark ISSLStreamManager
  #pragma mark
  
  interaction ISSLStreamManager
  {
    struct Capabilities;
    struct SSLStreamInfo;

    typedef boost::shared_ptr<Capabilities> CapabilitiesPtr;
    typedef boost::shared_ptr<SSLStreamInfo> SSLStreamInfoPtr;
    
    typedef boost::shared_ptr<openpeer::services::ITransportStream> ITransportStreamPtr;
    typedef boost::shared_ptr<openpeer::services::ITransportStreamWriter> ITransportStreamWriterPtr;
    typedef boost::shared_ptr<openpeer::services::ITransportStreamReader> ITransportStreamReaderPtr;
    typedef boost::shared_ptr<openpeer::services::ITransportStreamWriterSubscription> ITransportStreamWriterSubscriptionPtr;
    typedef boost::shared_ptr<openpeer::services::ITransportStreamReaderSubscription>ITransportStreamReaderSubscriptionPtr;

    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLConnectionStates
    #pragma mark
    enum SSLConnectionStates
    {
      SSLConnectionState_None,
      SSLConnectionState_Wait,
      SSLConnectionState_Connecting,
      SSLConnectionState_Connected,
      //SSLConnectionState_ConnectedButTransportDetached,  // either no ICE transport is attached or the ICE transport is haulted
      SSLConnectionState_Closed,
      SSLConnectionState_Error
    };

    static const char *toString(SSLConnectionStates state);

    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark Options
    #pragma mark

    enum Options
    {
      Option_Unknown,
    };

    static const char *toString(Options option);

    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark Capabilities
    #pragma mark

    struct Capabilities
    {
      typedef std::list<Options> OptionsList;

      OptionsList mOptions;

      static CapabilitiesPtr create();
      ElementPtr toDebug() const;

    protected:
      Capabilities() {}
      Capabilities(const Capabilities &) {}
    };

    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark SSLStreamInfo
    #pragma mark

    struct SSLStreamInfo
    {
      static SSLStreamInfoPtr create();
      ElementPtr toDebug() const;

    protected:
      SSLStreamInfo() {}
      SSLStreamInfo(const SSLStreamInfo &) {}
    };


    static ElementPtr toDebug(ISSLStreamManagerPtr sslstreammanager);

    static ISSLStreamManagerPtr create(
                                    ISSLStreamManagerDelegatePtr delegate
                                    //ITransportStreamPtr sslstream
                                    );

    virtual PUID getID() const = 0;

    virtual ISSLStreamManagerSubscriptionPtr subscribe(ISSLStreamManagerDelegatePtr delegate) = 0;

    static CapabilitiesPtr getCapabilities();


    virtual SSLConnectionStates getState(
                                      WORD *outError = NULL,
                                      String *outReason = NULL
                                      ) = 0;
#if 1
    virtual ITransportStreamPtr getSSLTransportStream() = 0;
#endif

#if 1
      //sslstreamadapter apis -- from jingle library
      // void set_ignore_bad_cert(bool ignore) { ignore_bad_cert_ = ignore; }
      // bool ignore_bad_cert() const { return ignore_bad_cert_; }

      // Specify our SSL identity: key and certificate. Mostly this is
      // only used in the peer-to-peer mode (unless we actually want to
      // provide a client certificate to a server).
      // SSLStream takes ownership of the SSLIdentity object and will
      // free it when appropriate. Should be called no more than once on a
      // given SSLStream instance.
      virtual void SetIdentity(ortc::internal::SSLIdentity* identity) = 0;

      // Call this to indicate that we are to play the server's role in
      // the peer-to-peer mode.
      // The default argument is for backward compatibility
      // TODO(ekr@rtfm.com): rename this SetRole to reflect its new function
      virtual void SetServerRole(SSLRole role = SSL_SERVER) = 0;

      // Do DTLS or TLS
      virtual void SetMode(SSLMode mode) = 0;

      // The mode of operation is selected by calling either
      // StartSSLWithServer or StartSSLWithPeer.
      // Use of the stream prior to calling either of these functions will
      // pass data in clear text.
      // Calling one of these functions causes SSL negotiation to begin as
      // soon as possible: right away if the underlying wrapped stream is
      // already opened, or else as soon as it opens.
      //
      // These functions return a negative error code on failure.
      // Returning 0 means success so far, but negotiation is probably not
      // complete and will continue asynchronously.  In that case, the
      // exposed stream will open after successful negotiation and
      // verification, or an SE_CLOSE event will be raised if negotiation
      // fails.

      // StartSSLWithServer starts SSL negotiation with a server in
      // traditional mode. server_name specifies the expected server name
      // which the server's certificate needs to specify.
      virtual int StartSSLWithServer(const char* server_name) = 0;

      // StartSSLWithPeer starts negotiation in the special peer-to-peer
      // mode.
      // Generally, SetIdentity() and possibly SetServerRole() should have
      // been called before this.
      // SetPeerCertificate() or SetPeerCertificateDigest() must also be called.
      // It may be called after StartSSLWithPeer() but must be called before the
      // underlying stream opens.
      virtual int StartSSLWithPeer() = 0;

      // Specify the certificate that our peer is expected to use in
      // peer-to-peer mode. Only this certificate will be accepted during
      // SSL verification. The certificate is assumed to have been
      // obtained through some other secure channel (such as the XMPP
      // channel). (This could also specify the certificate authority that
      // will sign the peer's certificate.)
      // SSLStream takes ownership of the SSLCertificate object and will
      // free it when appropriate. Should be called no more than once on a
      // given SSLStream instance.
      virtual void SetPeerCertificate(ortc::internal::SSLCertificate* cert) = 0;

      // Specify the digest of the certificate that our peer is expected to use in
      // peer-to-peer mode. Only this certificate will be accepted during
      // SSL verification. The certificate is assumed to have been
      // obtained through some other secure channel (such as the XMPP
      // channel). Unlike SetPeerCertificate(), this must specify the
      // terminal certificate, not just a CA.
      // SSLStream makes a copy of the digest value.
      virtual bool SetPeerCertificateDigest(const std::string& digest_alg,
                                            const unsigned char* digest_val,
                                            size_t digest_len) = 0;

      // Retrieves the peer's X.509 certificate, if a certificate has been
      // provided by SetPeerCertificate or a connection has been established. If
      // a connection has been established, this returns the
      // certificate transmitted over SSL, including the entire chain.
      // The returned certificate is owned by the caller.
      virtual bool GetPeerCertificate(ortc::internal::SSLCertificate** cert) const = 0;

      // Key Exporter interface from RFC 5705
      // Arguments are:
      // label               -- the exporter label.
      //                        part of the RFC defining each exporter
      //                        usage (IN)
      // context/context_len -- a context to bind to for this connection;
      //                        optional, can be NULL, 0 (IN)
      // use_context         -- whether to use the context value
      //                        (needed to distinguish no context from
      //                        zero-length ones).
      // result              -- where to put the computed value
      // result_len          -- the length of the computed value
      virtual bool ExportKeyingMaterial(const std::string& label,
                                        const uint8* context,
                                        size_t context_len,
                                        bool use_context,
                                        uint8* result,
                                        size_t result_len)= 0;


      // DTLS-SRTP interface
      virtual bool SetDtlsSrtpCiphers(const std::vector<std::string>& ciphers) = 0;

      virtual bool GetDtlsSrtpCipher(std::string* cipher)  = 0;
#endif
  };

  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark ISSLStreamManagerDelegate
  #pragma mark

  interaction ISSLStreamManagerDelegate
  {
    virtual void onSSLStreamStateChanged(
                                            ISSLStreamManagerPtr sslstreammanager,
                                            ISSLStreamManager::SSLConnectionStates state
                                            ) = 0;
  };

  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark ISSLStreamManagerSubscription
  #pragma mark

  interaction ISSLStreamManagerSubscription
  {
    virtual PUID getID() const = 0;

    virtual void cancel() = 0;

    virtual void background() = 0;
  };
}

ZS_DECLARE_PROXY_BEGIN(ortc::ISSLStreamManagerDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::ISSLStreamManagerPtr, ISSLStreamManagerPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::ISSLStreamManager::SSLConnectionStates, SSLConnectionStates)
ZS_DECLARE_PROXY_METHOD_2(onSSLStreamStateChanged, ISSLStreamManagerPtr, SSLConnectionStates)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(ortc::ISSLStreamManagerDelegate, ortc::ISSLStreamManagerSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::ISSLStreamManagerPtr, ISSLStreamManagerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::ISSLStreamManager::SSLConnectionStates, SSLConnectionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_2(onSSLStreamStateChanged, ISSLStreamManagerPtr, SSLConnectionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
