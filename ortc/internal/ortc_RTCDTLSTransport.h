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

#include <ortc/internal/types.h>
#include <webrtc/common_types.h>
#include <zsLib/types.h>

// Forward declaration to avoid pulling in libsrtp headers here
struct srtp_event_data_t;
struct srtp_ctx_t;
typedef srtp_ctx_t* srtp_t;
struct srtp_policy_t;

using namespace zsLib;

namespace ortc
{
  namespace internal
  {
    
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
#pragma mark
#pragma mark RTCDTLSTransport
#pragma mark
    enum SSLRole {
      SSL_CLIENT,
      SSL_SERVER
      
    };
    
    class RTCDTLSTransport : public Noop,
                             public webrtc::Transport,
                             public webrtc::Encryption,
                             public MessageQueueAssociator
                             //public IRTCSocket,
                             //public IRTCSocketForRTCConnection
    {
    public:
      //friend interaction IRTCSocket;
      //friend interaction IRTCSocketForRTCConnection;
      
    protected:
      RTCDTLSTransport(
                IMessageQueuePtr queue
                );
      
    public:
      virtual int SendPacket(int channel, const void *data, int len);
      virtual int SendRTCPPacket(int channel, const void *data, int len);
      
      virtual void encrypt(
                           int channel,
                           unsigned char* in_data,
                           unsigned char* out_data,
                           int bytes_in,
                           int* bytes_out);
      
      virtual void decrypt(
                           int channel,
                           unsigned char* in_data,
                           unsigned char* out_data,
                           int bytes_in,
                           int* bytes_out);
      
      virtual void encrypt_rtcp(
                                int channel,
                                unsigned char* in_data,
                                unsigned char* out_data,
                                int bytes_in,
                                int* bytes_out);
      
      virtual void decrypt_rtcp(
                                int channel,
                                unsigned char* in_data,
                                unsigned char* out_data,
                                int bytes_in,
                                int* bytes_out);
      
      virtual bool InitSrtp();
      
      virtual void DestroySrtp();
      
      bool SetSend(const std::string& cs, const UCHAR* key, int len);
      bool SetRecv(const std::string& cs, const UCHAR* key, int len);
      
      bool SetKey(int type, const std::string& cs, const UCHAR* key, int len);
      
      
      // Encrypts/signs an individual RTP/RTCP packet, in-place.
      // If an HMAC is used, this will increase the packet size.
      bool ProtectRtp(void* data, int in_len, int max_len, int* out_len);
      bool ProtectRtcp(void* data, int in_len, int max_len, int* out_len);
      // Decrypts/verifies an invidiual RTP/RTCP packet.
      // If an HMAC is used, this will decrease the packet size.
      bool UnprotectRtp(void* data, int in_len, int* out_len);
      bool UnprotectRtcp(void* data, int in_len, int* out_len);
      
      
      
      // Set up the ciphers to use for DTLS-SRTP. If this method is not called
      // before DTLS starts, or |ciphers| is empty, SRTP keys won't be negotiated.
      // This method should be called before SetupDtls.
      virtual bool SetSrtpCiphers(const std::vector<std::string>& ciphers);
      
      // Find out which DTLS-SRTP cipher was negotiated
      virtual bool GetSrtpCipher(std::string* cipher);
      
      virtual bool GetSslRole(SSLRole* role) const;
      virtual bool SetSslRole(SSLRole role);
      virtual bool HandleDtlsPacket(const char* data,
                                    size_t size);
      
      virtual ~RTCDTLSTransport();
      
    protected:
      
      bool mSrtpInitialized;
      srtp_t mSrtpSession;
      int mRtpAuthTagLen;
      int mRtcpAuthTagLen;

      
    };
  }
}

