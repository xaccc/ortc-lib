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

#include <ortc/internal/ortc_RTCDTLSTransport.h>
#include <zsLib/Log.h>


#include <openpeer/services/IICESocket.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <srtp.h>

using namespace zsLib;

namespace ortc { ZS_IMPLEMENT_SUBSYSTEM(ortclib) }

namespace ortc
{
  namespace internal
  {
    
    const char CS_AES_CM_128_HMAC_SHA1_80[] = "AES_CM_128_HMAC_SHA1_80";
    const char CS_AES_CM_128_HMAC_SHA1_32[] = "AES_CM_128_HMAC_SHA1_32";
    const int SRTP_MASTER_KEY_BASE64_LEN = SRTP_MASTER_KEY_LEN * 4 / 3;
    const int SRTP_MASTER_KEY_KEY_LEN = 16;
    const int SRTP_MASTER_KEY_SALT_LEN = 14;

    // We don't pull the RTP constants from rtputils.h, to avoid a layer violation.
    static const size_t kDtlsRecordHeaderLen = 13;
    static const size_t kMaxDtlsPacketLen = 2048;
    static const size_t kMinRtpPacketLen = 12;
    static const size_t kDefaultVideoAndDataCryptos = 1;
    
    static bool IsDtlsPacket(const char* data, size_t len) {
      const UCHAR* u = reinterpret_cast<const UCHAR*>(data);
      return (len >= kDtlsRecordHeaderLen && (u[0] > 19 && u[0] < 64));
    }
    static bool IsRtpPacket(const char* data, size_t len) {
      const UCHAR* u = reinterpret_cast<const UCHAR*>(data);
      return (len >= kMinRtpPacketLen && (u[0] & 0xC0) == 0x80);
    }
#pragma mark
#pragma mark RTCDataChannel
#pragma mark
    
    //-----------------------------------------------------------------------
    RTCDTLSTransport::RTCDTLSTransport(IMessageQueuePtr queue) :
    MessageQueueAssociator(queue)
    {
    }
    
    //-----------------------------------------------------------------------
    RTCDTLSTransport::~RTCDTLSTransport()
    {
    }
    
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
#pragma mark
#pragma mark RTCDTLSTransport => webrtc::Transport
#pragma mark
    
    //-----------------------------------------------------------------------
    int RTCDTLSTransport::SendPacket(int channel, const void *data, int len)
    {
      return 1;
    }
    
    //-----------------------------------------------------------------------
    int RTCDTLSTransport::SendRTCPPacket(int channel, const void *data, int len)
    {
      return 1;
    }
    
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
#pragma mark
#pragma mark RTCDTLSTransport => webrtc::Encryption
#pragma mark
    
    
    void RTCDTLSTransport::encrypt(
                         int channel,
                         unsigned char* in_data,
                         unsigned char* out_data,
                         int bytes_in,
                         int* bytes_out)
    {
      
    }
    
    void RTCDTLSTransport::decrypt(
                         int channel,
                         unsigned char* in_data,
                         unsigned char* out_data,
                         int bytes_in,
                         int* bytes_out)
    {
      
    }
    
    void RTCDTLSTransport::encrypt_rtcp(
                              int channel,
                              unsigned char* in_data,
                              unsigned char* out_data,
                              int bytes_in,
                              int* bytes_out)
    {
      
    }
    
    void RTCDTLSTransport::decrypt_rtcp(
                              int channel,
                              unsigned char* in_data,
                              unsigned char* out_data,
                              int bytes_in,
                              int* bytes_out)
    {
      
    }
    
    
    bool RTCDTLSTransport::InitSrtp()
    {
      if (!mSrtpInitialized) {
        int err;
        err = srtp_init();
        if (err != err_status_ok) {
          //LOG(LS_ERROR) << "Failed to init SRTP, err=" << err;
          return false;
        }
        
        //err = srtp_install_event_handler(&SrtpSession::HandleEventThunk);
        if (err != err_status_ok) {
          //LOG(LS_ERROR) << "Failed to install SRTP event handler, err=" << err;
          return false;
        }
        
        mSrtpInitialized = true;
      }
      
      return true;
    }
    
    void RTCDTLSTransport::DestroySrtp()
    {
      if (mSrtpInitialized) {
        int err = srtp_shutdown();
        if (err) {
          //LOG(LS_ERROR) << "srtp_shutdown failed. err=" << err;
          return;
        }
        mSrtpInitialized = false;
      }
    }
    
    
    bool RTCDTLSTransport::SetSend(const std::string& cs, const UCHAR* key, int len) {
      return SetKey(ssrc_any_outbound, cs, key, len);
    }
    
    bool RTCDTLSTransport::SetRecv(const std::string& cs, const UCHAR* key, int len) {
      return SetKey(ssrc_any_inbound, cs, key, len);
    }
    
    bool RTCDTLSTransport::SetKey(int type, const std::string& cs,
                             const UCHAR* key, int len) {
      if (mSrtpSession) {
        //LOG(LS_ERROR) << "Failed to create SRTP session: "
        //<< "SRTP session already created";
        return false;
      }
      
      if (!InitSrtp()) {
        return false;
      }
      
      srtp_policy_t policy;
      memset(&policy, 0, sizeof(policy));
      
      if (cs == CS_AES_CM_128_HMAC_SHA1_80) {
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
      } else if (cs == CS_AES_CM_128_HMAC_SHA1_32) {
        crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy.rtp);   // rtp is 32,
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);  // rtcp still 80
      } else {
        //LOG(LS_WARNING) << "Failed to create SRTP session: unsupported"
        //<< " cipher_suite " << cs.c_str();
        return false;
      }
      
      if (!key || len != SRTP_MASTER_KEY_LEN) {
        //LOG(LS_WARNING) << "Failed to create SRTP session: invalid key";
        return false;
      }
      
      policy.ssrc.type = static_cast<ssrc_type_t>(type);
      policy.ssrc.value = 0;
      policy.key = const_cast<UCHAR*>(key);
      // TODO(astor) parse window size from WSH session-param
      policy.window_size = 1024;
      policy.allow_repeat_tx = 1;
      policy.next = NULL;
      
      int err = srtp_create(&mSrtpSession, &policy);
      if (err != err_status_ok) {
        //LOG(LS_ERROR) << "Failed to create SRTP session, err=" << err;
        return false;
      }
      
      mRtpAuthTagLen = policy.rtp.auth_tag_len;
      mRtcpAuthTagLen = policy.rtcp.auth_tag_len;
      return true;
    }
    
    bool RTCDTLSTransport::ProtectRtp(void* p, int in_len, int max_len, int* out_len) {
      if (!mSrtpSession) {
        //LOG(LS_WARNING) << "Failed to protect SRTP packet: no SRTP Session";
        return false;
      }
      
      int need_len = in_len + mRtpAuthTagLen;  // NOLINT
      if (max_len < need_len) {
//        LOG(LS_WARNING) << "Failed to protect SRTP packet: The buffer length "
//        << max_len << " is less than the needed " << need_len;
        return false;
      }
      
      *out_len = in_len;
      int err = srtp_protect(mSrtpSession, p, out_len);
//      uint32 ssrc;
//      if (GetRtpSsrc(p, in_len, &ssrc)) {
//        srtp_stat_->AddProtectRtpResult(ssrc, err);
//      }
//      int seq_num;
//      GetRtpSeqNum(p, in_len, &seq_num);
      if (err != err_status_ok) {
//        LOG(LS_WARNING) << "Failed to protect SRTP packet, seqnum="
//        << seq_num << ", err=" << err << ", last seqnum="
//        << last_send_seq_num_;
        return false;
      }
//      last_send_seq_num_ = seq_num;
      return true;
    }
    
    bool RTCDTLSTransport::ProtectRtcp(void* p, int in_len, int max_len, int* out_len) {
      if (!mSrtpSession) {
        //LOG(LS_WARNING) << "Failed to protect SRTCP packet: no SRTP Session";
        return false;
      }
      
      int need_len = in_len + sizeof(UINT) + mRtcpAuthTagLen;  // NOLINT
      if (max_len < need_len) {
//        LOG(LS_WARNING) << "Failed to protect SRTCP packet: The buffer length "
//        << max_len << " is less than the needed " << need_len;
        return false;
      }
      
      *out_len = in_len;
      int err = srtp_protect_rtcp(mSrtpSession, p, out_len);
      //srtp_stat_->AddProtectRtcpResult(err);
      if (err != err_status_ok) {
        //LOG(LS_WARNING) << "Failed to protect SRTCP packet, err=" << err;
        return false;
      }
      return true;
    }
    
    bool RTCDTLSTransport::UnprotectRtp(void* p, int in_len, int* out_len) {
      if (!mSrtpSession) {
        //LOG(LS_WARNING) << "Failed to unprotect SRTP packet: no SRTP Session";
        return false;
      }
      
      *out_len = in_len;
      int err = srtp_unprotect(mSrtpSession, p, out_len);
//      uint32 ssrc;
//      if (GetRtpSsrc(p, in_len, &ssrc)) {
//        srtp_stat_->AddUnprotectRtpResult(ssrc, err);
//      }
      if (err != err_status_ok) {
        //LOG(LS_WARNING) << "Failed to unprotect SRTP packet, err=" << err;
        return false;
      }
      return true;
    }
    
    bool RTCDTLSTransport::UnprotectRtcp(void* p, int in_len, int* out_len) {
      if (!mSrtpSession) {
        //LOG(LS_WARNING) << "Failed to unprotect SRTCP packet: no SRTP Session";
        return false;
      }
      
      *out_len = in_len;
      int err = srtp_unprotect_rtcp(mSrtpSession, p, out_len);
      //srtp_stat_->AddUnprotectRtcpResult(err);
      if (err != err_status_ok) {
        //LOG(LS_WARNING) << "Failed to unprotect SRTCP packet, err=" << err;
        return false;
      }
      return true;
    }

    
    
  }
}

