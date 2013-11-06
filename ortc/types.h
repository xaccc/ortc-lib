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

#include <openpeer/services/types.h>

namespace ortc
{
  using zsLib::PUID;
  using zsLib::BYTE;
  using zsLib::WORD;
  using zsLib::DWORD;
  using zsLib::QWORD;
  using zsLib::ULONG;
  using zsLib::Time;
  using zsLib::Duration;
  using zsLib::String;

  using openpeer::services::SecureByteBlock;
  using openpeer::services::SecureByteBlockPtr;
  
  //-------------------------------------------------------------------------
  //-------------------------------------------------------------------------
  //-------------------------------------------------------------------------
  //-------------------------------------------------------------------------
  #pragma mark
  #pragma mark (other)
  #pragma mark
  
  interaction IRTCConnection;
  typedef boost::shared_ptr<IRTCConnection> IRTCConnectionPtr;
  typedef boost::weak_ptr<IRTCConnection> IRTCConnectionWeakPtr;
  
  interaction IRTCConnectionDelegate;
  typedef boost::shared_ptr<IRTCConnectionDelegate> IRTCConnectionDelegatePtr;
  typedef boost::weak_ptr<IRTCConnectionDelegate> IRTCConnectionDelegateWeakPtr;
  typedef zsLib::Proxy<IRTCConnectionDelegate> IRTCConnectionDelegateProxy;
  
  interaction IRTCSocket;
  typedef boost::shared_ptr<IRTCSocket> IRTCSocketPtr;
  typedef boost::weak_ptr<IRTCSocket> IRTCSocketWeakPtr;
  
  interaction IRTCStream;
  typedef boost::shared_ptr<IRTCStream> IRTCStreamPtr;
  typedef boost::weak_ptr<IRTCStream> IRTCStreamWeakPtr;
  
  typedef std::list<IRTCStream> RTCStreamList;
  typedef boost::shared_ptr<RTCStreamList> RTCStreamListPtr;
  typedef boost::weak_ptr<RTCStreamList> RTCStreamListWeakPtr;

  interaction IRTCTrack;
  typedef boost::shared_ptr<IRTCTrack> IRTCTrackPtr;
  typedef boost::weak_ptr<IRTCTrack> IRTCTrackWeakPtr;
  
  typedef std::list<IRTCTrack> RTCTrackList;
  typedef boost::shared_ptr<RTCTrackList> RTCTrackListPtr;
  typedef boost::weak_ptr<RTCTrackList> RTCTrackListWeakPtr;

  interaction IRTCDTMFTrack;
  typedef boost::shared_ptr<IRTCDTMFTrack> IRTCDTMFTrackPtr;
  typedef boost::weak_ptr<IRTCDTMFTrack> IRTCDTMFTrackWeakPtr;
  
  interaction IRTCDTMFTrackDelegate;
  typedef boost::shared_ptr<IRTCDTMFTrackDelegate> IRTCDTMFTrackDelegatePtr;
  typedef boost::weak_ptr<IRTCDTMFTrackDelegate> IRTCDTMFTrackDelegateWeakPtr;
  typedef zsLib::Proxy<IRTCDTMFTrackDelegate> IRTCDTMFTrackDelegateProxy;

  interaction IRTCDataChannel;
  typedef boost::shared_ptr<IRTCDataChannel> IRTCDataChannelPtr;
  typedef boost::weak_ptr<IRTCDataChannel> IRTCDataChannelWeakPtr;
  
  interaction IRTCDataChannelDelegate;
  typedef boost::shared_ptr<IRTCDataChannelDelegate> IRTCDataChannelDelegatePtr;
  typedef boost::weak_ptr<IRTCDataChannelDelegate> IRTCDataChannelDelegateWeakPtr;
  typedef zsLib::Proxy<IRTCDataChannelDelegate> IRTCDataChannelDelegateProxy;

  interaction IMediaStream;
  typedef boost::shared_ptr<IMediaStream> IMediaStreamPtr;
  typedef boost::weak_ptr<IMediaStream> IMediaStreamWeakPtr;

  interaction IMediaStreamTrack;
  typedef boost::shared_ptr<IMediaStreamTrack> IMediaStreamTrackPtr;
  typedef boost::weak_ptr<IMediaStreamTrack> IMediaStreamTrackWeakPtr;
  
}
