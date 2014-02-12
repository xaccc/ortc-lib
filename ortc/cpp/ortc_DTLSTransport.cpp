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

#include <ortc/internal/ortc_DTLSTransport.h>
#include <ortc/internal/ortc_RTPReceiver.h>
#include <ortc/internal/ortc_ORTC.h>

#include <openpeer/services/IHelper.h>
#include <openpeer/services/IHTTP.h>

#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <android/log.h>

static const char kAES_CM_HMAC_SHA1_80[] = "AES_CM_128_HMAC_SHA1_80";
static const char kAES_CM_HMAC_SHA1_32[] = "AES_CM_128_HMAC_SHA1_32";

namespace ortc { ZS_DECLARE_SUBSYSTEM(ortclib) }

namespace ortc
{
  typedef openpeer::services::IHelper OPIHelper;

  namespace internal
  {
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
    #pragma mark IDTLSTransportForRTPSender
    #pragma mark
    
    //-------------------------------------------------------------------------
    ElementPtr IDTLSTransportForRTPSender::toDebug(ForRTPSenderPtr transport)
    {
      return DTLSTransport::toDebug(DTLSTransport::convert(transport));
    }
    
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDTLSTransportForRTPReceiver
    #pragma mark
    
    //-------------------------------------------------------------------------
    ElementPtr IDTLSTransportForRTPReceiver::toDebug(ForRTPReceiverPtr transport)
    {
      return DTLSTransport::toDebug(DTLSTransport::convert(transport));
    }
 
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport
    #pragma mark
    
    //-------------------------------------------------------------------------
    DTLSTransport::DTLSTransport(
                                 IMessageQueuePtr queue,
                                 IDTLSTransportDelegatePtr originalDelegate,
                                 IICETransportPtr iceTransport
                                 ) :
      MessageQueueAssociator(queue),
      mCurrentState(ConnectionState_New),
      mICETransport(ICETransport::convert(iceTransport))
    {
      ZS_LOG_DETAIL(debug("created"))

      mDefaultSubscription = mSubscriptions.subscribe(IDTLSTransportDelegateProxy::create(IORTCForInternal::queueDelegate(), originalDelegate), queue);
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::init()
    {
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    DTLSTransport::~DTLSTransport()
    {
      if (isNoop()) return;

      ZS_LOG_DETAIL(log("destroyed"))
      mThisWeak.reset();
      cancel();
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::convert(IDTLSTransportPtr object)
    {
      return boost::dynamic_pointer_cast<DTLSTransport>(object);
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::convert(ForRTPSenderPtr object)
    {
      return boost::dynamic_pointer_cast<DTLSTransport>(object);
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::convert(ForRTPReceiverPtr object)
    {
      return boost::dynamic_pointer_cast<DTLSTransport>(object);
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::convert(ForICETransportPtr object)
    {
      return boost::dynamic_pointer_cast<DTLSTransport>(object);
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::convert(ForDTLSContextPtr object)
    {
      return boost::dynamic_pointer_cast<DTLSTransport>(object);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IDTLSTransport
    #pragma mark
    
    //-------------------------------------------------------------------------
    ElementPtr DTLSTransport::toDebug(IDTLSTransportPtr transport)
    {
      if (!transport) return ElementPtr();
      DTLSTransportPtr pThis = DTLSTransport::convert(transport);
      return pThis->toDebug();
    }

    //-------------------------------------------------------------------------
    DTLSTransportPtr DTLSTransport::create(
                                           IDTLSTransportDelegatePtr delegate,
                                           IICETransportPtr iceTransport
                                           )
    {
      DTLSTransportPtr pThis(new DTLSTransport(IORTCForInternal::queueORTC(), delegate, iceTransport));
      pThis->mThisWeak.lock();
      pThis->init();
      return pThis;
    }

    //-------------------------------------------------------------------------
    PUID DTLSTransport::getID() const
    {
      return mID;
    }

    //-------------------------------------------------------------------------
    IDTLSTransportSubscriptionPtr DTLSTransport::subscribe(IDTLSTransportDelegatePtr originalDelegate)
    {
      ZS_LOG_DETAIL(log("subscribing to transport state"))

      AutoRecursiveLock lock(getLock());
      if (!originalDelegate) return mDefaultSubscription;

      IDTLSTransportSubscriptionPtr subscription = mSubscriptions.subscribe(IDTLSTransportDelegateProxy::create(IORTCForInternal::queueDelegate(), originalDelegate));

      IDTLSTransportDelegatePtr delegate = mSubscriptions.delegate(subscription);

      if (delegate) {
        DTLSTransportPtr pThis = mThisWeak.lock();

        if (ConnectionState_New != mCurrentState) {
          delegate->onDTLSTransportStateChanged(pThis, mCurrentState);
        }
      }

      if (isShutdown()) {
        mSubscriptions.clear();
      }

      return subscription;
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::CapabilitiesPtr DTLSTransport::getCapabilities()
    {
      return CapabilitiesPtr();
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::TransportInfoPtr DTLSTransport::createParams(CapabilitiesPtr capabilities)
    {
      return TransportInfoPtr();
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::TransportInfoPtr DTLSTransport::filterParams(
                                                               TransportInfoPtr params,
                                                               CapabilitiesPtr capabilities
                                                               )
    {
      return TransportInfoPtr();
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::TransportInfoPtr DTLSTransport::getLocal()
    {
      AutoRecursiveLock lock(getLock());
      return mLocal;
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::TransportInfoPtr DTLSTransport::getRemote()
    {
      AutoRecursiveLock lock(getLock());
      return mRemote;
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::setLocal(TransportInfoPtr info)
    {
      AutoRecursiveLock lock(getLock());

      ZS_LOG_TRACE(log("set local called") + ZS_PARAM("local", info ? info->toDebug() : ElementPtr()))

      mLocal = info;
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::setRemote(TransportInfoPtr info)
    {
      AutoRecursiveLock lock(getLock());

      ZS_LOG_TRACE(log("set remote called") + ZS_PARAM("remote", info ? info->toDebug() : ElementPtr()))

      mRemote = info;
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::attach(IICETransportPtr inIceTransport)
    {
      AutoRecursiveLock lock(getLock());

      UseICETransportPtr iceTransport = ICETransport::convert(inIceTransport);

      if (iceTransport == mICETransport) {
        ZS_LOG_DEBUG(log("attach called but passed in same attachment value"))
        return;
      }

      // kick start step to fix up state later
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();

      if (mICETransport) {
        ZS_LOG_DEBUG(log("detaching current ICE transport") + ZS_PARAM("ice transport", mICETransport->getID()))
        mICETransport->detach(*this);
      }

      if (!iceTransport) return;

      ZS_LOG_DEBUG(log("attaching new ICE transport") + ZS_PARAM("ice transport", iceTransport->getID()))

      mICETransport = iceTransport;
      mICETransport->attach(mThisWeak.lock());
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::start(TransportInfoPtr localTransportInfo)
    {
      ZS_LOG_DEBUG(log("stop"))

      AutoRecursiveLock lock(getLock());

      ZS_LOG_DEBUG(log("start called"))

      if ((isShuttingDown()) ||
          (isShutdown())) {
        ZS_LOG_WARNING(Detail, log("already shutdown"));
        return;
      }

      get(mStartCalled) = true;

      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::stop()
    {
      ZS_LOG_DEBUG(log("stop"))

      AutoRecursiveLock lock(getLock());

      if ((isShuttingDown()) ||
          (isShutdown())) {
        ZS_LOG_TRACE(log("already shutting down/shutdown"))
        return;
      }

      mGracefulShutdownReference = mThisWeak.lock();

      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    IDTLSTransport::ConnectionStates DTLSTransport::getState(
                                                           WORD *outError,
                                                           String *outReason
                                                           )
    {
      AutoRecursiveLock lock(getLock());

      ZS_LOG_DEBUG(log("get state") + ZS_PARAM("current state", IDTLSTransport::toString(mCurrentState)) + ZS_PARAM("error", mLastError) + ZS_PARAM("reason", mLastErrorReason))

      if (outError) {
        *outError = mLastError;
      }
      if (outReason) {
        *outReason = mLastErrorReason;
      }

      return mCurrentState;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IDTLSTransportForRTPSender
    #pragma mark

    //-------------------------------------------------------------------------
    bool DTLSTransport::sendPacket(
                                   const BYTE *buffer,
                                   size_t bufferLengthInBytes
                                   ) const
    {
      ZS_LOG_TRACE(log("sending packet") + ZS_PARAM("length", bufferLengthInBytes))

      UseICETransportPtr transport;

      {
        AutoRecursiveLock lock(getLock());
        if (!mICETransport) {
          ZS_LOG_WARNING(Debug, log("no ice transport is attached"))
          return false;
        }
        transport = mICETransport;
      }

      return transport->sendPacket(buffer, bufferLengthInBytes);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IDTLSTransportForRTPReceiver
    #pragma mark

    //-------------------------------------------------------------------------
    void DTLSTransport::attachRouting(
                                      RTPReceiverPtr inReceiver,
                                      SSRC route
                                      )
    {
      UseRTPReceiverPtr receiver = inReceiver;

      AutoRecursiveLock lock(getLock());
#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::detachRouting(
                                      RTPReceiver &inReceiver,
                                      SSRC route
                                      )
    {
      UseRTPReceiver &receiver = inReceiver;
#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IDTLSTransportForICETransport
    #pragma mark

    //-------------------------------------------------------------------------
    void DTLSTransport::handleReceivedPacket(
                                             ICETransportPtr inIceTransport,
                                             const BYTE *buffer,
                                             size_t bufferLengthInBytes
                                             )
    {
      UseICETransportPtr iceTransport = inIceTransport;

      ZS_LOG_TRACE(log("handle receive packet") + ZS_PARAM("transport", iceTransport->getID()) + ZS_PARAM("length", bufferLengthInBytes))

      // scope: pre-validation check
      {
        AutoRecursiveLock lock(getLock());
        if (iceTransport != mICETransport) {
          ZS_LOG_WARNING(Debug, log("incoming packet was not attached to this session (during re-attachment?)") + ZS_PARAM("received ice transport", iceTransport->getID()) + ZS_PARAM("expecting ice transport", mICETransport ? mICETransport->getID() : 0))
        }

        if (mDTLSContext) {
          // TBD -- Need to check the state of sslstream -- if connected then only dtlspackets can be handled
          if (mDTLSContext->handleIfDTLSContextPacket(buffer, bufferLengthInBytes)) {
            ZS_LOG_TRACE(log("packet was handled by DTLS context"))
            return;
          }
        }
      }

#define TODO_FORWARD_TO_RTC_RECEIVER 1
#define TODO_FORWARD_TO_RTC_RECEIVER 2
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::notifyDTLSContextConnected()
    {
      ZS_LOG_DEBUG(log("notify DTLS context connected"))
      AutoRecursiveLock lock(getLock());

      get(mContextIsConnected) = true;

      // handle asynchronously
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::notifyDTLSContextShutdown()
    {
      ZS_LOG_DEBUG(log("notify DTLS context shutdown"))
      AutoRecursiveLock lock(getLock());

      mDTLSContext.reset(); // no longer have a context

      mGracefulShutdownReference = mThisWeak.lock();

      // handle asynchronously
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IDTLSTransportForDTLSContext
    #pragma mark

    //-------------------------------------------------------------------------
    bool DTLSTransport::sendDTLSContextPacket(
                                              const BYTE *buffer,
                                              size_t bufferLengthInBytes
                                              )
    {
      ZS_THROW_INVALID_ARGUMENT_IF(!buffer)
      ZS_THROW_INVALID_ARGUMENT_IF(bufferLengthInBytes < 1)

      AutoRecursiveLock lock(getLock());

      if (isShutdown()) {
        return false;
      }

      if (!mPendingBuffers) {
        mPendingBuffers = PendingDTLSBufferListPtr(new PendingDTLSBufferList);
      }

      SecureByteBlockPtr secBuffer = OPIHelper::convertToBuffer(buffer, bufferLengthInBytes);
      mPendingBuffers->push_back(secBuffer);

      // send asynchronously
      IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      return false;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IWakeDelegate
    #pragma mark

    //-------------------------------------------------------------------------
    void DTLSTransport::onWake()
    {
      ZS_LOG_DEBUG(log("wake"))

      step(); // do not call within lock
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => IICETransportDelegate
    #pragma mark

    //-------------------------------------------------------------------------
    void DTLSTransport::onICETransportCandidatesChangeDetected(IICETransportPtr transport)
    {
      // ignored
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::onICETransportCandidate(
                                                IICETransportPtr transport,
                                                IICETransport::CandidateInfoPtr candidate
                                                )
    {
      // ignored
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::onICETransportEndOfCandidates(IICETransportPtr trannsport)
    {
      // ignored
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::onICETransportActiveCandidate(
                                                      IICETransportPtr transport,
                                                      IICETransport::CandidateInfoPtr localCandidate,
                                                      IICETransport::CandidateInfoPtr remoteCandidate
                                                      )
    {
      // ignored
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::onICETransportStateChanged(
                                                   IICETransportPtr transport,
                                                   IICETransport::ConnectionStates state
                                                   )
    {
      ZS_LOG_DEBUG(log("ice transport state changed") + ZS_PARAM("session", transport->getID()) + ZS_PARAM("state", IICETransport::toString(state)))

      step(); // do not call within lock
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport => (internal)
    #pragma mark

    //-------------------------------------------------------------------------
    Log::Params DTLSTransport::log(const char *message) const
    {
      ElementPtr objectEl = Element::create("ortc::DTLSTransport");
      OPIHelper::debugAppend(objectEl, "id", mID);
      return Log::Params(message, objectEl);
    }

    //-------------------------------------------------------------------------
    Log::Params DTLSTransport::debug(const char *message) const
    {
      return Log::Params(message, toDebug());
    }

    //-------------------------------------------------------------------------
    ElementPtr DTLSTransport::toDebug() const
    {
      ElementPtr resultEl = Element::create("ortc::DTLSTransport");

      OPIHelper::debugAppend(resultEl, "id", mID);

      OPIHelper::debugAppend(resultEl, "graceful shutdown", (bool)mGracefulShutdownReference);

      OPIHelper::debugAppend(resultEl, "subscribers", mSubscriptions.size());
      OPIHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

      OPIHelper::debugAppend(resultEl, "state", IDTLSTransport::toString(mCurrentState));
      OPIHelper::debugAppend(resultEl, "start called", mStartCalled);

      OPIHelper::debugAppend(resultEl, "error", mLastError);
      OPIHelper::debugAppend(resultEl, "error reason", mLastErrorReason);

      OPIHelper::debugAppend(resultEl, "local", mLocal ? mLocal->toDebug() : ElementPtr());
      OPIHelper::debugAppend(resultEl, "remote", mRemote ? mRemote->toDebug() : ElementPtr());

      OPIHelper::debugAppend(resultEl, "ice transport", UseICETransport::toDebug(mICETransport));
      OPIHelper::debugAppend(resultEl, "ice socket subscription", (bool)mICETransportSubscription);

      OPIHelper::debugAppend(resultEl, "dtls context", mDTLSContext ? mDTLSContext->getID() : 0);

      OPIHelper::debugAppend(resultEl, "dtls context told to freeze", mContextToldToFreeze);
      OPIHelper::debugAppend(resultEl, "dtls context told to shutdown", mContextToldToShutdown);

      OPIHelper::debugAppend(resultEl, "dtls context did connect", mContextIsConnected);

      OPIHelper::debugAppend(resultEl, "dtls pending buffers", mPendingBuffers ? mPendingBuffers->size() : 0);

      return resultEl;
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::isShuttingDown() const
    {
      return (bool)mGracefulShutdownReference;
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::isShutdown() const
    {
      if (mGracefulShutdownReference) return false;
      return ConnectionState_Closed == mCurrentState;
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::step()
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

        if (!stepICESession()) return;
        if (!stepFixState()) return;
      }

      stepSendPending();
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::stepICESession()
    {
      if (!mStartCalled) {
        ZS_LOG_TRACE(log("waiting for start to be called"))
        return false;
      }

      // scope: check the ICE transport state
      {
        if (!mICETransport) {
          ZS_LOG_TRACE(log("waiting for association to ICE transport to be attached"))
          goto dtls_frozen;
        }

        WORD error = 0;
        String reason;
        switch (mICETransport->getState(&error, &reason)) {
          case IICETransport::ConnectionState_New:
          case IICETransport::ConnectionState_Searching:
          {
            ZS_LOG_TRACE(log("ICE transport is not ready yet"))
            goto dtls_frozen;
          }
          case IICETransport::ConnectionState_Connected:
          case IICETransport::ConnectionState_Completed:
          {
            ZS_LOG_TRACE(log("ICE transport is ready for DTLS"))
            goto dtls_ready;
          }
          case IICETransport::ConnectionState_Haulted:
          {
            ZS_LOG_TRACE(log("ice transport is haulted (wait until connection is established)"))
            goto dtls_frozen;
          }
          case IICETransport::ConnectionState_Closed:
          {
            ZS_LOG_DEBUG(log("ice transport is closed"))
            cancel();
            return false;
          }
        }
      }

    dtls_frozen:
      {
        if (mDTLSContext) {
          if (!mContextToldToFreeze) {
            mDTLSContext->freeze();
            get(mContextToldToFreeze) = true;
          }
        }

        return true;
      }

    dtls_ready:
      {
        if (!mDTLSContext) {

          mDTLSContext = DTLSContext::create(
        		  	  	  	  	  	  	  	 getAssociatedMessageQueue(),
                                             mThisWeak.lock(),
                                             mICETransport->getRole()
                                             );
        }

        if (mContextToldToFreeze) {
          mDTLSContext->unfreeze();
          get(mContextToldToFreeze) = false;
        }
      }

      return true;
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::stepFixState()
    {
      ZS_LOG_TRACE(debug("step fix state"))

      if (!mDTLSContext) {
        setState(ConnectionState_Connecting);
        return false;
      }

      if (!mContextIsConnected) {
        setState(ConnectionState_Connecting);
        return false;
      }

      if (mContextToldToFreeze) {
        setState(ConnectionState_ConnectedButTransportDetached);
        return false;
      }

      setState(ConnectionState_Connected);
      return true;
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::stepSendPending()
    {
      UseICETransportPtr transport;
      PendingDTLSBufferListPtr pending;

      {
        AutoRecursiveLock lock(getLock());
        if (!mICETransport) {
          ZS_LOG_WARNING(Debug, log("ice transport is not attached"))
          return false;
        }

        pending = mPendingBuffers;
        mPendingBuffers.reset();
        transport = mICETransport;
      }

      ZS_LOG_TRACE(debug("step send pending") + ZS_PARAM("transport", transport ? transport->getID() : 0) + ZS_PARAM("size", pending ? pending->size() : 0))

      if (!pending) return true;

      for (PendingDTLSBufferList::iterator iter = pending->begin(); iter != pending->end(); ++iter)
      {
        const SecureByteBlockPtr &buffer = (*iter);

        transport->sendPacket(*buffer, buffer->SizeInBytes());
      }

      return true;
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::cancel()
    {
      //.......................................................................
      // start the shutdown process

      // WARNING: Don't tell ICE session to stop just because DTLS session is
      //          shutting down.

      if (mDTLSContext) {
        if (!mContextToldToShutdown) {
          mDTLSContext->shutdown();
          get(mContextToldToShutdown) = true;
        }
      }

      //.......................................................................
      // try to gracefully shutdown

      if (!mGracefulShutdownReference) mGracefulShutdownReference = mThisWeak.lock();

      if (mGracefulShutdownReference) {
        if (mDTLSContext) {
          ZS_LOG_DEBUG(log("waiting for the DTLS context to report itself as shutdown"))
          return;
        }
      }

      //.......................................................................
      // final cleanup

      if (mICETransportSubscription) {
        mICETransportSubscription->cancel();
        mICETransportSubscription.reset();
      }

      mICETransport.reset();

      if (mDTLSContext) {
        mDTLSContext->detach();
        mDTLSContext.reset();
      }

      setState(ConnectionState_Closed);

      // make sure to cleanup any final reference to self
      mGracefulShutdownReference.reset();

      mPendingBuffers.reset();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::setState(ConnectionStates state)
    {
      if (state == mCurrentState) return;

      ZS_LOG_DETAIL(debug("state changed") + ZS_PARAM("old state", IDTLSTransport::toString(mCurrentState)) + ZS_PARAM("new state", state))

      mCurrentState = state;

      DTLSTransportPtr pThis = mThisWeak.lock();
      if (pThis) {
        mSubscriptions.delegate()->onDTLSTransportStateChanged(pThis, mCurrentState);
      }
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::setError(WORD errorCode, const char *inReason)
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

      ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("error", mLastError) + ZS_PARAM("reason", mLastErrorReason))
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport::DTLSContext
    #pragma mark

    //-------------------------------------------------------------------------
    DTLSTransport::DTLSContext::DTLSContext(
    										IMessageQueuePtr queue,
                                            DTLSTransportPtr transport,
                                            bool inClientRole
                                            ) :
	  MessageQueueAssociator(queue),
      mTransport(transport),
      mInClientRole(inClientRole)
    {
    }

    //-------------------------------------------------------------------------
    DTLSTransport::DTLSContext::~DTLSContext()
    {
      mThisWeak.reset();
      cancel();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::init()
    {
    	//set up the dtls context here
    	//if(!mSSLStreammanager)
    	{
    		mSSLStreammanager = ISSLStreamManager::create(mThisWeak.lock());
    		mDTLSTransportStream = mSSLStreammanager->getSSLTransportStream();
    		//call getSSLTransportStream here.
    	}

    	//setupdtls() -- ssl related parameters
    	if (!SetupDtls())
    	{
    	    std::cout << "Error initializing DTLS";
    	    //TBD - Need to set the state of dtlscontext/dtlstransport object
    	    //dtls_state_ = STATE_CLOSED;
    	    return;
    	 }
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::DTLSContext::SetupDtls() {

      //check if reset is required here
      //mSSLStreammanager.reset();

      if (!mSSLStreammanager) {
        std::cout << "Failed to get dtls stream manager instance.";
        return false;
      }

#if 1 // TBD -- generate ientity
      std::string remote_fingerprint_algorithm_ = ortc::internal::DIGEST_SHA_1;
	  std::vector<std::string> srtp_ciphers_;
  	  unsigned char digest[20];
      size_t digest_len;
#endif

      mSSLStreammanager->SetMode(SSL_MODE_DTLS);

  	  //If the role is contolled that means client --
      if(mInClientRole)
      {
    	  //generate the identity
      	  std::string param;
    	  std::string strParam = "ortcclient";
    	  param = strParam;

    	  //sslId1 = sslId2->Generate(param);
    	  clientidentity_ = SSLIdentity::Generate(param);

    	  //set the identity for sslstreammanager
    	  mSSLStreammanager->SetIdentity(clientidentity_);

    	  //set the role for sslstreammanager
    	  mSSLStreammanager->SetServerRole(SSL_CLIENT);
      }else
      {
    	  //generate the identity
      	  std::string param;
    	  std::string strParam = "ortcserver";
    	  param = strParam;

    	  //sslId1 = sslId2->Generate(param);
    	  serveridentity_ = SSLIdentity::Generate(param);

    	  //set the identity for sslstreammanager
    	  mSSLStreammanager->SetIdentity(serveridentity_);

    	  mSSLStreammanager->SetServerRole(SSL_SERVER);
      }

      //peercertificate digest set
	  if (!mSSLStreammanager->SetPeerCertificateDigest(remote_fingerprint_algorithm_, digest, digest_len))
	  {
		  std::cout << "Couldn't set DTLS certificate digest" << std::endl;
	  }

	  // Set up DTLS-SRTP, if it's been enabled.
	  srtp_ciphers_.push_back(kAES_CM_HMAC_SHA1_80);
	  if (!srtp_ciphers_.empty())
	  {
		if (!mSSLStreammanager->SetDtlsSrtpCiphers(srtp_ciphers_))
		{
			std::cout << "Couldn't set DTLS-SRTP ciphers" << std::endl;
		}
	  }
	  else
	  {
		std::cout << "Not using SRTP" << std::endl;
	  }

      //start dtls handshake with peer -- This will initiate the state change of sslstreammanager class
      mSSLStreammanager->StartSSLWithPeer();

     std::cout << "DTLS setup complete.";
     return true;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport::DTLSContext => friend DTLSTransport
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr DTLSTransport::DTLSContext::toDebug(DTLSContextPtr context)
    {
      if (!context) return ElementPtr();
      return context->toDebug();
    }

    //-------------------------------------------------------------------------
    DTLSTransport::DTLSContextPtr DTLSTransport::DTLSContext::create(
    																 IMessageQueuePtr queue,
                                                                     DTLSTransportPtr transport,
                                                                     IICETransport::Roles role
                                                                     )
    {
      DTLSContextPtr pThis(new DTLSContext(queue, transport, IICETransport::Role_Controlled == role ? true : false));
      pThis->mThisWeak = pThis;
      pThis->init();
      return pThis;
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::detach()
    {
      ZS_LOG_DEBUG(log("transport is detached"))

      AutoRecursiveLock lock(getLock());
      mTransport.reset();

      cancel();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::freeze()
    {
      ZS_LOG_DEBUG(log("freeze"))

      AutoRecursiveLock lock(getLock());
#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::unfreeze()
    {
      ZS_LOG_DEBUG(log("unfreeze"))

      AutoRecursiveLock lock(getLock());
#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::shutdown()
    {
      ZS_LOG_DEBUG(log("shutdown"))

      AutoRecursiveLock lock(getLock());

      // NOTE: shutting down make take time due to graceful negotiated closure?
#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::DTLSContext::handleIfDTLSContextPacket(
                                                               const BYTE *buffer,
                                                               size_t bufferLengthInBytes
                                                               )
    {
      ZS_LOG_DEBUG(log("handle if dtls context packet") + ZS_PARAM("length", bufferLengthInBytes))
#define TODO 1
#define TODO 2
#if 1
	  if (IsDtlsPacket((const char*)buffer, bufferLengthInBytes)) {
		  // Sanity check we're not passing junk that
		  // just looks like DTLS.
		  const UINT* tmp_data = reinterpret_cast<const UINT* >(buffer);
		  size_t tmp_size = bufferLengthInBytes;
		  while (tmp_size > 0) {
			if (tmp_size < kDtlsRecordHeaderLen)
			  return false;  // Too short for the header

			size_t record_len = (tmp_data[11] << 8) | (tmp_data[12]);
			if ((record_len + kDtlsRecordHeaderLen) > tmp_size)
			  return false;  // Body too short

			tmp_data += record_len + kDtlsRecordHeaderLen;
			tmp_size -= record_len + kDtlsRecordHeaderLen;
		  }
		  
	  //}
#endif	  
      //if dtlspacket then get the writer object from sslstreammanager class and write the data.
      //TBD//call get
      openpeer::services::ITransportStreamWriterPtr writerStream;
	  writerStream = mDTLSTransportStream->getWriter();
	  writerStream->write(buffer,bufferLengthInBytes);
	  }else
	  {
		  std::cout << "Not a DTLS Context Packet" << std::endl;
		  return false;
	  }
      return true;
    }

#if 1
    //-----------------------------------------------------------------------
	#pragma mark
	#pragma mark DTLSTransport => ISSLStreamManagerDelegate
	#pragma mark

    void DTLSTransport::DTLSContext::onSSLStreamStateChanged(
								ISSLStreamManagerPtr sslstreammanager,
								ISSLStreamManager::SSLConnectionStates state
								)
    {
    	ZS_LOG_DEBUG(log("ice transport state changed") + ZS_PARAM("state", ISSLStreamManager::toString(state)))
		printf("\n!!! Inside ortc_DTLScontext : ..... onSSLStreamStateChanged().....!!!\n");
    }
#endif

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark DTLSTransport::DTLSContext => (internal)
    #pragma mark

    //-------------------------------------------------------------------------
    Log::Params DTLSTransport::DTLSContext::log(const char *message) const
    {
      ElementPtr objectEl = Element::create("ortc::DTLSTransport::DTLSContext");
      OPIHelper::debugAppend(objectEl, "id", mID);
      return Log::Params(message, objectEl);
    }

    //-------------------------------------------------------------------------
    Log::Params DTLSTransport::DTLSContext::debug(const char *message) const
    {
      return Log::Params(message, toDebug());
    }

    //-------------------------------------------------------------------------
    ElementPtr DTLSTransport::DTLSContext::toDebug() const
    {
      ElementPtr resultEl = Element::create("ortc::DTLSTransport::DTLSContext");

      OPIHelper::debugAppend(resultEl, "id", mID);

      OPIHelper::debugAppend(resultEl, "role is client", mInClientRole);
      OPIHelper::debugAppend(resultEl, "role is server", !mInClientRole);
      OPIHelper::debugAppend(resultEl, "dtls transport", (bool)mTransport.lock());

#define TODO 1
#define TODO 2

      return resultEl;
    }

    //-------------------------------------------------------------------------
    RecursiveLock &DTLSTransport::DTLSContext::getLock() const
    {
      TransportPtr outer = mTransport.lock();
      if (outer) {return outer->getLock();}
      return mBogusLock;
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::cancel()
    {
      ZS_LOG_DEBUG(log("cancel"))

      mTransport.reset();

#define TODO 1
#define TODO 2
    }

    //-------------------------------------------------------------------------
    bool DTLSTransport::DTLSContext::sendPacket(
                                                const BYTE *buffer,
                                                size_t bufferLengthInBytes
                                                ) const
    {
      ZS_LOG_TRACE(log("send packet") + ZS_PARAM("length", bufferLengthInBytes))

      TransportPtr outer = mTransport.lock();
      if (!outer) {
        ZS_LOG_WARNING(Debug, log("cannot send packet as transport has shutdown"))
        return false;
      }

      //TBD -- Read the buffer using "dtlstransportstream reader" wherer the data has been written by dtls stack
      //send the data to other peer using sendDTLSContextPacket


      return outer->sendDTLSContextPacket(buffer, bufferLengthInBytes);
    }


    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::notifyConnected()
    {
      ZS_LOG_DEBUG(log("notify connected"))

      TransportPtr outer = mTransport.lock();
      if (!outer) {
        ZS_LOG_TRACE(log("cannot notify of connected status as transport is gone (okay during shutdown)"))
        return;
      }

      outer->notifyDTLSContextConnected();
    }

    //-------------------------------------------------------------------------
    void DTLSTransport::DTLSContext::notifyShutdown()
    {
      ZS_LOG_DEBUG(log("notify shutdown"))

      TransportPtr outer = mTransport.lock();
      if (!outer) {
        ZS_LOG_TRACE(log("cannot notify shutdown as transport is gone (okay during shutdown)"))
        return;
      }

      outer->notifyDTLSContextShutdown();
    }

  }

  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark IDTLSTransport
  #pragma mark

  //---------------------------------------------------------------------------
  const char *IDTLSTransport::toString(ConnectionStates state)
  {
    switch (state) {
      case ConnectionState_New:                             return "New";
      case ConnectionState_Connecting:                      return "Connecting";
      case ConnectionState_Connected:                       return "Connected";
      case ConnectionState_ConnectedButTransportDetached:   return "Connected but transport detached";
      case ConnectionState_Closed:                          return "Closed";
    }
    return "UNDEFINED";
  }

  //---------------------------------------------------------------------------
  const char *IDTLSTransport::toString(Options option)
  {
    switch (option) {
      case Option_Unknown:  return "Unknown";
    }
    return "UNDEFINED";
  }


  //---------------------------------------------------------------------------
  ElementPtr IDTLSTransport::toDebug(IDTLSTransportPtr transport)
  {
    return internal::DTLSTransport::toDebug(transport);
  }

  //---------------------------------------------------------------------------
  IDTLSTransportPtr IDTLSTransport::create(
                                           IDTLSTransportDelegatePtr delegate,
                                           IICETransportPtr iceTransport
                                           )
  {
    return internal::IDTLSTransportFactory::singleton().create(delegate, iceTransport);
  }

  //---------------------------------------------------------------------------
  IDTLSTransport::CapabilitiesPtr IDTLSTransport::getCapabilities()
  {
    return internal::DTLSTransport::getCapabilities();
  }

  //---------------------------------------------------------------------------
  IDTLSTransport::TransportInfoPtr IDTLSTransport::filterParams(
                                                                TransportInfoPtr params,
                                                                CapabilitiesPtr capabilities
                                                                )
  {
    return internal::DTLSTransport::filterParams(params, capabilities);
  }

  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark IDTLSTransport::Capabilities
  #pragma mark

  //---------------------------------------------------------------------------
  IDTLSTransport::CapabilitiesPtr IDTLSTransport::Capabilities::create()
  {
    return CapabilitiesPtr(new Capabilities);
  }

  //---------------------------------------------------------------------------
  ElementPtr IDTLSTransport::Capabilities::toDebug() const
  {
    if (mOptions.size() < 1) return ElementPtr();

    ElementPtr resultEl = Element::create("IDTLSTransport::Capabilities");

    for (OptionsList::const_iterator iter = mOptions.begin(); iter != mOptions.end(); ++iter)
    {
      const Options &option = (*iter);
      OPIHelper::debugAppend(resultEl, "option", IDTLSTransport::toString(option));
    }

    return resultEl;
  }

  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  //---------------------------------------------------------------------------
  #pragma mark
  #pragma mark IDTLSTransport::TransportInfo
  #pragma mark

  //---------------------------------------------------------------------------
  IDTLSTransport::TransportInfoPtr IDTLSTransport::TransportInfo::create()
  {
    return TransportInfoPtr(new TransportInfo);
  }

  //---------------------------------------------------------------------------
  ElementPtr IDTLSTransport::TransportInfo::toDebug() const
  {
    ElementPtr resultEl = Element::create("ortc::IDTLSTransport::TransportInfo");

    return resultEl->hasChildren() ? resultEl : ElementPtr();
  }

}
