LOCAL_PATH := $(call my-dir)/../../
BOOST_LIBS_PATH := ./libs/build/android/boost/lib

$(warning $(LOCAL_PATH))
$(warning $(ANDROIDNDK_PATH))
include $(CLEAR_VARS)

#openssl:begin
include $(CLEAR_VARS)
OPENSSL_LIB_PATH := ./libs/build/android/openssl
LOCAL_MODULE := libcrypto
LOCAL_SRC_FILES := \
    $(OPENSSL_LIB_PATH)/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
OPENSSL_LIB_PATH := ./libs/build/android/openssl
LOCAL_MODULE := libssl
LOCAL_SRC_FILES := \
    $(OPENSSL_LIB_PATH)/libssl.a
include $(PREBUILT_STATIC_LIBRARY)
#openssl:end

#cryptopp
include $(CLEAR_VARS)
CRYPTOPP_LIBS_PATH := ./libs/build/android/cryptopp
LOCAL_MODULE := libcryptopp
LOCAL_SRC_FILES := \
    $(CRYPTOPP_LIBS_PATH)/libcryptopp.a
include $(PREBUILT_STATIC_LIBRARY)

#udns
include $(CLEAR_VARS)
UDNS_LIBS_PATH := ./libs/build/android/udns
LOCAL_MODULE := libudns_android
LOCAL_SRC_FILES := \
    $(UDNS_LIBS_PATH)/libudns_android.a
include $(PREBUILT_STATIC_LIBRARY)

#ZsLib
include $(CLEAR_VARS)
ZSLIB_LIBS_PATH := ./libs/build/android/zsLib
LOCAL_MODULE := libzslib_android
LOCAL_SRC_FILES := \
    $(ZSLIB_LIBS_PATH)/libzslib_android.a
include $(PREBUILT_STATIC_LIBRARY)

#Boost libs
include $(CLEAR_VARS)
LOCAL_MODULE := libboost_atomic-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_atomic-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_chrono-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_chrono-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_date_time-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_date_time-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_filesystem-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_filesystem-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_graph-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_graph-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_iostreams-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_iostreams-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_program_options-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_program_options-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_random-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_random-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_regex-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_regex-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_signals-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_signals-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_system-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_system-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libboost_thread-gcc-mt-1_53
LOCAL_SRC_FILES := \
    $(BOOST_LIBS_PATH)/libboost_thread-gcc-mt-1_53.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
$(info $(LOCAL_PATH))
LOCAL_CFLAGS	:= -Wall \
-W \
-O2 \
-pipe \
-fPIC \
-frtti \
-fexceptions \
-D_ANDROID \
$(info $(LOCAL_PATH))

LOCAL_MODULE    := ortc_android

LOCAL_C_INCLUDES:= \
$(LOCAL_PATH) \
$(LOCAL_PATH)/libs/op-services-cpp \
$(LOCAL_PATH)/libs/build/android/boost/include/boost-1_53 \
$(LOCAL_PATH)/libs/zsLib \
$(LOCAL_PATH)/libs \
$(LOCAL_PATH)/libs/build/android/cryptopp/include \
$(LOCAL_PATH)/libs/webrtc/webrtc/voice_engine/include \
$(LOCAL_PATH)/libs/webrtc \
$(LOCAL_PATH)/libs/webrtc/webrtc \
$(LOCAL_PATH)/libs/webrtc/webrtc/video_engine/include \
$(LOCAL_PATH)/libs/webrtc/webrtc/modules/video_capture/include \
$(LOCAL_PATH)/ortc/internal/dtls \
$(LOCAL_PATH)/libs/openssl/include \
$(ANDROIDNDK_PATH)/sources/cxx-stl/gnu-libstdc++/4.7/include \
$(ANDROIDNDK_PATH)/sources/cxx-stl/gnu-libstdc++/4.7/libs/armeabi/include \
$(ANDROIDNDK_PATH)/platforms/android-9/arch-arm/usr/include \

LOCAL_SRC_FILES := ortc/cpp/ortc.cpp \
ortc/cpp/ortc_Factory.cpp \
ortc/cpp/ortc_Helper.cpp \
ortc/cpp/ortc_ICETransport.cpp \
ortc/cpp/ortc_MediaEngine.cpp \
ortc/cpp/ortc_MediaManager.cpp \
ortc/cpp/ortc_MediaStream.cpp \
ortc/cpp/ortc_MediaStreamTrack.cpp \
ortc/cpp/ortc_ORTC.cpp \
ortc/cpp/ortc_RTCDataChannel.cpp \
ortc/cpp/ortc_RTCDTMFTrack.cpp \
ortc/cpp/ortc_RTCStream.cpp \
ortc/cpp/ortc_RTCTrack.cpp \
ortc/cpp/ortc_SSLIdentity.cpp \
ortc/cpp/ortc_SSLStreamManager.cpp \
ortc/cpp/ortc_DTLSTransport.cpp \

#ortc/cpp/dtls/ortc_opensslidentity.cc \
#ortc/cpp/dtls/ortc_base64.cc \
#ortc/cpp/dtls/ortc_helpers.cc \
#ortc/cpp/dtls/ortc_stringutils.cc \
#ortc/cpp/dtls/ortc_stringencode.cc \
#ortc/cpp/dtls/ortc_messagedigest.cc \
#ortc/cpp/dtls/ortc_openssldigest.cc \

#$(info $(LOCAL_PATH))

#LOCAL_LDLIBS := -L$(LOCAL_PATH)/libs/build/android/boost/lib -L$(LOCAL_PATH)/libs/build/android/cryptopp -L$(LOCAL_PATH)/libs/build/android/curl -L$(LOCAL_PATH)/libs/build/#android/openssl -L$(LOCAL_PATH)/libs/build/android/op-services-cpp -L$(LOCAL_PATH)/libs/build/android/udns -L$(LOCAL_PATH)/libs/build/android/zsLib

#$(info $(LOCAL_PATH))
#LOCAL_LDLIBS += -lboost_atomic-gcc-mt-1_53 -lboost_chrono-gcc-mt-1_53 -lboost_date_time-gcc-mt-1_53 -lboost_filesystem-gcc-mt-1_53 -lboost_graph-gcc-mt-1_53 -lboost_random-#gcc-mt-1_53 -lboost_regex-gcc-mt-1_53 -lboost_signals-gcc-mt-1_53 -lboost_system-gcc-mt-1_53 -lboost_thread-gcc-mt-1_53 -lcrypto -lcryptopp -lcurl -lhfservices_android -lssl -#ludns_android -lzslib_android

LOCAL_LDLIBS += -lgnustl_static -lsupc++ -llog -L$(ANDROIDNDK_PATH)/sources/cxx-stl/gnu-libstdc++/4.4.3/libs/armeabi

LOCAL_STATIC_LIBRARIES := \
libzslib_android \
libboost_atomic-gcc-mt-1_53 \
libboost_chrono-gcc-mt-1_53 \
libboost_date_time-gcc-mt-1_53 \
libboost_filesystem-gcc-mt-1_53 \
libboost_graph-gcc-mt-1_53 \
libboost_iostreams-gcc-mt-1_53 \
libboost_program_options-gcc-mt-1_53 \
libboost_random-gcc-mt-1_53 \
libboost_regex-gcc-mt-1_53 \
libboost_signals-gcc-mt-1_53 \
libboost_system-gcc-mt-1_53 \
libboost_thread-gcc-mt-1_53 \
libcurl \
libssl \
libcrypto \

$(info $(LOCAL_PATH))		
$(info going to build static)
$(info $(ANDROIDNDK_PATH))	
include $(BUILD_STATIC_LIBRARY)

