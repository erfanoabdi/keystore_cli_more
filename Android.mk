LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := keystore_cli_more
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES += \
    keystore_cli_more.cpp

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libcutils \
    liblog \
    libutils \
    libkeystore_aidl \
    libkeystore_binder

include $(BUILD_EXECUTABLE)
