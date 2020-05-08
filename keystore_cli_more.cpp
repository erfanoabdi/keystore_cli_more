/*
 * Copyright (C) 2020 Erfan Abdi <erfangplus@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <vector>

#include <android/security/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <keystore/keystore.h>
#include <utils/Log.h>
#include <utils/String16.h>

using namespace android;
using namespace keystore;
using android::security::IKeystoreService;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s action [parameter ...]\n", argv[0]);
        return 1;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);
    int result = 0;
    if (service == nullptr) {
        printf("%s: error: could not connect to keystore service\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "getState") == 0) {
        int uid = atoi(argv[2]);
        auto binder_result = service->getState(uid, &result);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        printf("result: %d\n", result);
        return 0;
    }

    if (strcmp(argv[1], "onUserPasswordChanged") == 0) {
        int uid = atoi(argv[2]);
        String16 password = String16(argv[3]);
        auto binder_result = service->onUserPasswordChanged(uid, password, &result);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        printf("result: %d\n", result);
        return 0;
    }

    if (strcmp(argv[1], "onUserAdded") == 0) {
        int uid = atoi(argv[2]);
        int pid = atoi(argv[3]);
        auto binder_result = service->onUserAdded(uid, pid, &result);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        printf("result: %d", result);
        return 0;
    }

    if (strcmp(argv[1], "lock") == 0) {
        int uid = atoi(argv[2]);
        auto binder_result = service->lock(uid, &result);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        printf("result: %d\n", result);
        return 0;
    }

    if (strcmp(argv[1], "unlock") == 0) {
        int uid = atoi(argv[2]);
        String16 password = String16(argv[3]);
        auto binder_result = service->unlock(uid, password, &result);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        printf("result: %d\n", result);
        return 0;
    }

    if (strcmp(argv[1], "list") == 0) {
        String16 prefix = String16(argv[2]);
        int targetUid = atoi(argv[3]);
        std::vector<String16> matches;
        auto binder_result = service->list(prefix, targetUid, &matches);
        if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
            printf("Falure on KeyStore command\n");
            return 1;
        }
        std::vector<String16>::const_iterator it = matches.begin();
        for (; it != matches.end(); ++it) {
            printf("matches: %s\n", String8(*it).string());
        }
        return 0;
    }

    printf("%s: unknown command: %s\n", argv[0], argv[1]);
    return 1;
}
