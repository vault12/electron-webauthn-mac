#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import "WebAuthnMacBridge.h"
#include <napi.h>

class WebAuthnMacAddon : public Napi::ObjectWrap<WebAuthnMacAddon> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "WebAuthnMacAddon", {
            InstanceMethod("createCredential", &WebAuthnMacAddon::CreateCredential),
            InstanceMethod("getCredential", &WebAuthnMacAddon::GetCredential),
            InstanceMethod("managePasswords", &WebAuthnMacAddon::ManagePasswords)
        });

        Napi::FunctionReference* constructor = new Napi::FunctionReference();
        *constructor = Napi::Persistent(func);
        env.SetInstanceData(constructor);

        exports.Set("WebAuthnMacAddon", func);
        return exports;
    }

    WebAuthnMacAddon(const Napi::CallbackInfo& info) : Napi::ObjectWrap<WebAuthnMacAddon>(info) {}

private:

    struct AsyncDictData {
        Napi::Promise::Deferred* deferred;
        void* result;  // CFRetained NSDictionary
        std::string error;
        bool hasError;

        ~AsyncDictData() {
            if (result) {
                CFRelease(result);
            }
        }
    };

    // Helper function to convert Napi::Object to NSDictionary (recursive)
    static NSDictionary* NapiObjectToNSDictionary(Napi::Object obj) {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        Napi::Array keys = obj.GetPropertyNames();

        for (uint32_t i = 0; i < keys.Length(); i++) {
            Napi::Value keyVal = keys[i];
            std::string key = keyVal.As<Napi::String>();
            NSString* nsKey = [NSString stringWithUTF8String:key.c_str()];

            Napi::Value val = obj.Get(key);

            if (val.IsString()) {
                dict[nsKey] = [NSString stringWithUTF8String:val.As<Napi::String>().Utf8Value().c_str()];
            } else if (val.IsBoolean()) {
                dict[nsKey] = @(val.As<Napi::Boolean>().Value());
            } else if (val.IsNumber()) {
                dict[nsKey] = @(val.As<Napi::Number>().DoubleValue());
            } else if (val.IsArray()) {
                Napi::Array arr = val.As<Napi::Array>();
                NSMutableArray* nsArr = [NSMutableArray arrayWithCapacity:arr.Length()];
                for (uint32_t j = 0; j < arr.Length(); j++) {
                    Napi::Value item = arr[j];
                    if (item.IsString()) {
                        [nsArr addObject:[NSString stringWithUTF8String:item.As<Napi::String>().Utf8Value().c_str()]];
                    } else if (item.IsObject()) {
                        [nsArr addObject:NapiObjectToNSDictionary(item.As<Napi::Object>())];
                    }
                }
                dict[nsKey] = nsArr;
            } else if (val.IsObject()) {
                dict[nsKey] = NapiObjectToNSDictionary(val.As<Napi::Object>());
            }
        }

        return dict;
    }

    // Helper function to convert NSDictionary to Napi::Object (recursive)
    static Napi::Object NSDictionaryToNapiObject(Napi::Env env, void* dictPtr) {
        NSDictionary* dict = (__bridge NSDictionary*)dictPtr;
        Napi::Object obj = Napi::Object::New(env);

        for (NSString* key in dict) {
            id value = dict[key];
            std::string keyStr = [key UTF8String];

            if ([value isKindOfClass:[NSString class]]) {
                obj.Set(keyStr, Napi::String::New(env, [(NSString*)value UTF8String]));
            } else if ([value isKindOfClass:[NSNumber class]]) {
                NSNumber* num = (NSNumber*)value;
                const char* type = [num objCType];
                if (strcmp(type, @encode(BOOL)) == 0 || strcmp(type, "c") == 0) {
                    obj.Set(keyStr, Napi::Boolean::New(env, [num boolValue]));
                } else {
                    obj.Set(keyStr, Napi::Number::New(env, [num doubleValue]));
                }
            } else if ([value isKindOfClass:[NSArray class]]) {
                NSArray* arr = (NSArray*)value;
                Napi::Array napiArr = Napi::Array::New(env, [arr count]);
                for (NSUInteger i = 0; i < [arr count]; i++) {
                    id item = arr[i];
                    if ([item isKindOfClass:[NSString class]]) {
                        napiArr[i] = Napi::String::New(env, [(NSString*)item UTF8String]);
                    } else if ([item isKindOfClass:[NSDictionary class]]) {
                        napiArr[i] = NSDictionaryToNapiObject(env, (__bridge void*)item);
                    }
                }
                obj.Set(keyStr, napiArr);
            } else if ([value isKindOfClass:[NSDictionary class]]) {
                obj.Set(keyStr, NSDictionaryToNapiObject(env, (__bridge void*)value));
            }
        }

        return obj;
    }

    Napi::Value CreateCredential(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 1 || !info[0].IsObject()) {
            Napi::TypeError::New(env, "[webauthn_mac_addon.mm] CreateCredential(): Expected options object").ThrowAsJavaScriptException();
            return env.Null();
        }

        NSDictionary* options = NapiObjectToNSDictionary(info[0].As<Napi::Object>());

        auto* deferred = new Napi::Promise::Deferred(env);
        Napi::Promise promise = deferred->Promise();

        // Create threadsafe function for callback
        napi_threadsafe_function tsfn;
        napi_status status = napi_create_threadsafe_function(
            env,
            nullptr,
            nullptr,
            Napi::String::New(env, "CreateCredentialCallback"),
            0,
            1,
            nullptr,
            nullptr,
            nullptr,
            [](napi_env env, napi_value js_callback, void* context, void* data) {
                auto* asyncData = static_cast<AsyncDictData*>(data);
                if (asyncData && asyncData->deferred) {
                    Napi::Env napi_env(env);
                    Napi::HandleScope scope(napi_env);
                    if (asyncData->hasError) {
                        asyncData->deferred->Reject(Napi::Error::New(napi_env, asyncData->error).Value());
                    } else {
                        Napi::Object result = NSDictionaryToNapiObject(napi_env, asyncData->result);
                        asyncData->deferred->Resolve(result);
                    }
                    delete asyncData->deferred;
                    delete asyncData;
                }
            },
            &tsfn
        );

        if (status != napi_ok) {
            delete deferred;
            Napi::Error::New(env, "[webauthn_mac_addon.mm] CreateCredential(): Failed to create threadsafe function").ThrowAsJavaScriptException();
            return env.Null();
        }

        [WebAuthnMacBridge createCredential:options completion:^(NSDictionary* result, NSError* error) {
            auto* asyncData = new AsyncDictData{
                deferred,
                result ? (void*)CFBridgingRetain(result) : nullptr,
                error ? std::string([[error localizedDescription] UTF8String]) : "",
                error != nil
            };

            napi_call_threadsafe_function(tsfn, asyncData, napi_tsfn_blocking);
            napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        }];

        return promise;
    }

    Napi::Value GetCredential(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 1 || !info[0].IsObject()) {
            Napi::TypeError::New(env, "[webauthn_mac_addon.mm] GetCredential(): Expected options object").ThrowAsJavaScriptException();
            return env.Null();
        }

        NSDictionary* options = NapiObjectToNSDictionary(info[0].As<Napi::Object>());

        auto* deferred = new Napi::Promise::Deferred(env);
        Napi::Promise promise = deferred->Promise();

        // Create threadsafe function for callback
        napi_threadsafe_function tsfn;
        napi_status status = napi_create_threadsafe_function(
            env,
            nullptr,
            nullptr,
            Napi::String::New(env, "GetCredentialCallback"),
            0,
            1,
            nullptr,
            nullptr,
            nullptr,
            [](napi_env env, napi_value js_callback, void* context, void* data) {
                auto* asyncData = static_cast<AsyncDictData*>(data);
                if (asyncData && asyncData->deferred) {
                    Napi::Env napi_env(env);
                    Napi::HandleScope scope(napi_env);
                    if (asyncData->hasError) {
                        asyncData->deferred->Reject(Napi::Error::New(napi_env, asyncData->error).Value());
                    } else {
                        Napi::Object result = NSDictionaryToNapiObject(napi_env, asyncData->result);
                        asyncData->deferred->Resolve(result);
                    }
                    delete asyncData->deferred;
                    delete asyncData;
                }
            },
            &tsfn
        );

        if (status != napi_ok) {
            delete deferred;
            Napi::Error::New(env, "[webauthn_mac_addon.mm] GetCredential(): Failed to create threadsafe function").ThrowAsJavaScriptException();
            return env.Null();
        }

        [WebAuthnMacBridge getCredential:options completion:^(NSDictionary* result, NSError* error) {
            auto* asyncData = new AsyncDictData{
                deferred,
                result ? (void*)CFBridgingRetain(result) : nullptr,
                error ? std::string([[error localizedDescription] UTF8String]) : "",
                error != nil
            };

            napi_call_threadsafe_function(tsfn, asyncData, napi_tsfn_blocking);
            napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        }];

        return promise;
    }

    Napi::Value ManagePasswords(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        [WebAuthnMacBridge managePasswords];
        return env.Undefined();
    }
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    return WebAuthnMacAddon::Init(env, exports);
}

NODE_API_MODULE(webauthn_mac_addon, Init)
