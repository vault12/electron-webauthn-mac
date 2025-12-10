#import "WebAuthnMacBridge.h"
#import "webauthn_mac_addon-Swift.h"
#import <Foundation/Foundation.h>

@implementation WebAuthnMacBridge

+ (void)createCredential:(NSDictionary*)options completion:(void(^)(NSDictionary* _Nullable result, NSError* _Nullable error))completion {
    [WebAuthnMac createCredential:options completion:completion];
}

+ (void)getCredential:(NSDictionary*)options completion:(void(^)(NSDictionary* _Nullable result, NSError* _Nullable error))completion {
    [WebAuthnMac getCredential:options completion:completion];
}

+ (void)managePasswords {
    [WebAuthnMac managePasswords];
}

@end
