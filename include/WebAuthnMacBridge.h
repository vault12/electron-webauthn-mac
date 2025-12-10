#ifndef WebAuthnMacBridge_h
#define WebAuthnMacBridge_h

#import <Foundation/Foundation.h>

@interface WebAuthnMacBridge: NSObject

+ (void)createCredential:(NSDictionary * _Nonnull)options completion:(void(^ _Nonnull)(NSDictionary* _Nullable result, NSError* _Nullable error))completion;
+ (void)getCredential:(NSDictionary * _Nonnull)options completion:(void(^ _Nonnull)(NSDictionary* _Nullable result, NSError* _Nullable error))completion;
+ (void)managePasswords;

@end

#endif
