{
  "targets": [{
    "target_name": "webauthn_mac_addon",
    "conditions": [
      ['OS=="mac"', {
        "sources": [
          "src/webauthn_mac_addon.mm",
          "src/WebAuthnMacBridge.m",
          "src/WebAuthnMac.swift"
        ],
        "include_dirs": [
          "<!@(node -p \"require('node-addon-api').include\")",
          "include",
          "build_swift"
        ],
        "dependencies": [
          "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        "libraries": [],
        "link_settings": {
          "libraries": [
            "<(PRODUCT_DIR)/libSwiftCode.a"
          ]
        },
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions" ],
        "xcode_settings": {
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "CLANG_ENABLE_OBJC_ARC": "YES",
          "SWIFT_OBJC_BRIDGING_HEADER": "include/WebAuthnMacBridge.h",
          "SWIFT_VERSION": "5.0",
          "SWIFT_OBJC_INTERFACE_HEADER_NAME": "webauthn_mac_addon-Swift.h",
          "MACOSX_DEPLOYMENT_TARGET": "11.0",
          "OTHER_CFLAGS": [
            "-ObjC++",
            "-fobjc-arc"
          ],
          "OTHER_LDFLAGS": [
            "-Wl,-rpath,@loader_path"
          ],
          "HEADER_SEARCH_PATHS": [
            "$(SRCROOT)/include",
            "$(CONFIGURATION_BUILD_DIR)",
            "$(SRCROOT)/build/Release",
            "$(SRCROOT)/build_swift"
          ]
        },
        "actions": [
          {
            "action_name": "build_swift",
            "inputs": [
              "src/WebAuthnMac.swift",
              "src/PasskeyManager.swift"
            ],
            "outputs": [
              "build_swift/libSwiftCode.a",
              "build_swift/webauthn_mac_addon-Swift.h"
            ],
            "action": [
              "swiftc",
              "src/WebAuthnMac.swift",
              "src/PasskeyManager.swift",
              "-emit-objc-header-path", "./build_swift/webauthn_mac_addon-Swift.h",
              "-emit-library", "-static", "-o", "./build_swift/libSwiftCode.a",
              "-emit-module", "-module-name", "webauthn_mac_addon"
            ]
          },
          {
            "action_name": "copy_swift_lib",
            "inputs": [
              "<(module_root_dir)/build_swift/libSwiftCode.a"
            ],
            "outputs": [
              "<(PRODUCT_DIR)/libSwiftCode.a"
            ],
            "action": [
              "sh",
              "-c",
              "cp -f <(module_root_dir)/build_swift/libSwiftCode.a <(PRODUCT_DIR)/libSwiftCode.a"
            ]
          }
        ]
      }]
    ]
  }]
}
