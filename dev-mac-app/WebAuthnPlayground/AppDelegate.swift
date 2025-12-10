//
//  AppDelegate.swift
//  WebAuthnPlayground
//
//  Copyright (c) 2025 Vault12, Inc.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}
