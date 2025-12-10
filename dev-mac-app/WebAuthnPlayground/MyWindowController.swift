//
//  MyWindowController.swift
//  WebAuthnPlayground
//
//  Copyright (c) 2025 Vault12, Inc.
//

import Foundation
import Cocoa

class MyWindowController: NSWindowController {
    override func windowDidLoad() {
        super.windowDidLoad()

        window?.center()
        window?.makeKeyAndOrderFront(nil)
    }
}
