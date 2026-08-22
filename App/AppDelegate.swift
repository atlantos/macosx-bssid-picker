// SPDX-License-Identifier: GPL-3.0-only

import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
  private let controller = ApplicationController()

  func applicationDidFinishLaunching(_ notification: Notification) {
    controller.start()
  }

  func applicationWillTerminate(_ notification: Notification) {
    controller.stop()
  }
}
