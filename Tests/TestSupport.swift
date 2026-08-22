// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation

struct RegressionTest {
  let name: String
  let body: () throws -> Void
}

struct RegressionTestFailure: LocalizedError {
  let message: String

  var errorDescription: String? { message }
}

func expect(
  _ condition: @autoclosure () -> Bool,
  _ message: @autoclosure () -> String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  guard condition() else {
    throw RegressionTestFailure(message: "\(file):\(line): \(message())")
  }
}

func expectEqual<Value: Equatable>(
  _ actual: @autoclosure () -> Value,
  _ expected: @autoclosure () -> Value,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  let actualValue = actual()
  let expectedValue = expected()
  try expect(
    actualValue == expectedValue,
    "expected \(String(reflecting: expectedValue)); got \(String(reflecting: actualValue))",
    file: file,
    line: line
  )
}

@main
enum RegressionTestRunner {
  static func main() {
    let tests = macRegistrantDatabaseTests() + scanExportTests()
    var failureCount = 0

    for test in tests {
      do {
        try test.body()
        print("PASS \(test.name)")
      } catch {
        failureCount += 1
        let description = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        FileHandle.standardError.write(Data("FAIL \(test.name): \(description)\n".utf8))
      }
    }

    print("Executed \(tests.count) regression tests; \(failureCount) failed.")
    if failureCount > 0 { exit(EXIT_FAILURE) }
  }
}
