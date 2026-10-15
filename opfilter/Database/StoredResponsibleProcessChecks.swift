//
//  StoredResponsibleProcessChecks.swift
//  opfilter
//

import Foundation

// Rows written before migration 014 hold NULL. NULL maps to the default list,
// which FAARule encoding omits, so the canonical JSON of those rows does not
// change and their signature still verifies. The default list is written back
// as NULL for the same reason. Any other list, including the empty list, is
// stored as a JSON array.
func storedResponsibleProcessChecks(_ storedValue: String?) -> [ProcessSignature]? {
    guard let storedValue else { return defaultResponsibleProcessChecks }
    guard let jsonData = storedValue.data(using: .utf8) else { return nil }
    return try? JSONDecoder().decode([ProcessSignature].self, from: jsonData)
}

func columnTextForResponsibleProcessChecks(_ checks: [ProcessSignature]) -> String? {
    guard checks != defaultResponsibleProcessChecks else { return nil }
    guard let encoded = try? JSONEncoder().encode(checks),
          let text = String(data: encoded, encoding: .utf8) else {
        fatalError("Database: Failed to JSON-encode responsible process checks — [ProcessSignature] must always be encodable")
    }
    return text
}
