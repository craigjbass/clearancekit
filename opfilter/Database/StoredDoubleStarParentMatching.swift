//
//  StoredDoubleStarParentMatching.swift
//  opfilter
//

import Foundation

// Rows written before migration 012 hold NULL. NULL maps to the value that
// FAARule decoding gives for a missing key, so the canonical JSON of those
// rows does not change and their signature still verifies.
func storedDoubleStarParentMatching(_ storedValue: String?, pattern: String) -> DoubleStarParentMatching? {
    guard let storedValue else { return .implied(by: pattern) }
    return DoubleStarParentMatching(rawValue: storedValue)
}
