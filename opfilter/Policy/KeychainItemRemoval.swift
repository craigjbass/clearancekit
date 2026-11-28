//
//  KeychainItemRemoval.swift
//  opfilter
//

import Foundation
import Security

/// Deletes every item that matches `query`. The call repeats until no item
/// is left, so duplicates from earlier builds are removed too.
func deleteEveryKeychainItem(matching query: [CFString: Any], itemDescription: String) {
    var deletedCount = 0
    while true {
        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess:
            deletedCount += 1
        case errSecItemNotFound:
            NSLog("Keychain: Deleted %d %@ item(s)", deletedCount, itemDescription)
            return
        default:
            NSLog("Keychain: SecItemDelete failed for %@ after %d deletion(s) (%d)", itemDescription, deletedCount, status)
            return
        }
    }
}
