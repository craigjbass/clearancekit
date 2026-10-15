//
//  EventProcessTarget.swift
//  clearancekit
//

import Foundation

struct EventProcessTarget: Equatable {
    let processPath: String
    let signingID: String
    let teamID: String
    let viaSigningID: String?

    init(event: FolderOpenEvent) {
        guard let responsibleProcessPath = event.responsibleProcessPath else {
            processPath = event.processPath
            signingID = event.signingID
            teamID = event.teamID
            viaSigningID = nil
            return
        }
        processPath = responsibleProcessPath
        signingID = event.responsibleSigningID ?? ""
        teamID = event.responsibleTeamID ?? ""
        viaSigningID = event.signingID
    }
}
