//
//  BoundedQueue.swift
//  opfilter
//

import os

final class BoundedQueue<Element: Sendable>: @unchecked Sendable {
    enum EnqueueResult: Equatable {
        case enqueued
        case full
    }

    private let storage: OSAllocatedUnfairLock<State>

    struct State {
        var buffer: [Element?]
        var head: Int
        var tail: Int
        var count: Int
        let capacity: Int
    }

    init(capacity: Int) {
        precondition(capacity > 0)
        let state = State(
            buffer: Array(repeating: nil, count: capacity),
            head: 0,
            tail: 0,
            count: 0,
            capacity: capacity
        )
        self.storage = OSAllocatedUnfairLock(initialState: state)
    }

    func tryEnqueue(_ element: Element) -> EnqueueResult {
        storage.withLock { state in
            guard state.count < state.capacity else { return .full }
            state.buffer[state.tail] = element
            state.tail = (state.tail + 1) % state.capacity
            state.count += 1
            return .enqueued
        }
    }

    func dequeue() -> Element? {
        storage.withLock { state in
            guard state.count > 0 else { return nil }
            let element = state.buffer[state.head]
            state.buffer[state.head] = nil
            state.head = (state.head + 1) % state.capacity
            state.count -= 1
            return element
        }
    }

    var count: Int {
        storage.withLock { $0.count }
    }
}
