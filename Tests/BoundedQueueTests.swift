//
//  BoundedQueueTests.swift
//  clearancekitTests
//

import Testing

@Suite("BoundedQueue")
struct BoundedQueueTests {
    @Test("dequeue from empty queue returns nil")
    func dequeueFromEmptyReturnsNil() {
        let queue = BoundedQueue<Int>(capacity: 4)
        #expect(queue.dequeue() == nil)
    }

    @Test("enqueue and dequeue preserves FIFO order")
    func fifoOrdering() {
        let queue = BoundedQueue<Int>(capacity: 4)
        #expect(queue.tryEnqueue(1) == .enqueued)
        #expect(queue.tryEnqueue(2) == .enqueued)
        #expect(queue.tryEnqueue(3) == .enqueued)

        #expect(queue.dequeue() == 1)
        #expect(queue.dequeue() == 2)
        #expect(queue.dequeue() == 3)
    }

    @Test("tryEnqueue returns full when at capacity")
    func fullCapacity() {
        let queue = BoundedQueue<Int>(capacity: 2)
        #expect(queue.tryEnqueue(10) == .enqueued)
        #expect(queue.tryEnqueue(20) == .enqueued)
        #expect(queue.tryEnqueue(30) == .full)
    }

    @Test("count tracks enqueue and dequeue")
    func countAccuracy() {
        let queue = BoundedQueue<Int>(capacity: 4)
        #expect(queue.count == 0)

        #expect(queue.tryEnqueue(1) == .enqueued)
        #expect(queue.count == 1)

        #expect(queue.tryEnqueue(2) == .enqueued)
        #expect(queue.count == 2)

        _ = queue.dequeue()
        #expect(queue.count == 1)

        _ = queue.dequeue()
        #expect(queue.count == 0)
    }

    @Test("wrap-around works correctly after filling and draining")
    func wrapAround() {
        let queue = BoundedQueue<Int>(capacity: 3)

        #expect(queue.tryEnqueue(1) == .enqueued)
        #expect(queue.tryEnqueue(2) == .enqueued)
        #expect(queue.tryEnqueue(3) == .enqueued)

        #expect(queue.dequeue() == 1)
        #expect(queue.dequeue() == 2)

        #expect(queue.tryEnqueue(4) == .enqueued)
        #expect(queue.tryEnqueue(5) == .enqueued)

        #expect(queue.dequeue() == 3)
        #expect(queue.dequeue() == 4)
        #expect(queue.dequeue() == 5)
        #expect(queue.dequeue() == nil)
    }

    @Test("multiple wrap-around cycles preserve correctness")
    func multipleWrapAroundCycles() {
        let queue = BoundedQueue<Int>(capacity: 2)

        for cycle in 0..<5 {
            let base = cycle * 2
            #expect(queue.tryEnqueue(base) == .enqueued)
            #expect(queue.tryEnqueue(base + 1) == .enqueued)
            #expect(queue.dequeue() == base)
            #expect(queue.dequeue() == base + 1)
            #expect(queue.count == 0)
        }
    }

    @Test("capacity of one works")
    func capacityOne() {
        let queue = BoundedQueue<Int>(capacity: 1)
        #expect(queue.tryEnqueue(42) == .enqueued)
        #expect(queue.tryEnqueue(99) == .full)
        #expect(queue.dequeue() == 42)
        #expect(queue.tryEnqueue(99) == .enqueued)
        #expect(queue.dequeue() == 99)
    }
}
