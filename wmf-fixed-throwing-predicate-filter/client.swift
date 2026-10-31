import Foundation

private enum FixedPredicateFailure: Error {
    case rejectedHash
}

@inline(never)
public func fixedThrowingObjectPredicate(_ value: NSObject) throws -> Bool {
    let hash = value.hash
    if hash == Int.min {
        throw FixedPredicateFailure.rejectedHash
    }
    return (hash & 1) == 0
}

@inline(never)
public func filterObjectsWithFixedThrowingPredicate(
    _ values: Set<NSObject>
) throws -> Set<NSObject> {
    try values.filter { try fixedThrowingObjectPredicate($0) }
}
