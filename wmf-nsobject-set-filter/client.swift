import Foundation

@inline(never)
public func filterObjectsThrowing(
    _ values: Set<NSObject>,
    _ predicate: (NSObject) throws -> Bool
) rethrows -> Set<NSObject> {
    try values.filter(predicate)
}

@inline(never)
public func filterObjectsPlain(
    _ values: Set<NSObject>,
    _ predicate: (NSObject) -> Bool
) -> Set<NSObject> {
    values.filter(predicate)
}

@inline(never)
public func filterGenericThrowing<Element: Hashable>(
    _ values: Set<Element>,
    _ predicate: (Element) throws -> Bool
) rethrows -> Set<Element> {
    try values.filter(predicate)
}

@inline(never)
public func filterGenericPlain<Element: Hashable>(
    _ values: Set<Element>,
    _ predicate: (Element) -> Bool
) -> Set<Element> {
    values.filter(predicate)
}
