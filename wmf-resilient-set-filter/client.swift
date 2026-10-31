import Foundation
import NDSetExternalElements

@inline(never)
public func filterFirstExternalThrowing(
    _ values: Set<FirstExternalElement>,
    _ predicate: (FirstExternalElement) throws -> Bool
) rethrows -> Set<FirstExternalElement> {
    try values.filter(predicate)
}

@inline(never)
public func filterFirstExternalPlain(
    _ values: Set<FirstExternalElement>,
    _ predicate: (FirstExternalElement) -> Bool
) -> Set<FirstExternalElement> {
    values.filter(predicate)
}

@inline(never)
public func filterSecondExternalThrowing(
    _ values: Set<SecondExternalElement>,
    _ predicate: (SecondExternalElement) throws -> Bool
) rethrows -> Set<SecondExternalElement> {
    try values.filter(predicate)
}

@inline(never)
public func filterSecondExternalPlain(
    _ values: Set<SecondExternalElement>,
    _ predicate: (SecondExternalElement) -> Bool
) -> Set<SecondExternalElement> {
    values.filter(predicate)
}
