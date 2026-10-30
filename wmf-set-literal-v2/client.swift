import Foundation
import NDSetExternalElements

@inline(never)
public func firstExternalLiteral(_ first: FirstExternalElement,
                                 _ second: FirstExternalElement) -> Set<FirstExternalElement> {
    return [first, second]
}

@inline(never)
public func secondExternalLiteral(_ first: SecondExternalElement,
                                  _ second: SecondExternalElement) -> Set<SecondExternalElement> {
    return [first, second]
}
