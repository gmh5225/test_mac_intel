import Foundation
import NDSetExternalElements

@inline(never)
public func filterFirstExternalWithFixedProxyPredicate(
    _ values: Set<FirstExternalElement>
) -> Set<FirstExternalElement> {
    values.filter { $0.isProxy() }
}

@inline(never)
public func filterSecondExternalWithFixedProxyPredicate(
    _ values: Set<SecondExternalElement>
) -> Set<SecondExternalElement> {
    values.filter { !$0.isProxy() }
}
