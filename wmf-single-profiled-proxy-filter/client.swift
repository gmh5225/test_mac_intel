import Foundation
import NDSetExternalElements

@inline(never)
public func filterFirstExternalWithFixedProxyPredicate(
    _ values: Set<FirstExternalElement>
) -> Set<FirstExternalElement> {
    values.filter { $0.isProxy() }
}
