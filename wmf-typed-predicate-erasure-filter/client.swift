import Foundation

@inline(never)
public func typedObjectFilter<Failure: Error>(
  _ values: Set<NSObject>,
  _ predicate: (NSObject) throws(Failure) -> Bool
) throws -> Set<NSObject> {
  try values.filter(predicate)
}

@inline(never)
public func typedGenericFilter<Value: Hashable, Failure: Error>(
  _ values: Set<Value>,
  _ predicate: (Value) throws(Failure) -> Bool
) throws -> Set<Value> {
  try values.filter(predicate)
}
