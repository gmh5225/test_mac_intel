import ObjectiveC

public final class ResizeAlpha: NSObject {}
public final class ResizeBeta: NSObject {}

@inline(never)
public func insertAlpha(_ member: ResizeAlpha, _ values: inout Set<ResizeAlpha>) -> Bool {
  return values.insert(member).inserted
}

@inline(never)
public func insertBeta(_ member: ResizeBeta, _ values: inout Set<ResizeBeta>) -> Bool {
  return values.insert(member).inserted
}

@inline(never)
public func copyAndInsertAlpha(_ member: ResizeAlpha, _ values: Set<ResizeAlpha>) -> (Set<ResizeAlpha>, Bool) {
  var result = values
  let inserted = result.insert(member).inserted
  return (result, inserted)
}

@inline(never)
public func copyAndInsertBeta(_ member: ResizeBeta, _ values: Set<ResizeBeta>) -> (Set<ResizeBeta>, Bool) {
  var result = values
  let inserted = result.insert(member).inserted
  return (result, inserted)
}
