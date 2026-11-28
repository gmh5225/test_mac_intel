import Foundation
public final class CalendarReceiver {
  public let stamp: String?
  public init(_ stamp: String?) { self.stamp = stamp }
  @inline(never) public func decoration(_ view: NSObject, components: DateComponents) -> NSObject? {
    return components.day == 1 && stamp != nil ? view : nil
  }
  @inline(never) public func label(for date: Date) -> String? {
    return date.timeIntervalSinceReferenceDate >= 0 ? stamp : nil
  }
}
