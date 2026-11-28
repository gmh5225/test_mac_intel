import UIKit

@available(iOS 16.0, *)
private struct CalendarHost {
  final class Coordinator: NSObject {
    let decoration: UICalendarView.Decoration?

    init(_ decoration: UICalendarView.Decoration?) {
      self.decoration = decoration
    }

    @objc(calendarView:decorationForDateComponents:)
    @inline(never) func calendarView(
      _ view: UICalendarView, decorationFor components: DateComponents
    ) -> UICalendarView.Decoration? {
      view.isHidden || components.day != 1 ? nil : decoration
    }
  }
}

@available(iOS 16.0, *)
public func calendarCoordinator(_ decoration: UICalendarView.Decoration?) -> NSObject {
  CalendarHost.Coordinator(decoration)
}
