public final class Theme {
  public let id: Int
  public init(_ id: Int) { self.id = id }
  @inline(never) private static func makeThemes() -> [String: Theme] {
    return ["standard": Theme(1), "dark": Theme(2)]
  }
  private static let themes = makeThemes()
  @inline(never) public static func withName(_ name: String?) -> Theme? {
    guard let name else { return nil }
    return themes[name]
  }
}
@inline(never) public func lookupTheme(_ name: String?) -> Theme? {
  Theme.withName(name)
}
