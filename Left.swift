import Combine
import UIKit

private final class ImageState {
    @Published var image: UIImage?

    init(image: UIImage?) {
        self.image = image
    }
}

@objc public final class CoverBridge: NSObject {
    private let state = ImageState(image: nil)

    @objc @inline(never)
    public func loadImage() -> UIImage? {
        state.image
    }

    @objc @inline(never)
    public func replaceImage(_ image: UIImage?) {
        state.image = image
    }
}
