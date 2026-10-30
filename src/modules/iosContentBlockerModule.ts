/**
 * iOS Content Blocker & Universal Link Tracking Module
 * Educational Reference Architecture & Prototype Implementation.
 * Note: Not production-ready unless separately built, security-reviewed, and device-tested.
 */

export const IOS_ARCHITECTURE_DOCS = {
  title: 'iOS Deep Link Interception & Content Blocker Architecture',
  components: [
    'Safari Services Content Blocker Extension (SFContentBlockerManager)',
    'Universal Link / Custom URL Scheme Gateway (SceneDelegate / UIWindowSceneDelegate)',
    'Pre-flight Threat Verification Gateway (Local SHA-256 hash prefix checking)',
    'Safe in-app WebView Wrapper (SFSafariViewController & WKWebView with process isolation)',
  ],
  privacyModel: 'Strict on-device verification. Deep links incoming from Mail, WhatsApp, or iMessage are parsed locally. Threat verification uses k-anonymity 8-byte hash prefixes.',
};

export const IOS_SWIFT_INTERCEPTOR = `import UIKit
import SafariServices
import WebKit
import CryptoKit

// MARK: - SceneDelegate Deep Link Gateway
class SceneDelegate: UIResponder, UIWindowSceneDelegate {

    var window: UIWindow?

    /**
     * Intercepts Universal Links arriving from external apps (Mail, WhatsApp, iMessage).
     */
    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
              let incomingURL = userActivity.webpageURL else {
            return
        }

        // Intercept external link and pass to safety verification gateway
        SafeLinkRouter.shared.routeAndVerify(url: incomingURL, from: window?.rootViewController)
    }

    /**
     * Intercepts custom URL schemes (e.g., signal-protect://open?url=...)
     */
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        guard let incomingURL = URLContexts.first?.url else { return }
        
        // Extract embedded target URL if routed via scheme
        let target = parseEmbeddedTarget(from: incomingURL) ?? incomingURL
        SafeLinkRouter.shared.routeAndVerify(url: target, from: window?.rootViewController)
    }

    private func parseEmbeddedTarget(from url: URL) -> URL? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItem = components.queryItems?.first(where: { $0.name == "url" }),
              let targetString = queryItem.value else {
            return nil
        }
        return URL(string: targetString)
    }
}

// MARK: - Safety Verification Router
final class SafeLinkRouter {
    static let shared = SafeLinkRouter()
    private init() {}

    // In-memory cache for fast URL verification results
    private let verificationCache = NSCache<NSURL, NSNumber>()

    func routeAndVerify(url: URL, from presentingVC: UIViewController?) {
        guard let host = url.host?.lowercased().replacingOccurrences(of: "^www\\\\.", with: "", options: .regularExpression) else {
            presentSafeBrowser(url: url, from: presentingVC)
            return
        }

        // Check in-memory cache first
        if let cachedResult = verificationCache.object(forKey: url as NSURL) {
            if cachedResult.boolValue {
                presentThreatWarning(url: url, threatType: "Known Phishing Domain", from: presentingVC)
            } else {
                presentSafeBrowser(url: url, from: presentingVC)
            }
            return
        }

        // Compute 8-byte (16 hex character) SHA-256 hash prefix for privacy
        let hashPrefix = computeHashPrefix(for: host)

        Task {
            // Check local blocklist or remote hash lookup
            let threatInfo = await verifyHashPrefix(hashPrefix: hashPrefix, domain: host)

            await MainActor.run {
                if let threat = threatInfo {
                    self.verificationCache.setObject(true, forKey: url as NSURL)
                    self.presentThreatWarning(url: url, threatType: threat.type, from: presentingVC)
                } else {
                    self.verificationCache.setObject(false, forKey: url as NSURL)
                    self.presentSafeBrowser(url: url, from: presentingVC)
                }
            }
        }
    }

    private func computeHashPrefix(for domain: String) -> String {
        let inputData = Data(domain.utf8)
        let digest = SHA256.hash(data: inputData)
        // Take first 8 bytes (16 hex chars)
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    private func verifyHashPrefix(hashPrefix: String, domain: String) async -> (isThreat: Bool, type: String)? {
        // Query local encrypted CoreData/SQLite database or privacy-preserving backend
        // Returns threat if match found
        return await CloudSqlLookupService.shared.queryPrefix(hashPrefix)
    }

    private func presentThreatWarning(url: URL, threatType: String, from presentingVC: UIViewController?) {
        let alert = UIAlertController(
            title: "⚠️ Phishing Warning Block",
            message: "Signal blocked navigation to '\(url.host ?? "unknown")'.\\n\\nThreat Classification: \(threatType).\\nThis destination was identified as an attempt to harvest credentials or compromise your device.",
            preferredStyle: .alert
        )

        alert.addAction(UIAlertAction(title: "Dismiss & Stay Safe", style: .cancel, handler: nil))
        alert.addAction(UIAlertAction(title: "Ignore Warning & Open", style: .destructive, handler: { _ in
            self.presentSafeBrowser(url: url, from: presentingVC)
        }))

        presentingVC?.present(alert, animated: true)
    }

    private func presentSafeBrowser(url: URL, from presentingVC: UIViewController?) {
        let safariConfig = SFSafariViewController.Configuration()
        safariConfig.entersReaderIfAvailable = false
        safariConfig.barCollapsingEnabled = true

        let safariVC = SFSafariViewController(url: url, configuration: safariConfig)
        safariVC.dismissButtonStyle = .close
        safariVC.modalPresentationStyle = .pageSheet

        presentingVC?.present(safariVC, animated: true)
    }
}

// MARK: - WKWebView Process Isolation Container
final class IsolatedSecurityWebViewController: UIViewController, WKNavigationDelegate {
    private var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        // Strict configuration: Isolated process pool, no persistent cookie leakage
        let config = WKWebViewConfiguration()
        config.processPool = WKProcessPool()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true

        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        view.addSubview(webView)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        // Run secondary safety check on redirects
        if navigationAction.navigationType == .linkActivated {
            SafeLinkRouter.shared.routeAndVerify(url: url, from: self)
            decisionHandler(.cancel)
            return
        }

        decisionHandler(.allow)
    }
}
`;

export const IOS_CONTENT_BLOCKER_JSON = `[
  {
    "trigger": {
      "url-filter": ".*",
      "if-domain": [
        "*secure-amazon-support.co",
        "*login-appleid-verify.com",
        "*paypal-account-security-update.com",
        "*netflix-billing-renew.net",
        "*chase-verify-login.xyz",
        "*account-update-alert.com"
      ]
    },
    "action": {
      "type": "block"
    }
  },
  {
    "trigger": {
      "url-filter": "^https?://\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}"
    },
    "action": {
      "type": "block"
    }
  }
]`;
