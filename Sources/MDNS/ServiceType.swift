/// Common DNS-SD service types (Tier-1 facade helper).

/// Common DNS-SD service types.
public enum ServiceType {
    /// HTTP web service.
    public static let http = "_http._tcp"

    /// HTTPS web service.
    public static let https = "_https._tcp"

    /// SSH service.
    public static let ssh = "_ssh._tcp"

    /// FTP service.
    public static let ftp = "_ftp._tcp"

    /// Printer (IPP).
    public static let ipp = "_ipp._tcp"

    /// AirPlay.
    public static let airplay = "_airplay._tcp"

    /// Apple File Sharing (AFP).
    public static let afp = "_afpovertcp._tcp"

    /// SMB file sharing.
    public static let smb = "_smb._tcp"

    /// SFTP service.
    public static let sftp = "_sftp-ssh._tcp"

    /// libp2p peer.
    public static let libp2p = "_p2p._udp"

    /// Returns the full service type string with domain.
    public static func fullType(_ type: String, domain: String = "local") -> String {
        "\(type).\(domain)."
    }
}
