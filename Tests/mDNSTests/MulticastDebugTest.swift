import Testing
import Foundation
@testable import MDNS
import DNSWire

@Suite("Multicast Debug Tests")
struct MulticastDebugTests {
    private func isUnavailableMulticastEnvironment(_ error: Error) -> Bool {
        let message = String(describing: error)
        return message.contains("No such device")
            || message.contains("Interface not found")
    }

    @Test("Debug: Can start transport without error")
    func canStartTransport() async throws {
        let transport = NIODNSTransport(configuration: .default)

        do {
            try await transport.start()
            print("✅ Transport started successfully")

            // Check if we can access multicast constants
            print("📡 IPv4 multicast: \(mdnsIPv4Address)")
            print("📡 IPv6 multicast: \(mdnsIPv6Address)")
            print("📡 Port: \(mdnsPort)")

            try await transport.shutdown()
            print("✅ Transport shutdown successfully")
        } catch {
            print("❌ Error: \(error)")
            if isUnavailableMulticastEnvironment(error) {
                print("Skipping multicast debug test because this environment has no multicast interface")
                return
            }
            throw error
        }
    }

    @Test("Debug: Can send multicast message with specific interface")
    func canSendMulticast() async throws {
        var config = MDNSTransportConfiguration.default
        config.networkInterface = "en0"
        let transport = NIODNSTransport(configuration: config)

        do {
            try await transport.start()
            print("✅ Transport started with en0")

            let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
            print("📤 Sending with interface: en0...")
            try await transport.send(query)
            print("✅ Message sent successfully with en0!")

            try await transport.shutdown()
        } catch {
            print("❌ en0 error: \(error)")
            if isUnavailableMulticastEnvironment(error) {
                print("Skipping multicast debug test because this environment has no multicast interface")
                return
            }
            throw error
        }
    }

    @Test("Debug: Can send multicast message with bind to local IP")
    func canSendMulticastBindToLocalIP() async throws {
        // Try binding to actual local IP instead of 0.0.0.0
        let transport = NIODNSTransport(configuration: .default)

        do {
            try await transport.start()
            print("✅ Transport started")

            // Create a simple DNS query
            let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
            print("📨 Created DNS query with \(query.questions.count) question(s)")

            // Try to send it
            print("📤 Attempting to send multicast message...")
            try await transport.send(query)
            print("✅ Message sent successfully!")

            try await transport.shutdown()
        } catch {
            print("❌ Send error: \(error)")
            print("Error type: \(type(of: error))")
            if let nsError = error as NSError? {
                print("Domain: \(nsError.domain)")
                print("Code: \(nsError.code)")
                print("UserInfo: \(nsError.userInfo)")
            }
            if isUnavailableMulticastEnvironment(error) {
                print("Skipping multicast debug test because this environment has no multicast interface")
                return
            }
            throw error
        }
    }

    @Test("Debug: MDNSResponder can advertise and stop")
    func responderCanStart() async throws {
        let responder = MDNSResponder()

        do {
            let service = MDNSService(
                name: "Test Service",
                type: "_test._tcp",
                port: 12345
            )
            try await responder.advertise(service)
            print("✅ MDNSResponder advertised")

            await responder.stop()
            print("✅ MDNSResponder stopped")
        } catch {
            print("❌ Responder error: \(error)")
            if isUnavailableMulticastEnvironment(error) {
                print("Skipping multicast debug test because this environment has no multicast interface")
                return
            }
            throw error
        }
    }

    @Test("Debug: MDNSResponder can advertise a service")
    func responderCanRegister() async throws {
        let responder = MDNSResponder()

        do {
            let service = MDNSService(
                name: "Test Service",
                type: "_test._tcp",
                port: 12345
            )

            print("📝 Advertising service: \(service.fullName)")
            try await responder.advertise(service)
            print("✅ Service advertised!")

            await responder.stop()
        } catch {
            print("❌ Register error: \(error)")
            print("Error type: \(type(of: error))")
            if let nsError = error as NSError? {
                print("Domain: \(nsError.domain)")
                print("Code: \(nsError.code)")
                print("UserInfo: \(nsError.userInfo)")
            }
            if isUnavailableMulticastEnvironment(error) {
                print("Skipping multicast debug test because this environment has no multicast interface")
                return
            }
            throw error
        }
    }
}
