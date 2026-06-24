// UTF8Validation.swift
// Foundation-free, validating UTF-8 decode for DNS label / TXT / HINFO strings.
//
// The hardened codec must REJECT malformed UTF-8 rather than silently substitute
// the Unicode replacement character (which `String(decoding:as:)` would do). This
// helper preserves that guarantee without Foundation's
// `String(bytes:encoding:.utf8)`.

/// Decodes a byte sequence as UTF-8, returning `nil` if the bytes are not valid
/// UTF-8.
///
/// This is the Embedded-clean replacement for Foundation's
/// `String(bytes:encoding:.utf8)` used by the DNS codec to surface malformed
/// UTF-8 explicitly instead of substituting replacement characters.
@inlinable
func validatedUTF8String(_ bytes: some Sequence<UInt8>) -> String? {
    var scalars = String.UnicodeScalarView()
    var decoder = UTF8()
    var iterator = bytes.makeIterator()
    while true {
        switch decoder.decode(&iterator) {
        case .scalarValue(let scalar):
            scalars.append(scalar)
        case .emptyInput:
            return String(scalars)
        case .error:
            return nil
        }
    }
}
