package keyhandler

// Handler defines how derived PSKs are delivered to their destination.
type Handler interface {
	// SetKey delivers a PSK (base64-encoded) to the configured output.
	SetKey(psk string) error

	// Invalidate writes a random key to the output, invalidating
	// any existing session that relies on the previous key.
	Invalidate() error
}
