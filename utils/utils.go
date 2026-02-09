package utils

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
