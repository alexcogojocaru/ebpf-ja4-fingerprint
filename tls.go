package main

const (
	TlsVersion_1_0 = 0x0301
	TlsVersion_1_1 = 0x0302
	TlsVersion_1_2 = 0x0303
	TlsVersion_1_3 = 0x0304
)

func tlsVersion(version uint16) string {
	switch version {
	case TlsVersion_1_3:
		return "13"
	case TlsVersion_1_2:
		return "12"
	case TlsVersion_1_1:
		return "11"
	case TlsVersion_1_0:
		return "10"
	}

	return "00"
}
