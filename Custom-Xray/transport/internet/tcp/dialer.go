package tcp

import (
	"context"
	gotls "crypto/tls"
	"math/rand"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	validFingerprints = []string{
		"chrome", "firefox", "safari", "ios", "edge", "randomized",
	}
	trafficClasses = []uint32{0x00, 0x10, 0x08, 0x20, 0x28, 0x2e}
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing TCP to ", dest)

	if streamSettings.SocketSettings == nil {
		streamSettings.SocketSettings = &internet.SocketConfig{}
	}
	streamSettings.SocketSettings.Tfo = internet.SocketConfig_Enable

	if streamSettings.SocketSettings.Tos == 0 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		streamSettings.SocketSettings.Tos = trafficClasses[r.Intn(len(trafficClasses))]
	}

	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
		_ = tcpConn.SetWriteBuffer(4096)
		_ = tcpConn.SetReadBuffer(4096)
		_ = tcpConn.SetLinger(0)
	}

	connRng := rand.New(rand.NewSource(time.Now().UnixNano()))

	conn = &fluxConn{
		Conn:  conn,
		rng:   connRng,
		first: true,
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		mitmServerName := session.MitmServerNameFromContext(ctx)
		mitmAlpn11 := session.MitmAlpn11FromContext(ctx)
		var tlsConfig *gotls.Config

		serverName := config.ServerName
		if tls.IsFromMitm(serverName) {
			tlsConfig = config.GetTLSConfig(tls.WithOverrideName(mitmServerName))
		} else {
			serverName = mixCaseSNI(serverName)
			tlsConfig = config.GetTLSConfig(tls.WithDestination(dest))
			tlsConfig.ServerName = serverName
		}

		isFromMitmVerify := false
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertInNames) > 0 {
			for i, name := range r.VerifyPeerCertInNames {
				if tls.IsFromMitm(name) {
					isFromMitmVerify = true
					r.VerifyPeerCertInNames[0], r.VerifyPeerCertInNames[i] = r.VerifyPeerCertInNames[i], r.VerifyPeerCertInNames[0]
					r.VerifyPeerCertInNames = r.VerifyPeerCertInNames[1:]
					after := mitmServerName
					for {
						if len(after) > 0 {
							r.VerifyPeerCertInNames = append(r.VerifyPeerCertInNames, after)
						}
						_, after, _ = strings.Cut(after, ".")
						if !strings.Contains(after, ".") {
							break
						}
					}
					slices.Reverse(r.VerifyPeerCertInNames)
					break
				}
			}
		}
		isFromMitmAlpn := len(tlsConfig.NextProtos) == 1 && tls.IsFromMitm(tlsConfig.NextProtos[0])
		if isFromMitmAlpn {
			if mitmAlpn11 {
				tlsConfig.NextProtos[0] = "http/1.1"
			} else {
				tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}

		fpName := config.Fingerprint
		if fpName == "" {
			fpName = validFingerprints[connRng.Intn(len(validFingerprints))]
		}

		if fingerprint := tls.GetFingerprint(fpName); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "http/1.1" {
				err = conn.(*tls.UConn).WebsocketHandshakeContext(ctx)
			} else {
				err = conn.(*tls.UConn).HandshakeContext(ctx)
			}
		} else {
			conn = tls.Client(conn, tlsConfig)
			err = conn.(*tls.Conn).HandshakeContext(ctx)
		}
		if err != nil {
			if isFromMitmVerify {
				return nil, errors.New("MITM freedom RAW TLS: failed to verify Domain Fronting certificate from " + mitmServerName).Base(err).AtWarning()
			}
			return nil, err
		}
		negotiatedProtocol := conn.(tls.Interface).NegotiatedProtocol()
		if isFromMitmAlpn && !mitmAlpn11 && negotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("MITM freedom RAW TLS: unexpected Negotiated Protocol (" + negotiatedProtocol + ") with " + mitmServerName).AtWarning()
		}
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		config.ServerName = mixCaseSNI(config.ServerName)
		if conn, err = reality.UClient(conn, config, ctx, dest); err != nil {
			return nil, err
		}
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("failed to get header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("failed to create header authenticator").Base(err).AtError()
		}
		conn = auth.Client(conn)
	}
	return stat.Connection(conn), nil
}

type fluxConn struct {
	net.Conn
	rng     *rand.Rand
	first   bool
	written int64
}

func (c *fluxConn) Write(b []byte) (int, error) {
	if c.first {
		c.first = false
		if len(b) < 10 {
			return c.Conn.Write(b)
		}

		time.Sleep(time.Duration(c.rng.Intn(3)+1) * time.Millisecond)

		totalWritten := 0
		remaining := b

		for len(remaining) > 0 {
			chunkSize := c.rng.Intn(5) + 1
			if chunkSize > len(remaining) {
				chunkSize = len(remaining)
			}

			n, err := c.Conn.Write(remaining[:chunkSize])
			if n > 0 {
				totalWritten += n
				c.written += int64(n)
				remaining = remaining[n:]
			}
			if err != nil {
				return totalWritten, err
			}

			if len(remaining) > 0 {
				sleepDur := time.Duration(c.rng.Intn(25)+5) * time.Millisecond
				time.Sleep(sleepDur)
			}
		}
		return totalWritten, nil
	}

	totalWritten := 0
	remaining := b
	const slowStartThreshold = 256 * 1024

	for len(remaining) > 0 {
		var maxChunk int
		isSlowPhase := c.written < slowStartThreshold

		if isSlowPhase {
			maxChunk = c.rng.Intn(1200) + 100
		} else {
			maxChunk = c.rng.Intn(4000) + 500
		}

		if maxChunk > len(remaining) {
			maxChunk = len(remaining)
		}

		n, err := c.Conn.Write(remaining[:maxChunk])
		if n > 0 {
			totalWritten += n
			c.written += int64(n)
			remaining = remaining[n:]
		}
		if err != nil {
			return totalWritten, err
		}

		if len(remaining) > 0 {
			chance := 0
			if isSlowPhase {
				chance = 6
			} else {
				chance = 8
			}

			if c.rng.Intn(10) > chance {
				sleepDur := time.Duration(c.rng.Intn(3)+1) * time.Millisecond
				time.Sleep(sleepDur)
			}
		}
	}

	return totalWritten, nil
}

func mixCaseSNI(sni string) string {
	if sni == "" {
		return sni
	}
	if net.ParseAddress(sni).Family().IsIP() {
		return sni
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	runes := []rune(sni)
	for i, r := range runes {
		if unicode.IsLetter(r) {
			if rng.Intn(2) == 0 {
				runes[i] = unicode.ToUpper(r)
			} else {
				runes[i] = unicode.ToLower(r)
			}
		}
	}
	return string(runes)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}