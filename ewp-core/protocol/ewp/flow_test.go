package ewp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

var flowTestUUID = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// ─── 1. FlowFrame 编解码 Round-trip ─────────────────────────────────────────

func TestFlowFrame_RoundTrip_NoContent(t *testing.T) {
	frame := EncodeFlowFrame(0, FlowCommandContinue, nil, 64)
	decoded, err := DecodeFlowFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeFlowFrame: %v", err)
	}
	if decoded.Command != FlowCommandContinue {
		t.Errorf("Command mismatch: got %d want %d", decoded.Command, FlowCommandContinue)
	}
	if decoded.ContentLen != 0 {
		t.Errorf("ContentLen should be 0, got %d", decoded.ContentLen)
	}
	if decoded.PaddingLen != 64 {
		t.Errorf("PaddingLen mismatch: got %d want 64", decoded.PaddingLen)
	}
}

func TestFlowFrame_RoundTrip_WithContent(t *testing.T) {
	content := []byte("hello, world!")
	frame := EncodeFlowFrame(42, FlowCommandEnd, content, 32)
	decoded, err := DecodeFlowFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeFlowFrame: %v", err)
	}
	if decoded.StreamID != 42 {
		t.Errorf("StreamID mismatch: got %d want 42", decoded.StreamID)
	}
	if decoded.Command != FlowCommandEnd {
		t.Errorf("Command mismatch: got %d want %d", decoded.Command, FlowCommandEnd)
	}
	if !bytes.Equal(decoded.Content, content) {
		t.Errorf("Content mismatch: got %q want %q", decoded.Content, content)
	}
	if decoded.PaddingLen != 32 {
		t.Errorf("PaddingLen mismatch: got %d want 32", decoded.PaddingLen)
	}
}

func TestFlowFrame_RoundTrip_LargeContent(t *testing.T) {
	content := make([]byte, 8192)
	rand.Read(content)
	frame := EncodeFlowFrame(0, FlowCommandDirect, content, 0)
	decoded, err := DecodeFlowFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeFlowFrame large: %v", err)
	}
	if !bytes.Equal(decoded.Content, content) {
		t.Error("Large content mismatch after encode/decode")
	}
}

func TestFlowFrame_TruncatedHeader(t *testing.T) {
	_, err := DecodeFlowFrame(bytes.NewReader([]byte{0x00, 0x01}))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestFlowFrame_TruncatedContent(t *testing.T) {
	// 构造一个声称有 1000 字节内容但实际只有 7 字节 header 的帧
	frame := EncodeFlowFrame(0, FlowCommandEnd, make([]byte, 1000), 0)
	_, err := DecodeFlowFrame(bytes.NewReader(frame[:10]))
	if err == nil {
		t.Fatal("expected error for truncated content")
	}
}

// ─── 2. XtlsPadding / XtlsUnpadding Round-trip ──────────────────────────────

func testPadUnpad(t *testing.T, content []byte, command byte, withUUID bool) {
	t.Helper()

	state := NewFlowState(flowTestUUID)
	var uuidPtr []byte
	if withUUID {
		uuidCopy := make([]byte, 16)
		copy(uuidCopy, flowTestUUID)
		uuidPtr = uuidCopy
	}

	padded := XtlsPadding(content, command, &uuidPtr, true, DefaultPaddingConfig)
	if len(padded) == 0 {
		t.Fatal("padded output should not be empty")
	}

	unpadded := XtlsUnpadding(padded, state, true)

	if command == FlowCommandContinue {
		// Continue 命令：content 会被拆成内容部分，应包含在 unpadded 中
		if !bytes.Contains(unpadded, content) && len(content) > 0 {
			t.Errorf("content not found in unpadded output (cmd=Continue)")
		}
	} else {
		// End / Direct 命令：unpadded 应等于原始 content
		if !bytes.Equal(unpadded, content) {
			t.Errorf("Unpadding failed: got %d bytes want %d bytes", len(unpadded), len(content))
		}
	}
}

func TestXtlsPadUnpad_SmallContent_WithUUID(t *testing.T) {
	testPadUnpad(t, []byte("small payload"), FlowCommandEnd, true)
}

func TestXtlsPadUnpad_LargeContent_WithUUID(t *testing.T) {
	content := make([]byte, 2048)
	rand.Read(content)
	testPadUnpad(t, content, FlowCommandEnd, true)
}

func TestXtlsPadUnpad_NoUUID(t *testing.T) {
	content := []byte("no uuid test")
	state := NewFlowState(flowTestUUID)
	var nilUUID []byte
	padded := XtlsPadding(content, FlowCommandEnd, &nilUUID, false, DefaultPaddingConfig)
	// 无 UUID 时 XtlsUnpadding 初始检测失败，直接返回原始数据
	unpadded := XtlsUnpadding(padded, state, true)
	// 无 UUID padding，data 原样返回
	if len(unpadded) == 0 {
		t.Error("unpadded should not be empty for no-UUID path")
	}
}

func TestXtlsPadding_UUIDClearedAfterFirstUse(t *testing.T) {
	uuidCopy := make([]byte, 16)
	copy(uuidCopy, flowTestUUID)
	uuidPtr := uuidCopy

	_ = XtlsPadding([]byte("data"), FlowCommandContinue, &uuidPtr, true, DefaultPaddingConfig)
	if uuidPtr != nil {
		t.Error("userUUID should be nil after first XtlsPadding call")
	}
}

func TestXtlsPadding_PaddingLenInRange(t *testing.T) {
	cfg := DefaultPaddingConfig
	for i := 0; i < 200; i++ {
		content := make([]byte, i*10)
		var nilUUID []byte
		padded := XtlsPadding(content, FlowCommandEnd, &nilUUID, true, cfg)
		if len(padded) > 65535 {
			t.Errorf("padded frame too large: %d bytes at contentLen=%d", len(padded), len(content))
		}
	}
}

// ─── 3. XtlsPadding 多帧连续 unpadding ──────────────────────────────────────

func TestXtlsUnpadding_MultiBlock(t *testing.T) {
	state := NewFlowState(flowTestUUID)

	// 第一帧：带 UUID，Continue 命令
	uuid1 := make([]byte, 16)
	copy(uuid1, flowTestUUID)
	content1 := []byte("block-one")
	padded1 := XtlsPadding(content1, FlowCommandContinue, &uuid1, true, DefaultPaddingConfig)

	// 第二帧：End 命令，无 UUID
	var nilUUID []byte
	content2 := []byte("block-two")
	padded2 := XtlsPadding(content2, FlowCommandEnd, &nilUUID, true, DefaultPaddingConfig)

	// 连续处理
	out1 := XtlsUnpadding(padded1, state, true)
	out2 := XtlsUnpadding(padded2, state, true)

	if !bytes.Contains(out1, content1) {
		t.Errorf("block1: content not found in output, got %d bytes", len(out1))
	}
	if !bytes.Equal(out2, content2) {
		t.Errorf("block2: got %q want %q", out2, content2)
	}
}

// ─── 4. IsCompleteRecord ─────────────────────────────────────────────────────

func TestIsCompleteRecord_Valid(t *testing.T) {
	// 构造一个合法的 TLS Application Data 记录: 0x17 0x03 0x03 + length(2) + payload
	payload := []byte("tls application data")
	record := make([]byte, 5+len(payload))
	record[0] = 0x17
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(len(payload) >> 8)
	record[4] = byte(len(payload))
	copy(record[5:], payload)

	if !IsCompleteRecord(record) {
		t.Error("valid TLS record should return true")
	}
}

func TestIsCompleteRecord_TooShort(t *testing.T) {
	if IsCompleteRecord([]byte{0x17, 0x03}) {
		t.Error("short data should return false")
	}
}

func TestIsCompleteRecord_WrongType(t *testing.T) {
	record := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	if IsCompleteRecord(record) {
		t.Error("non-AppData TLS record should return false")
	}
}

func TestIsCompleteRecord_Truncated(t *testing.T) {
	// 声称有 100 字节但只提供 10 字节
	record := []byte{0x17, 0x03, 0x03, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05}
	if IsCompleteRecord(record) {
		t.Error("truncated TLS record should return false")
	}
}

func TestIsCompleteRecord_MultiRecord(t *testing.T) {
	// 两个连续的完整记录
	makeRecord := func(payload []byte) []byte {
		r := make([]byte, 5+len(payload))
		r[0] = 0x17
		r[1] = 0x03
		r[2] = 0x03
		r[3] = byte(len(payload) >> 8)
		r[4] = byte(len(payload))
		copy(r[5:], payload)
		return r
	}
	combined := append(makeRecord([]byte("first")), makeRecord([]byte("second"))...)
	if !IsCompleteRecord(combined) {
		t.Error("two complete TLS records should return true")
	}
}

// ─── 5. FlowWriter / FlowReader 端到端 ──────────────────────────────────────

func TestFlowWriterReader_DirectCopy_NoState(t *testing.T) {
	pr, pw := io.Pipe()

	writer := NewFlowWriter(pw, nil, true)
	reader := NewFlowReader(pr, nil, true)

	payload := []byte("direct copy without flow state")
	done := make(chan error, 1)

	go func() {
		_, err := writer.Write(payload)
		pw.Close()
		done <- err
	}()

	buf := make([]byte, len(payload))
	n, err := io.ReadFull(reader, buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload mismatch: got %q want %q", buf[:n], payload)
	}
	<-done
}

func TestFlowReader_Leftover_MultiRead(t *testing.T) {
	// 模拟 ProcessUplink 返回比 p 更大的数据，触发 leftover 路径
	// 通过一个 io.Reader 返回大块数据，但 Read 调用只提供小 buf
	bigPayload := bytes.Repeat([]byte("ABCDEFGH"), 512) // 4096 bytes
	pr, pw := io.Pipe()

	go func() {
		pw.Write(bigPayload)
		pw.Close()
	}()

	reader := NewFlowReader(pr, nil, true) // nil state = direct copy

	var collected []byte
	smallBuf := make([]byte, 256)
	for {
		n, err := reader.Read(smallBuf)
		if n > 0 {
			collected = append(collected, smallBuf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}

	if !bytes.Equal(collected, bigPayload) {
		t.Errorf("collected %d bytes, want %d", len(collected), len(bigPayload))
	}
}

// ─── 6. CalculatePadding 边界 ────────────────────────────────────────────────

func TestCalculatePadding_LongPadding(t *testing.T) {
	cfg := DefaultPaddingConfig
	// contentLen < 900 且 isTLS=true → 长 padding
	p := cfg.CalculatePadding(100, true)
	if p < 0 {
		t.Errorf("padding should be non-negative, got %d", p)
	}
	// 最大值不超过 LongPaddingBase + MaxRandomPadding - contentLen
	maxExpected := int32(cfg.LongPaddingBase) + int32(cfg.MaxRandomPadding) - 100
	if p > maxExpected {
		t.Errorf("long padding %d exceeds expected max %d", p, maxExpected)
	}
}

func TestCalculatePadding_ShortPadding(t *testing.T) {
	cfg := DefaultPaddingConfig
	// contentLen >= 900 → 短 padding
	p := cfg.CalculatePadding(1000, true)
	if p < 0 || p >= int32(cfg.ShortPaddingMax) {
		t.Errorf("short padding %d out of range [0, %d)", p, cfg.ShortPaddingMax)
	}
}

func TestCalculatePadding_NoTLS(t *testing.T) {
	cfg := DefaultPaddingConfig
	// isTLS=false → 短 padding 路径
	p := cfg.CalculatePadding(10, false)
	if p < 0 || p >= int32(cfg.ShortPaddingMax) {
		t.Errorf("non-TLS padding %d out of range [0, %d)", p, cfg.ShortPaddingMax)
	}
}

// ─── 7. FlowState 状态机 ─────────────────────────────────────────────────────

func TestFlowState_InitialState(t *testing.T) {
	state := NewFlowState(flowTestUUID)

	if state.NumberOfPacketToFilter != 8 {
		t.Errorf("NumberOfPacketToFilter should be 8, got %d", state.NumberOfPacketToFilter)
	}
	if state.EnableXtls {
		t.Error("EnableXtls should be false initially")
	}
	if !state.Inbound.IsPadding {
		t.Error("Inbound.IsPadding should be true initially")
	}
	if !state.Outbound.IsPadding {
		t.Error("Outbound.IsPadding should be true initially")
	}
	if state.Inbound.RemainingCommand != -1 {
		t.Errorf("RemainingCommand should be -1, got %d", state.Inbound.RemainingCommand)
	}
}

func TestFlowState_XtlsFilterTls_ServerHello(t *testing.T) {
	state := NewFlowState(flowTestUUID)

	// TlsServerHandShakeStart = [0x16, 0x03, 0x03]
	// XtlsFilterTls 检查 data[:3] == TlsServerHandShakeStart && data[5] == ServerHello
	// 所以构造：[0x16, 0x03, 0x03, lenHigh, lenLow, 0x02, ...]
	serverHello := make([]byte, 80)
	copy(serverHello[0:3], TlsServerHandShakeStart) // 0x16 0x03 0x03
	serverHello[3] = 0x00
	serverHello[4] = 0x4a // record length = 74
	serverHello[5] = TlsHandshakeTypeServerHello // 0x02

	state.XtlsFilterTls(serverHello)

	if !state.IsTLS {
		t.Error("IsTLS should be true after Server Hello")
	}
	if !state.IsTLS12orAbove {
		t.Error("IsTLS12orAbove should be true after Server Hello")
	}
}

func TestFlowState_ShouldDirectCopy_FalseInitially(t *testing.T) {
	state := NewFlowState(flowTestUUID)
	if state.ShouldDirectCopy(true) {
		t.Error("ShouldDirectCopy(uplink) should be false initially")
	}
	if state.ShouldDirectCopy(false) {
		t.Error("ShouldDirectCopy(downlink) should be false initially")
	}
}

func TestFlowState_ProcessUplink_PassThrough_AfterPaddingDone(t *testing.T) {
	state := NewFlowState(flowTestUUID)
	// 强制退出 padding 模式
	state.Inbound.WithinPaddingBuffers = false
	state.Inbound.UplinkReaderDirectCopy = false

	data := []byte("raw application data")
	result := state.ProcessUplink(data)

	// WithinPaddingBuffers=false，直接返回原始 data
	if !bytes.Equal(result, data) {
		t.Errorf("ProcessUplink should pass through data when not in padding: got %q", result)
	}
}

// ─── 8. FastRand 分布性 ──────────────────────────────────────────────────────

func TestFastIntn_InRange(t *testing.T) {
	for i := 0; i < 10000; i++ {
		n := FastIntn(256)
		if n < 0 || n >= 256 {
			t.Fatalf("FastIntn(256) = %d, out of [0,256)", n)
		}
	}
}

func TestFastBytes_FillsBuffer(t *testing.T) {
	buf := make([]byte, 128)
	FastBytes(buf)
	// 128 字节全为 0 的概率极低（2^-1024），视为失败
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("FastBytes produced all-zero buffer (extremely unlikely, probably a bug)")
	}
}

// ─── 9. Benchmark ────────────────────────────────────────────────────────────

func BenchmarkHandshakeEncode(b *testing.B) {
	addr := protoTestAddr()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := NewHandshakeRequest(protoTestUUID, CommandTCP, addr)
		_, _ = req.Encode()
	}
}

func BenchmarkHandshakeDecodeCached(b *testing.B) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, _ := req.Encode()
	cache := NewUUIDKeyCache([][16]byte{protoTestUUID})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeHandshakeRequestCached(frame, cache)
	}
}

func BenchmarkXtlsPadding_1KB(b *testing.B) {
	content := make([]byte, 1024)
	rand.Read(content)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var nilUUID []byte
		_ = XtlsPadding(content, FlowCommandEnd, &nilUUID, true, DefaultPaddingConfig)
	}
}

func BenchmarkXtlsUnpadding_1KB(b *testing.B) {
	content := make([]byte, 1024)
	rand.Read(content)
	state := NewFlowState(flowTestUUID)
	uuid := make([]byte, 16)
	copy(uuid, flowTestUUID)
	padded := XtlsPadding(content, FlowCommandEnd, &uuid, true, DefaultPaddingConfig)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 重置状态
		s := NewFlowState(flowTestUUID)
		_ = XtlsUnpadding(padded, s, true)
	}
	_ = state
}

func BenchmarkNonceCache_CheckAndAdd(b *testing.B) {
	c := NewNonceCache()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var nonce [12]byte
		i := 0
		for pb.Next() {
			nonce[0] = byte(i)
			nonce[1] = byte(i >> 8)
			nonce[2] = byte(i >> 16)
			c.CheckAndAdd(nonce)
			i++
		}
	})
}

// ─── 辅助：确保测试包名正确引用到常量 ───────────────────────────────────────

func TestFlowCommands_Values(t *testing.T) {
	if FlowCommandContinue != 0 {
		t.Errorf("FlowCommandContinue should be 0, got %d", FlowCommandContinue)
	}
	if FlowCommandEnd != 1 {
		t.Errorf("FlowCommandEnd should be 1, got %d", FlowCommandEnd)
	}
	if FlowCommandDirect != 2 {
		t.Errorf("FlowCommandDirect should be 2, got %d", FlowCommandDirect)
	}
}

