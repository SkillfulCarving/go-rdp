package pdu

import (
	"bytes"

	"github.com/SkillfulCarving/go-rdp/core"
	"github.com/SkillfulCarving/go-rdp/emission"
	"github.com/SkillfulCarving/go-rdp/protocol/t125/gcc"
)

type PDULayer struct {
	emission.Emitter
	transport          core.Transport
	sharedId           uint32
	userId             uint16
	channelId          uint16
	serverCapabilities map[CapsType]Capability
	clientCapabilities map[CapsType]Capability
	fastPathSender     core.FastPathSender
	demandActivePDU    *DemandActivePDU
}

func NewPDULayer(t core.Transport) *PDULayer {
	p := &PDULayer{
		Emitter:   *emission.NewEmitter(),
		transport: t,
		sharedId:  0x103EA,
		serverCapabilities: map[CapsType]Capability{
			CAPSTYPE_GENERAL: &GeneralCapability{
				ProtocolVersion: 0x0200,
			},
			CAPSTYPE_BITMAP: &BitmapCapability{
				Receive1BitPerPixel:      0x0001,
				Receive4BitsPerPixel:     0x0001,
				Receive8BitsPerPixel:     0x0001,
				BitmapCompressionFlag:    0x0001,
				MultipleRectangleSupport: 0x0001,
			},
			CAPSTYPE_ORDER: &OrderCapability{
				DesktopSaveXGranularity: 1,
				DesktopSaveYGranularity: 20,
				MaximumOrderLevel:       1,
				OrderFlags:              NEGOTIATEORDERSUPPORT,
				DesktopSaveSize:         480 * 480,
			},
			CAPSTYPE_POINTER:        &PointerCapability{ColorPointerCacheSize: 20},
			CAPSTYPE_INPUT:          &InputCapability{},
			CAPSTYPE_VIRTUALCHANNEL: &VirtualChannelCapability{},
			CAPSTYPE_FONT:           &FontCapability{SupportFlags: 0x0001},
			CAPSTYPE_COLORCACHE:     &ColorCacheCapability{CacheSize: 0x0006},
			CAPSTYPE_SHARE:          &ShareCapability{},
		},
		clientCapabilities: map[CapsType]Capability{
			CAPSTYPE_GENERAL: &GeneralCapability{
				ProtocolVersion: 0x0200,
			},
			CAPSTYPE_BITMAP: &BitmapCapability{
				Receive1BitPerPixel:      0x0001,
				Receive4BitsPerPixel:     0x0001,
				Receive8BitsPerPixel:     0x0001,
				BitmapCompressionFlag:    0x0001,
				MultipleRectangleSupport: 0x0001,
			},
			CAPSTYPE_ORDER: &OrderCapability{
				DesktopSaveXGranularity: 1,
				DesktopSaveYGranularity: 20,
				MaximumOrderLevel:       1,
				OrderFlags:              NEGOTIATEORDERSUPPORT,
				DesktopSaveSize:         480 * 480,
			},
			CAPSTYPE_BITMAPCACHE:           &BitmapCacheCapability{},
			CAPSTYPE_POINTER:               &PointerCapability{ColorPointerCacheSize: 20},
			CAPSTYPE_INPUT:                 &InputCapability{},
			CAPSTYPE_BRUSH:                 &BrushCapability{},
			CAPSTYPE_GLYPHCACHE:            &GlyphCapability{},
			CAPSTYPE_OFFSCREENCACHE:        &OffscreenBitmapCacheCapability{},
			CAPSTYPE_VIRTUALCHANNEL:        &VirtualChannelCapability{},
			CAPSTYPE_SOUND:                 &SoundCapability{},
			CAPSETTYPE_MULTIFRAGMENTUPDATE: &MultiFragmentUpdate{},
			CAPSTYPE_RAIL: &RemoteProgramsCapability{
				RailSupportLevel: RAIL_LEVEL_SUPPORTED |
					RAIL_LEVEL_SHELL_INTEGRATION_SUPPORTED |
					RAIL_LEVEL_LANGUAGE_IME_SYNC_SUPPORTED |
					RAIL_LEVEL_SERVER_TO_CLIENT_IME_SYNC_SUPPORTED |
					RAIL_LEVEL_HIDE_MINIMIZED_APPS_SUPPORTED |
					RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED |
					RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED |
					RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED,
			},
		},
	}

	t.On("close", func() {
		p.Emit("close")
	}).On("error", func(err error) {
		p.Emit("error", err)
	})
	return p
}

func (p *PDULayer) sendPDU(message PDUMessage) {
	pdu := NewPDU(p.userId, message)
	p.transport.Write(pdu.serialize())
}

func (p *PDULayer) sendDataPDU(message DataPDUData) {
	dataPdu := NewDataPDU(message, p.sharedId)
	p.sendPDU(dataPdu)
}

func (p *PDULayer) SetFastPathSender(f core.FastPathSender) {
	p.fastPathSender = f
}

type Client struct {
	*PDULayer
	clientCoreData *gcc.ClientCoreData
}

func NewClient(t core.Transport) *Client {
	c := &Client{
		PDULayer: NewPDULayer(t),
	}
	c.transport.Once("connect", c.connect)
	return c
}

func (c *Client) connect(data *gcc.ClientCoreData, userId uint16, channelId uint16) {
	c.clientCoreData = data
	c.userId = userId
	c.channelId = channelId
	c.transport.Once("data", c.recvDemandActivePDU)
}

func (c *Client) recvDemandActivePDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, err := readPDU(r)
	if err != nil {
		return
	}
	if pdu.ShareCtrlHeader.PDUType != PDUTYPE_DEMANDACTIVEPDU {
		c.transport.Once("data", c.recvDemandActivePDU)
		return
	}
	c.sharedId = pdu.Message.(*DemandActivePDU).SharedId
	c.demandActivePDU = pdu.Message.(*DemandActivePDU)
	for _, caps := range pdu.Message.(*DemandActivePDU).CapabilitySets {
		c.serverCapabilities[caps.Type()] = caps
	}

	c.sendConfirmActivePDU()
	c.sendClientFinalizeSynchronizePDU()
	c.transport.Once("data", c.recvServerSynchronizePDU)
}

func (c *Client) sendConfirmActivePDU() {

	pdu := NewConfirmActivePDU()

	generalCapa := c.clientCapabilities[CAPSTYPE_GENERAL].(*GeneralCapability)
	generalCapa.OSMajorType = OSMAJORTYPE_WINDOWS
	generalCapa.OSMinorType = OSMINORTYPE_WINDOWS_NT
	generalCapa.ExtraFlags = LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM
	//if not self._fastPathSender is None:
	generalCapa.ExtraFlags |= FASTPATH_OUTPUT_SUPPORTED

	bitmapCapa := c.clientCapabilities[CAPSTYPE_BITMAP].(*BitmapCapability)
	bitmapCapa.PreferredBitsPerPixel = c.clientCoreData.HighColorDepth
	bitmapCapa.DesktopWidth = c.clientCoreData.DesktopWidth
	bitmapCapa.DesktopHeight = c.clientCoreData.DesktopHeight

	orderCapa := c.clientCapabilities[CAPSTYPE_ORDER].(*OrderCapability)
	orderCapa.OrderFlags |= ZEROBOUNDSDELTASSUPPORT

	inputCapa := c.clientCapabilities[CAPSTYPE_INPUT].(*InputCapability)
	inputCapa.Flags = INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE
	inputCapa.KeyboardLayout = c.clientCoreData.KbdLayout
	inputCapa.KeyboardType = c.clientCoreData.KeyboardType
	inputCapa.KeyboardSubType = c.clientCoreData.KeyboardSubType
	inputCapa.KeyboardFunctionKey = c.clientCoreData.KeyboardFnKeys
	inputCapa.ImeFileName = c.clientCoreData.ImeFileName

	pdu.SharedId = c.sharedId
	pdu.NumberCapabilities = c.demandActivePDU.NumberCapabilities
	for _, v := range c.clientCapabilities {
		pdu.CapabilitySets = append(pdu.CapabilitySets, v)
	}

	pdu.LengthSourceDescriptor = c.demandActivePDU.LengthSourceDescriptor
	pdu.SourceDescriptor = c.demandActivePDU.SourceDescriptor
	pdu.LengthCombinedCapabilities = c.demandActivePDU.LengthCombinedCapabilities

	c.sendPDU(pdu)
}

func (c *Client) sendClientFinalizeSynchronizePDU() {
	c.sendDataPDU(NewSynchronizeDataPDU(c.channelId))
	c.sendDataPDU(&ControlDataPDU{Action: CTRLACTION_COOPERATE})
	c.sendDataPDU(&ControlDataPDU{Action: CTRLACTION_REQUEST_CONTROL})
	//c.sendDataPDU(&PersistKeyPDU{BBitMask: 0x03})
	c.sendDataPDU(&FontListDataPDU{ListFlags: 0x0003, EntrySize: 0x0032})
}

func (c *Client) recvServerSynchronizePDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, err := readPDU(r)
	if err != nil {
		return
	}
	dataPdu, ok := pdu.Message.(*DataPDU)
	if !ok || dataPdu.Header.PDUType2 != PDUTYPE2_SYNCHRONIZE {
		c.transport.Once("data", c.recvServerSynchronizePDU)
		return
	}
	c.transport.Once("data", c.recvServerControlCooperatePDU)
}

func (c *Client) recvServerControlCooperatePDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, err := readPDU(r)
	if err != nil {
		return
	}
	dataPdu, ok := pdu.Message.(*DataPDU)
	if !ok || dataPdu.Header.PDUType2 != PDUTYPE2_CONTROL {
		c.transport.Once("data", c.recvServerControlCooperatePDU)
		return
	}
	if dataPdu.Data.(*ControlDataPDU).Action != CTRLACTION_COOPERATE {
		c.transport.Once("data", c.recvServerControlCooperatePDU)
		return
	}
	c.transport.Once("data", c.recvServerControlGrantedPDU)
}

func (c *Client) recvServerControlGrantedPDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, err := readPDU(r)
	if err != nil {
		return
	}
	dataPdu, ok := pdu.Message.(*DataPDU)
	if !ok || dataPdu.Header.PDUType2 != PDUTYPE2_CONTROL {
		c.transport.Once("data", c.recvServerControlGrantedPDU)
		return
	}
	if dataPdu.Data.(*ControlDataPDU).Action != CTRLACTION_GRANTED_CONTROL {
		c.transport.Once("data", c.recvServerControlGrantedPDU)
		return
	}
	c.transport.Once("data", c.recvServerFontMapPDU)
}

func (c *Client) recvServerFontMapPDU(s []byte) {
	r := bytes.NewReader(s)
	pdu, err := readPDU(r)
	if err != nil {
		return
	}
	dataPdu, ok := pdu.Message.(*DataPDU)
	if !ok || dataPdu.Header.PDUType2 != PDUTYPE2_FONTMAP {
		return
	}
	c.transport.On("data", c.recvPDU)
	c.Emit("ready")
}

func (c *Client) recvPDU(s []byte) {
	r := bytes.NewReader(s)
	if r.Len() > 0 {
		p, err := readPDU(r)
		if err != nil {
			return
		}
		if p.ShareCtrlHeader.PDUType == PDUTYPE_DEACTIVATEALLPDU {
			c.transport.Once("data", c.recvDemandActivePDU)
		}
	}
}

func (c *Client) RecvFastPath(secFlag byte, s []byte) {
	r := bytes.NewReader(s)
	for r.Len() > 0 {
		p, err := readFastPathUpdatePDU(r)
		if err != nil {

			return
		}
		if p.UpdateHeader == FASTPATH_UPDATETYPE_BITMAP {
			c.Emit("update", p.Data.(*FastPathBitmapUpdateDataPDU).Rectangles)
		}
	}
}

type InputEventsInterface interface {
	Serialize() []byte
}

func (c *Client) SendInputEvents(msgType uint16, events []InputEventsInterface) {
	pdu := &ClientInputEventPDU{}
	pdu.NumEvents = uint16(len(events))
	pdu.SlowPathInputEvents = make([]SlowPathInputEvent, 0, pdu.NumEvents)
	for _, in := range events {
		seria := in.Serialize()
		s := SlowPathInputEvent{0, msgType, len(seria), seria}
		pdu.SlowPathInputEvents = append(pdu.SlowPathInputEvents, s)
	}

	c.sendDataPDU(pdu)
}
