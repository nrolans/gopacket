package layers

// Copied from https://github.com/google/gopacket/pull/484

// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

// ERSPANII contains all of the fields found in an ERSPAN Type II header
// https://tools.ietf.org/html/draft-foschiano-erspan-03
type ERSPANII struct {
	BaseLayer
	IsTruncated                         bool
	Version, CoS, TrunkEncap            uint8
	VLANIdentifier, SessionID, Reserved uint16
	Index                               uint32
}

func (e ERSPANII) LayerType() gopacket.LayerType {
	return LayerTypeERSPANII
}

func (e ERSPANII) NextLayerType() gopacket.LayerType {
	return LayerTypeEthernet
}

const (
	//ERSPANIIVersionObsolete - The obsolete value for the version field
	ERSPANIIVersionObsolete = 0x0
	// ERSPANIIVersion - The current value for the version field
	ERSPANIIVersion = 0x1
)

// NewERSPANII is a convenience "constructor" which sets common default values
func NewERSPANII() *ERSPANII {
	return &ERSPANII{
		Version: ERSPANIIVersion,
	}
}

// DecodeFromBytes decodes the given bytes into this layer.
func (h *ERSPANII) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	h.Version = data[0] & 0xF0 >> 4
	h.VLANIdentifier = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	h.CoS = data[2] & 0xE0 >> 5
	h.TrunkEncap = data[2] & 0x18 >> 3
	h.IsTruncated = data[2]&0x4>>2 != 0
	h.SessionID = binary.BigEndian.Uint16(data[2:4]) & 0x03FF
	h.Reserved = binary.BigEndian.Uint16(data[4:6]) & 0xFFF0 >> 4
	h.Index = binary.BigEndian.Uint32(data[4:8]) & 0x000FFFFF
	h.BaseLayer = BaseLayer{data[:8], data[8:]}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (h *ERSPANII) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}

	twoByteInt := uint16(h.Version&0xF)<<12 | h.VLANIdentifier&0x0FFF
	binary.BigEndian.PutUint16(bytes, twoByteInt)

	twoByteInt = uint16(h.CoS&0x7)<<13 | uint16(h.TrunkEncap&0x3)<<11 | h.SessionID&0x03FF
	if h.IsTruncated {
		twoByteInt |= 0x400
	}
	binary.BigEndian.PutUint16(bytes[2:], twoByteInt)

	fourByteInt := uint32(h.Reserved&0x0FFF)<<20 | h.Index&0x000FFFFF
	binary.BigEndian.PutUint32(bytes[4:], fourByteInt)
	return nil
}

func decodeERSPANII(data []byte, p gopacket.PacketBuilder) error {
	erspan := &ERSPANII{}
	err := erspan.DecodeFromBytes(data, p)
	p.AddLayer(erspan)
	// p.SetTransportLayer(ip)
	if err != nil {
		return err
	}
	return p.NextDecoder(LayerTypeEthernet)
}
