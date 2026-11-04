package inspect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
)

type jpegComponent struct {
	h, v, quant, dc, ac byte
}

type jpegHuffman struct {
	counts [16]int
	values []byte
}

func validateJPEG(ctx context.Context, r io.ReaderAt, size int64) (int, int, error) {
	var width, height int64
	var components []jpegComponent
	var quant [4]bool
	var tables [2][2]jpegHuffman
	var jfif bool
	for offset := int64(2); offset < size; {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if size-offset < 4 {
			return 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		var header [4]byte
		if err := imageBytes(r, header[:], offset); err != nil {
			return 0, 0, err
		}
		length := int64(binary.BigEndian.Uint16(header[2:]))
		if header[0] != 0xff || length < 2 || length > size-offset-2 {
			return 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		segment := make([]byte, length-2)
		if err := imageBytes(r, segment, offset+4); err != nil {
			return 0, 0, err
		}
		switch header[1] {
		case 0xe0:
			if offset != 2 || jfif || len(segment) != 14 || !bytes.Equal(segment[:5], []byte("JFIF\x00")) || segment[5] != 1 || segment[6] > 2 || segment[7] > 2 || binary.BigEndian.Uint16(segment[8:10]) == 0 || binary.BigEndian.Uint16(segment[10:12]) == 0 || segment[12] != 0 || segment[13] != 0 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			jfif = true
		case 0xdb:
			if len(segment) == 0 || len(segment)%65 != 0 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			for i := 0; i < len(segment); i += 65 {
				index := segment[i]
				if index > 3 || quant[index] {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
				for _, value := range segment[i+1 : i+65] {
					if value == 0 {
						return 0, 0, fail("UNSUPPORTED_FORMAT")
					}
				}
				quant[index] = true
			}
		case 0xc4:
			if len(segment) == 0 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			for len(segment) != 0 {
				if len(segment) < 17 || segment[0]>>4 > 1 || segment[0]&15 > 1 {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
				class, index := segment[0]>>4, segment[0]&15
				table := &tables[class][index]
				if table.values != nil {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
				count, code := 0, 0
				for i, value := range segment[1:17] {
					table.counts[i] = int(value)
					count += int(value)
					code += int(value)
					if code >= 1<<(i+1) {
						return 0, 0, fail("UNSUPPORTED_FORMAT")
					}
					code <<= 1
				}
				if count == 0 || count > 256 || len(segment) < 17+count {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
				table.values = append([]byte(nil), segment[17:17+count]...)
				var seen [256]bool
				for _, value := range table.values {
					if seen[value] || class == 0 && value > 11 || class == 1 && (value&15 > 10 || value&15 == 0 && value != 0 && value != 0xf0) {
						return 0, 0, fail("UNSUPPORTED_FORMAT")
					}
					seen[value] = true
				}
				segment = segment[17+count:]
			}
		case 0xc0:
			if components != nil || len(segment) < 6 || segment[0] != 8 || (segment[5] != 1 && segment[5] != 3) || len(segment) != 6+3*int(segment[5]) {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			height, width = int64(binary.BigEndian.Uint16(segment[1:3])), int64(binary.BigEndian.Uint16(segment[3:5]))
			if width == 0 || height == 0 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			components = make([]jpegComponent, segment[5])
			for i := range components {
				id, sampling, q := segment[6+3*i], segment[7+3*i], segment[8+3*i]
				if id != byte(i+1) || q > 3 || (i != 0 || len(components) == 1) && sampling != 0x11 || i == 0 && sampling != 0x11 && sampling != 0x21 && sampling != 0x22 {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
				components[i] = jpegComponent{h: sampling >> 4, v: sampling & 15, quant: q}
			}
			// The decoder allocates whole MCU rectangles, including edge padding.
			h, v := int64(components[0].h)*8, int64(components[0].v)*8
			if ((width+h-1)/h*h)*((height+v-1)/v*v)*4 > imageDecodedLimit {
				return 0, 0, fail("LIMIT_EXCEEDED")
			}
		case 0xda:
			if components == nil || len(segment) != 4+2*len(components) || int(segment[0]) != len(components) || !bytes.Equal(segment[len(segment)-3:], []byte{0, 63, 0}) {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			for i := range components {
				c := &components[i]
				c.dc, c.ac = segment[2+2*i]>>4, segment[2+2*i]&15
				if segment[1+2*i] != byte(i+1) || c.dc > 1 || c.ac > 1 || !quant[c.quant] || tables[0][c.dc].values == nil || tables[1][c.ac].values == nil {
					return 0, 0, fail("UNSUPPORTED_FORMAT")
				}
			}
			var end [2]byte
			if err := imageBytes(r, end[:], size-2); err != nil {
				return 0, 0, err
			}
			start := offset + length + 2
			if end != [2]byte{0xff, 0xd9} || start >= size-2 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			reader := &imageByteReader{r: bufio.NewReader(imageInput{ctx, io.NewSectionReader(r, start, size-2-start)})}
			bits := jpegBits{r: reader}
			var predictors [3]int
			mcuW, mcuH := int64(components[0].h)*8, int64(components[0].v)*8
			mcus := (width + mcuW - 1) / mcuW * ((height + mcuH - 1) / mcuH)
			for mcu := int64(0); mcu < mcus; mcu++ {
				if err := ctx.Err(); err != nil {
					return 0, 0, err
				}
				for i, c := range components {
					for block := 0; block < int(c.h)*int(c.v); block++ {
						if err := bits.block(&tables[0][c.dc], &tables[1][c.ac], &predictors[i]); err != nil {
							return 0, 0, err
						}
					}
				}
			}
			if reader.count != size-2-start || uint16(bits.value)&((1<<bits.remaining)-1) != (1<<bits.remaining)-1 {
				return 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			return int(width), int(height), nil
		default:
			return 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		offset += length + 2
	}
	return 0, 0, fail("UNSUPPORTED_FORMAT")
}

type jpegBits struct {
	r                *imageByteReader
	value, remaining byte
}

func (r *jpegBits) take(n byte) (int, error) {
	result := 0
	for ; n != 0; n-- {
		if r.remaining == 0 {
			value, err := r.r.ReadByte()
			if err != nil {
				return 0, fail("UNSUPPORTED_FORMAT")
			}
			if value == 0xff {
				stuffed, err := r.r.ReadByte()
				if err != nil || stuffed != 0 {
					return 0, fail("UNSUPPORTED_FORMAT")
				}
			}
			r.value, r.remaining = value, 8
		}
		r.remaining--
		result = result<<1 | int((r.value>>r.remaining)&1)
	}
	return result, nil
}

func (r *jpegBits) symbol(table *jpegHuffman) (byte, error) {
	code, minimum, offset := 0, 0, 0
	for _, count := range table.counts {
		bit, err := r.take(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | bit
		if code >= minimum && code < minimum+count {
			return table.values[offset+code-minimum], nil
		}
		offset += count
		minimum = (minimum + count) << 1
	}
	return 0, fail("UNSUPPORTED_FORMAT")
}

func (r *jpegBits) block(dc, ac *jpegHuffman, predictor *int) error {
	value, err := r.symbol(dc)
	if err != nil {
		return err
	}
	difference, err := r.take(value)
	if err != nil {
		return err
	}
	if value != 0 && difference < 1<<(value-1) {
		difference -= (1 << value) - 1
	}
	*predictor += difference
	if *predictor < -1024 || *predictor > 1023 {
		return fail("UNSUPPORTED_FORMAT")
	}
	for position := 1; position < 64; {
		value, err := r.symbol(ac)
		if err != nil {
			return err
		}
		if value == 0 {
			return nil
		}
		if value == 0xf0 {
			position += 16
			if position > 64 {
				return fail("UNSUPPORTED_FORMAT")
			}
			continue
		}
		position += int(value >> 4)
		if position >= 64 {
			return fail("UNSUPPORTED_FORMAT")
		}
		if _, err := r.take(value & 15); err != nil {
			return err
		}
		position++
	}
	return nil
}
