package inspect

import (
	"bufio"
	"compress/zlib"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
)

func validatePNG(ctx context.Context, r io.ReaderAt, size int64) (int, int, int, error) {
	var width, height, channels, depth, colorType int64
	var palette int64
	var transparency, idat bool
	var dataStart, dataEnd, compressed int64
	for offset := int64(8); offset < size; {
		if size-offset < 12 {
			return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		var header [8]byte
		if err := imageBytes(r, header[:], offset); err != nil {
			return 0, 0, 0, err
		}
		length := int64(binary.BigEndian.Uint32(header[:4]))
		if length > size-offset-12 {
			return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		kind := string(header[4:])
		crc := crc32.NewIEEE()
		crc.Write(header[4:])
		n, err := copyContext(ctx, crc, io.NewSectionReader(r, offset+8, length))
		if err != nil {
			return 0, 0, 0, err
		}
		var recorded [4]byte
		if err := imageBytes(r, recorded[:], offset+8+length); err != nil {
			return 0, 0, 0, err
		}
		if n != length || crc.Sum32() != binary.BigEndian.Uint32(recorded[:]) || offset == 8 && kind != "IHDR" {
			return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		switch kind {
		case "IHDR":
			if offset != 8 || length != 13 {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			var h [13]byte
			if err := imageBytes(r, h[:], offset+8); err != nil {
				return 0, 0, 0, err
			}
			width, height = int64(binary.BigEndian.Uint32(h[:4])), int64(binary.BigEndian.Uint32(h[4:8]))
			depth, colorType = int64(h[8]), int64(h[9])
			channels = map[int64]int64{0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colorType]
			validDepth := depth == 8 || depth == 16 && colorType != 3 || (depth == 1 || depth == 2 || depth == 4) && (colorType == 0 || colorType == 3)
			if width == 0 || height == 0 || width > 0x7fffffff || height > 0x7fffffff || channels == 0 || !validDepth || h[10] != 0 || h[11] != 0 || h[12] != 0 {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			pixelBytes := int64(4)
			if depth == 16 {
				pixelBytes = 8
			}
			if width > imageDecodedLimit/pixelBytes/height {
				return 0, 0, 0, fail("LIMIT_EXCEEDED")
			}
		case "PLTE":
			if idat || transparency || palette != 0 || colorType == 0 || colorType == 4 || length == 0 || length > 768 || length%3 != 0 || colorType == 3 && length/3 > 1<<depth {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			palette = length / 3
		case "tRNS":
			if idat || transparency || (colorType == 0 && length != 2) || (colorType == 2 && length != 6) || (colorType == 3 && (palette == 0 || length == 0 || length > palette)) || colorType == 4 || colorType == 6 {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			if colorType != 3 {
				var values [6]byte
				if err := imageBytes(r, values[:length], offset+8); err != nil {
					return 0, 0, 0, err
				}
				for i := int64(0); i < length; i += 2 {
					if uint32(binary.BigEndian.Uint16(values[i:i+2])) >= uint32(1)<<depth {
						return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
					}
				}
			}
			transparency = true
		case "IDAT":
			if colorType == 3 && palette == 0 {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			if !idat {
				dataStart = offset
			}
			idat = true
			dataEnd = offset + length + 12
			compressed += length
		case "IEND":
			if !idat || length != 0 || offset+12 != size {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			// PNG's decoder ignores additional IDAT bytes after the zlib stream.
			reader := &imageByteReader{r: bufio.NewReader(imageInput{ctx, &pngDataReader{r: r, offset: dataStart, end: dataEnd}})}
			stream, err := zlib.NewReader(reader)
			if err != nil {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			rowBytes := 1 + (width*channels*depth+7)/8
			expected := height * rowBytes
			n, err := copyContext(ctx, io.Discard, io.LimitReader(stream, expected+1))
			closeErr := stream.Close()
			if ctx.Err() != nil {
				return 0, 0, 0, ctx.Err()
			}
			if err != nil || closeErr != nil || n != expected || reader.count != compressed {
				return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
			}
			return int(width), int(height), int(palette), nil
		default:
			return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
		}
		offset += length + 12
	}
	return 0, 0, 0, fail("UNSUPPORTED_FORMAT")
}

type pngDataReader struct {
	r                      io.ReaderAt
	offset, end, remaining int64
}

func (r *pngDataReader) Read(p []byte) (int, error) {
	for r.remaining == 0 {
		if r.offset == r.end {
			return 0, io.EOF
		}
		var header [8]byte
		if err := imageBytes(r.r, header[:], r.offset); err != nil {
			return 0, err
		}
		r.remaining = int64(binary.BigEndian.Uint32(header[:4]))
		r.offset += 8
		if r.remaining == 0 {
			r.offset += 4
		}
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.ReadAt(p, r.offset)
	r.offset += int64(n)
	r.remaining -= int64(n)
	if r.remaining == 0 {
		r.offset += 4
	}
	return n, err
}
