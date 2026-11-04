package inspect

import (
	"bufio"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
)

const imageDecodedLimit = int64(100 << 20)

type imageInput struct {
	ctx context.Context
	r   io.Reader
}

func (r imageInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func imageBytes(r io.ReaderAt, p []byte, offset int64) error {
	_, err := r.ReadAt(p, offset)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fail("UNSUPPORTED_FORMAT")
	}
	return err
}

func validateImage(ctx context.Context, r io.ReaderAt, size int64, format string) error {
	var width, height, palette int
	var err error
	var decode func(io.Reader) (image.Image, error)
	if format == "png" {
		width, height, palette, err = validatePNG(ctx, r, size)
		decode = png.Decode
	} else {
		width, height, err = validateJPEG(ctx, r, size)
		decode = jpeg.Decode
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	decoded, err := decode(imageInput{ctx, io.NewSectionReader(r, 0, size)})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fail("UNSUPPORTED_FORMAT")
	}
	if decoded.Bounds().Dx() != width || decoded.Bounds().Dy() != height {
		return fail("UNSUPPORTED_FORMAT")
	}
	if indexed, ok := decoded.(*image.Paletted); ok && len(indexed.Palette) != palette {
		return fail("UNSUPPORTED_FORMAT")
	}
	return nil
}

type imageByteReader struct {
	r     *bufio.Reader
	count int64
}

func (r *imageByteReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.count += int64(n)
	return n, err
}

func (r *imageByteReader) ReadByte() (byte, error) {
	b, err := r.r.ReadByte()
	if err == nil {
		r.count++
	}
	return b, err
}
