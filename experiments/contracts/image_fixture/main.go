package main

import (
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	directory := os.Args[1]
	if err := os.Mkdir(directory, 0700); err != nil {
		panic(err)
	}
	gray := image.NewGray(image.Rect(0, 0, 17, 9))
	rgba := image.NewNRGBA(image.Rect(0, 0, 17, 19))
	deep := image.NewNRGBA64(image.Rect(0, 0, 3, 2))
	palette := image.NewPaletted(image.Rect(0, 0, 17, 9), color.Palette{color.Black, color.NRGBA{R: 192, G: 64, B: 32, A: 128}})
	for y := 0; y < 19; y++ {
		for x := 0; x < 17; x++ {
			rgba.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 13), G: uint8(y * 11), B: uint8((x + y) * 7), A: uint8(128 + (x+y)%128)})
			if y < 9 {
				gray.SetGray(x, y, color.Gray{Y: uint8(x*11 + y*7)})
				palette.SetColorIndex(x, y, uint8((x+y)%2))
			}
			if x < 3 && y < 2 {
				deep.SetNRGBA64(x, y, color.NRGBA64{R: uint16(x*131 + 1), G: uint16(y*717 + 2), B: 953, A: 32768})
			}
		}
	}
	for name, value := range map[string]image.Image{"gray": gray, "rgba": rgba, "deep": deep, "palette": palette} {
		output, err := os.OpenFile(filepath.Join(directory, name+".png"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			panic(err)
		}
		err = png.Encode(output, value)
		closeErr := output.Close()
		if err != nil || closeErr != nil {
			panic("PNG fixture generation failed")
		}
	}
	for name, value := range map[string]image.Image{"gray": gray, "color": rgba} {
		output, err := os.OpenFile(filepath.Join(directory, name+".jpg"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			panic(err)
		}
		err = jpeg.Encode(output, value, &jpeg.Options{Quality: 90})
		closeErr := output.Close()
		if err != nil || closeErr != nil {
			panic("JPEG fixture generation failed")
		}
	}
}
