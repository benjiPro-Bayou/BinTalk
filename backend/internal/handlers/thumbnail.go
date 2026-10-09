package handlers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	_ "image/gif" // register decoders
	"image/jpeg"
	_ "image/png"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	thumbnailMaxSide = 640        // pixels; displayed at up to ~320 CSS px, so sharp on 2x screens
	thumbnailQuality = 75         // JPEG quality
	maxImagePixels   = 25_000_000 // refuse to decode larger images (decompression bombs): ~100 MB as RGBA
)

var errNotPreviewable = errors.New("image cannot be previewed")

// makeThumbnail decodes a JPEG, PNG, GIF or WebP image and returns a compressed JPEG no larger
// than thumbnailMaxSide on its longest side, upright according to its EXIF orientation.
// Transparent areas are flattened onto white.
func makeThumbnail(data []byte) ([]byte, error) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxImagePixels {
		return nil, errNotPreviewable
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, errNotPreviewable
	}

	bounds := src.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if longest := max(width, height); longest > thumbnailMaxSide {
		width = max(1, width*thumbnailMaxSide/longest)
		height = max(1, height*thumbnailMaxSide/longest)
	}

	scaled := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(scaled, scaled.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.CatmullRom.Scale(scaled, scaled.Bounds(), src, bounds, draw.Over, nil)

	var out image.Image = scaled
	if format == "jpeg" {
		out = orient(scaled, jpegOrientation(data))
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: thumbnailQuality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// orient applies an EXIF orientation (1-8) so the image displays upright.
func orient(src *image.RGBA, orientation int) image.Image {
	if orientation < 2 || orientation > 8 {
		return src
	}
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	dw, dh := w, h
	if orientation >= 5 {
		dw, dh = h, w
	}

	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			var sx, sy int
			switch orientation {
			case 2: // mirrored horizontally
				sx, sy = w-1-x, y
			case 3: // rotated 180°
				sx, sy = w-1-x, h-1-y
			case 4: // mirrored vertically
				sx, sy = x, h-1-y
			case 5: // transposed
				sx, sy = y, x
			case 6: // needs 90° clockwise rotation
				sx, sy = y, h-1-x
			case 7: // transversed
				sx, sy = w-1-y, h-1-x
			case 8: // needs 90° counter-clockwise rotation
				sx, sy = w-1-y, x
			}
			dst.SetRGBA(x, y, src.RGBAAt(sx, sy))
		}
	}
	return dst
}

// jpegOrientation returns the EXIF orientation of a JPEG, or 1 if it has none.
func jpegOrientation(data []byte) int {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return 1
	}
	for i := 2; i+4 <= len(data); {
		if data[i] != 0xFF {
			return 1
		}
		marker := data[i+1]
		if marker == 0xDA || marker == 0xD9 { // start of image data / end of image
			return 1
		}
		size := int(binary.BigEndian.Uint16(data[i+2:]))
		if size < 2 || i+2+size > len(data) {
			return 1
		}
		if marker == 0xE1 { // APP1, where EXIF lives
			if o := exifOrientation(data[i+4 : i+2+size]); o > 0 {
				return o
			}
		}
		i += 2 + size
	}
	return 1
}

// exifOrientation reads the Orientation tag (0x0112) from an EXIF APP1 segment, or returns 0.
func exifOrientation(segment []byte) int {
	if len(segment) < 14 || string(segment[:6]) != "Exif\x00\x00" {
		return 0
	}
	tiff := segment[6:]
	var order binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 0
	}

	ifd := int(order.Uint32(tiff[4:8]))
	if ifd < 8 || ifd+2 > len(tiff) {
		return 0
	}
	entries := int(order.Uint16(tiff[ifd:]))
	for k := 0; k < entries; k++ {
		entry := ifd + 2 + k*12
		if entry+12 > len(tiff) {
			return 0
		}
		if order.Uint16(tiff[entry:]) == 0x0112 {
			if v := int(order.Uint16(tiff[entry+8:])); v >= 1 && v <= 8 {
				return v
			}
			return 0
		}
	}
	return 0
}
