package handlers

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func TestOrientRotatesUpright(t *testing.T) {
	// 2x1 image: A (red) on the left, B (blue) on the right.
	src := image.NewRGBA(image.Rect(0, 0, 2, 1))
	a, b := color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}
	src.SetRGBA(0, 0, a)
	src.SetRGBA(1, 0, b)

	cases := []struct {
		orientation   int
		w, h          int
		first, second color.RGBA // pixel (0,0) and the other pixel
	}{
		{1, 2, 1, a, b},
		{2, 2, 1, b, a}, // mirrored
		{3, 2, 1, b, a}, // 180°
		{6, 1, 2, a, b}, // 90° clockwise: left goes to top
		{8, 1, 2, b, a}, // 90° counter-clockwise: right goes to top
	}
	for _, tc := range cases {
		out := orient(src, tc.orientation).(*image.RGBA)
		if out.Bounds().Dx() != tc.w || out.Bounds().Dy() != tc.h {
			t.Fatalf("orientation %d: got %v, want %dx%d", tc.orientation, out.Bounds(), tc.w, tc.h)
		}
		second := out.RGBAAt(1, 0)
		if tc.h == 2 {
			second = out.RGBAAt(0, 1)
		}
		if out.RGBAAt(0, 0) != tc.first || second != tc.second {
			t.Errorf("orientation %d: got %v,%v want %v,%v", tc.orientation, out.RGBAAt(0, 0), second, tc.first, tc.second)
		}
	}
}

func TestMakeThumbnailScalesAndCompresses(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2000, 1000))
	for y := 0; y < 1000; y++ {
		for x := 0; x < 2000; x++ {
			// Noisy, photo-like content (smooth gradients compress unrealistically well as PNG).
			n := uint8((x*7919 + y*104729) ^ (x * y))
			src.SetRGBA(x, y, color.RGBA{n, uint8(x) ^ n, uint8(y) + n, 255})
		}
	}
	var original bytes.Buffer
	if err := png.Encode(&original, src); err != nil {
		t.Fatal(err)
	}

	thumb, err := makeThumbnail(original.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(thumb))
	if err != nil {
		t.Fatalf("thumbnail is not a JPEG: %v", err)
	}
	if cfg.Width != 640 || cfg.Height != 320 {
		t.Errorf("got %dx%d, want 640x320", cfg.Width, cfg.Height)
	}
	if len(thumb) >= original.Len() {
		t.Errorf("thumbnail (%d bytes) is not smaller than original (%d bytes)", len(thumb), original.Len())
	}
}

func TestMakeThumbnailRejectsNonImages(t *testing.T) {
	if _, err := makeThumbnail([]byte("not an image")); !errors.Is(err, errNotPreviewable) {
		t.Errorf("got %v, want errNotPreviewable", err)
	}
}

func TestJPEGOrientationParsesExif(t *testing.T) {
	// Minimal JPEG header + APP1 EXIF segment (big-endian) with Orientation = 6.
	exif := []byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08\x00\x01\x01\x12\x00\x03\x00\x00\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00")
	data := append([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, byte(len(exif) + 2)}, exif...)
	data = append(data, 0xFF, 0xDA)
	if got := jpegOrientation(data); got != 6 {
		t.Errorf("got orientation %d, want 6", got)
	}
	if got := jpegOrientation([]byte{0xFF, 0xD8, 0xFF, 0xDA}); got != 1 {
		t.Errorf("no EXIF: got %d, want 1", got)
	}
}
