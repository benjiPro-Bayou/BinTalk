package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

const (
	fileColumns = `f.id, f.uploaded_by, f.filename, f.file_type, f.file_size, COALESCE(f.mime_type, ''), f.s3_key,
		COALESCE(f.s3_bucket, ''), f.file_hash_encrypted, f.file_hash_iv, COALESCE(f.is_encrypted, true),
		COALESCE(f.encryption_key_version, 0), COALESCE(f.virus_scan_status, 'pending'), f.virus_scan_date,
		COALESCE(f.download_count, 0), f.last_downloaded_at, f.created_at, f.deleted_at`

	// localBucket marks files stored on the API server's disk rather than in S3.
	localBucket = "local"
)

// Concurrency limits for memory-heavy work: an upload holds the file and its ciphertext in memory,
// and decoding an image for a thumbnail can take ~100 MB.
var (
	uploadSlots    = make(chan struct{}, 8)
	thumbnailSlots = make(chan struct{}, 2)
)

// acquire takes a slot, or writes a 503 and returns false if none frees up within 30 seconds.
func acquire(c *gin.Context, slots chan struct{}) bool {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return true
	case <-c.Request.Context().Done():
		c.AbortWithStatus(499)
	case <-timer.C:
		c.Header("Retry-After", "10")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the server is busy; try again shortly"})
	}
	return false
}

var validFileTypes = map[string]bool{
	"document": true, "image": true, "video": true, "audio": true, "archive": true, "other": true,
}

// FileHandler handles encrypted file storage. Files are encrypted with AES-256-GCM and stored
// in UPLOAD_DIR (default /data/uploads).
type FileHandler struct {
	deps      *Dependencies
	uploadDir string
}

// NewFileHandler creates a FileHandler.
func NewFileHandler(deps *Dependencies) *FileHandler {
	dir := os.Getenv("UPLOAD_DIR")
	if dir == "" {
		dir = "/data/uploads"
	}
	return &FileHandler{deps: deps, uploadDir: dir}
}

func scanFile(row rowScanner) (*models.File, error) {
	var f models.File
	err := row.Scan(&f.ID, &f.UploadedBy, &f.Filename, &f.FileType, &f.FileSize, &f.MimeType, &f.S3Key,
		&f.S3Bucket, &f.FileHashEncrypted, &f.FileHashIV, &f.IsEncrypted,
		&f.EncryptionKeyVersion, &f.VirusScanStatus, &f.VirusScanDate,
		&f.DownloadCount, &f.LastDownloadedAt, &f.CreatedAt, &f.DeletedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// UploadFile accepts a multipart upload in the "file" field. Optional form fields:
// "filename" (defaults to the uploaded name) and "file_type" (derived from the MIME type).
func (h *FileHandler) UploadFile(c *gin.Context) {
	maxSize := h.deps.Config.Security.MaxRequestSize
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize+1<<20)

	header, err := c.FormFile("file")
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file is too large", "max_bytes": maxSize})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": `multipart field "file" is required`})
		return
	}
	if header.Size > maxSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file is too large", "max_bytes": maxSize})
		return
	}

	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	if over, err := h.overQuota(ctx, h.deps.DB, userID, header.Size); err != nil {
		h.deps.internalError(c, err, "check storage quota")
		return
	} else if over {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "your storage quota is full; delete some files first"})
		return
	}

	if !acquire(c, uploadSlots) {
		return
	}
	defer func() { <-uploadSlots }()

	src, err := header.Open()
	if err != nil {
		h.deps.internalError(c, err, "open upload")
		return
	}
	data, err := io.ReadAll(src)
	src.Close()
	if err != nil {
		h.deps.internalError(c, err, "read upload")
		return
	}

	filename := filepath.Base(strings.TrimSpace(c.DefaultPostForm("filename", header.Filename)))
	if filename == "." || filename == "/" || len(filename) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filename"})
		return
	}
	// The client's type decides how browsers render the file, so it must not claim to be an image
	// when the content is not one.
	mimeType := header.Header.Get("Content-Type")
	sniffed := http.DetectContentType(data)
	if mimeType == "" || mimeType == "application/octet-stream" ||
		(strings.HasPrefix(mimeType, "image/") && !strings.HasPrefix(sniffed, "image/")) {
		mimeType = sniffed
	}
	if len(mimeType) > 100 {
		mimeType = mimeType[:100]
	}
	fileType := c.PostForm("file_type")
	if !validFileTypes[fileType] {
		fileType = classifyFile(mimeType, filename)
	}

	encrypted, err := h.deps.EncryptionService.EncryptBlob(data)
	if err != nil {
		h.deps.internalError(c, err, "encrypt file")
		return
	}
	hash := sha256.Sum256(data)
	hashCiphertext, hashIV, hashTag, keyVersion, err := h.deps.EncryptionService.EncryptField(hash[:])
	if err != nil {
		h.deps.internalError(c, err, "encrypt file hash")
		return
	}

	id := uuid.New()
	storageKey := id.String() + ".enc"
	if err := os.MkdirAll(h.uploadDir, 0o700); err != nil {
		h.deps.internalError(c, err, "create upload directory")
		return
	}
	path := filepath.Join(h.uploadDir, storageKey)
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		h.deps.internalError(c, err, "write file")
		return
	}

	file, quotaFull, err := h.insertFile(ctx, userID, func(tx *sql.Tx) (*models.File, error) {
		return scanFile(tx.QueryRowContext(ctx, `
			INSERT INTO files AS f (id, uploaded_by, filename, file_type, file_size, mime_type, s3_key, s3_bucket,
				file_hash_encrypted, file_hash_iv, is_encrypted, encryption_key_version, virus_scan_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11, 'pending')
			RETURNING `+fileColumns,
			id, userID, filename, fileType, len(data), mimeType, storageKey, localBucket,
			append(hashCiphertext, hashTag...), hashIV, keyVersion,
		))
	}, int64(len(data)))
	if err != nil || quotaFull {
		os.Remove(path)
		if quotaFull {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "your storage quota is full; delete some files first"})
			return
		}
		h.deps.internalError(c, err, "insert file")
		return
	}

	h.deps.Kafka.Publish(ctx, "file.uploaded", file.ID.String(), gin.H{
		"file_id": file.ID, "uploaded_by": userID, "file_type": fileType, "file_size": file.FileSize,
	})
	c.JSON(http.StatusCreated, gin.H{"file": file.ToDTO(nil)})
}

// overQuota reports whether storing size more bytes would exceed the user's storage quota.
func (h *FileHandler) overQuota(ctx context.Context, q queryer, userID uuid.UUID, size int64) (bool, error) {
	quota := h.deps.Config.Security.StorageQuotaPerUser
	if quota <= 0 {
		return false, nil
	}
	var used int64
	if err := q.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(file_size), 0) FROM files WHERE uploaded_by = $1 AND deleted_at IS NULL`,
		userID).Scan(&used); err != nil {
		return false, err
	}
	return used+size > quota, nil
}

// insertFile runs insert in a transaction that holds a per-user lock and rechecks the quota, so
// concurrent uploads cannot together exceed it.
func (h *FileHandler) insertFile(ctx context.Context, userID uuid.UUID, insert func(*sql.Tx) (*models.File, error), size int64) (*models.File, bool, error) {
	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('files:' || $1::text))`, userID); err != nil {
		return nil, false, err
	}
	if over, err := h.overQuota(ctx, tx, userID, size); err != nil || over {
		return nil, over, err
	}
	file, err := insert(tx)
	if err != nil {
		return nil, false, err
	}
	return file, false, tx.Commit()
}

// DownloadFile decrypts and returns a file. The uploader, and anyone who can see a message
// the file is attached to, can download it.
func (h *FileHandler) DownloadFile(c *gin.Context) {
	file, ok := h.loadFile(c)
	if !ok {
		return
	}
	if !h.checkAccess(c, file) {
		return
	}
	data, ok := h.readContent(c, file)
	if !ok {
		return
	}

	ctx := c.Request.Context()

	if _, err := h.deps.DB.ExecContext(ctx, `
		UPDATE files SET download_count = COALESCE(download_count, 0) + 1, last_downloaded_at = NOW()
		WHERE id = $1`, file.ID); err != nil {
		h.deps.Logger.WithError(err).Warn("Failed to record download")
	}

	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": file.Filename}))
	c.Header("Cache-Control", "private, no-store")
	// Explicit length: large responses are streamed, and clients need it to show download progress.
	c.Header("Content-Length", strconv.Itoa(len(data)))
	contentType := file.MimeType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Data(http.StatusOK, contentType, data)
}

// Thumbnail returns a compressed JPEG preview of an image file (at most 640px on the longest
// side). Previews are generated on first request and cached, encrypted, next to the original.
func (h *FileHandler) Thumbnail(c *gin.Context) {
	file, ok := h.loadFile(c)
	if !ok {
		return
	}
	if !h.checkAccess(c, file) {
		return
	}
	if !strings.HasPrefix(file.MimeType, "image/") {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "file is not an image"})
		return
	}

	cachePath := filepath.Join(h.uploadDir, file.ID.String()+".thumb.enc")
	if blob, err := os.ReadFile(cachePath); err == nil {
		if thumb, err := h.deps.EncryptionService.DecryptBlob(blob); err == nil {
			serveThumbnail(c, thumb)
			return
		}
	}

	if !acquire(c, thumbnailSlots) {
		return
	}
	defer func() { <-thumbnailSlots }()
	data, ok := h.readContent(c, file)
	if !ok {
		return
	}
	thumb, err := makeThumbnail(data)
	if err != nil {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "this image format cannot be previewed"})
		return
	}

	if blob, err := h.deps.EncryptionService.EncryptBlob(thumb); err == nil {
		tmp := cachePath + ".tmp-" + uuid.NewString()
		if err := os.WriteFile(tmp, blob, 0o600); err == nil {
			if err := os.Rename(tmp, cachePath); err != nil {
				os.Remove(tmp)
			}
		}
	}
	serveThumbnail(c, thumb)
}

func serveThumbnail(c *gin.Context, thumb []byte) {
	c.Header("Cache-Control", "private, max-age=86400")
	c.Header("Content-Length", strconv.Itoa(len(thumb)))
	c.Data(http.StatusOK, "image/jpeg", thumb)
}

// checkAccess allows the uploader, and anyone who can see a message the file is attached to.
// It writes a 404 (so file existence is not revealed) or 403 response and returns false otherwise.
func (h *FileHandler) checkAccess(c *gin.Context, file *models.File) bool {
	userID := middleware.GetUserID(c)
	if file.UploadedBy != userID {
		var allowed bool
		err := h.deps.DB.QueryRowContext(c.Request.Context(), `
			SELECT EXISTS (
				SELECT 1 FROM messages m
				WHERE m.file_id = $1 AND NOT COALESCE(m.is_deleted, false)
				  AND (m.sender_id = $2 OR m.receiver_id = $2
				       OR m.group_id IN (SELECT group_id FROM group_members WHERE user_id = $2)))`,
			file.ID, userID).Scan(&allowed)
		if err != nil {
			h.deps.internalError(c, err, "check file access")
			return false
		}
		if !allowed {
			c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
			return false
		}
	}
	if !file.CanDownload() {
		c.JSON(http.StatusForbidden, gin.H{"error": "file failed virus scan"})
		return false
	}
	return true
}

// readContent reads and decrypts a file's content, writing an error response on failure.
func (h *FileHandler) readContent(c *gin.Context, file *models.File) ([]byte, bool) {
	blob, err := os.ReadFile(filepath.Join(h.uploadDir, filepath.Base(file.S3Key)))
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusNotFound, gin.H{"error": "file content is missing"})
		return nil, false
	}
	if err != nil {
		h.deps.internalError(c, err, "read file")
		return nil, false
	}
	data, err := h.deps.EncryptionService.DecryptBlob(blob)
	if err != nil {
		h.deps.internalError(c, err, "decrypt file")
		return nil, false
	}
	return data, true
}

// DeleteFile deletes a file. Only the uploader can delete it.
func (h *FileHandler) DeleteFile(c *gin.Context) {
	file, ok := h.loadFile(c)
	if !ok {
		return
	}
	userID := middleware.GetUserID(c)
	if file.UploadedBy != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the uploader can delete this file"})
		return
	}

	ctx := c.Request.Context()
	if _, err := h.deps.DB.ExecContext(ctx, `UPDATE files SET deleted_at = NOW() WHERE id = $1`, file.ID); err != nil {
		h.deps.internalError(c, err, "delete file")
		return
	}
	for _, name := range []string{filepath.Base(file.S3Key), file.ID.String() + ".thumb.enc"} {
		if err := os.Remove(filepath.Join(h.uploadDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			h.deps.Logger.WithError(err).Warn("Failed to remove file content")
		}
	}

	h.deps.Kafka.Publish(ctx, "file.deleted", file.ID.String(), gin.H{"file_id": file.ID, "deleted_by": userID})
	c.JSON(http.StatusOK, gin.H{"id": file.ID, "deleted": true})
}

// loadFile loads the non-deleted file named by the :id parameter, writing an error response if absent.
func (h *FileHandler) loadFile(c *gin.Context) (*models.File, bool) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return nil, false
	}
	file, err := scanFile(h.deps.DB.QueryRowContext(c.Request.Context(),
		"SELECT "+fileColumns+" FROM files f WHERE f.id = $1 AND f.deleted_at IS NULL", id))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return nil, false
	}
	if err != nil {
		h.deps.internalError(c, err, "load file")
		return nil, false
	}
	return file, true
}

// classifyFile maps a MIME type (or extension) to the file_type enum.
func classifyFile(mimeType, filename string) string {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return "image"
	case strings.HasPrefix(mimeType, "video/"):
		return "video"
	case strings.HasPrefix(mimeType, "audio/"):
		return "audio"
	}
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz":
		return "archive"
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".rtf", ".odt":
		return "document"
	}
	if strings.HasPrefix(mimeType, "text/") || strings.Contains(mimeType, "pdf") {
		return "document"
	}
	return "other"
}
