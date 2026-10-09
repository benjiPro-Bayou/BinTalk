package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// File represents a file in the system
type File struct {
	ID                   uuid.UUID `db:"id" json:"id"`
	UploadedBy           uuid.UUID `db:"uploaded_by" json:"uploaded_by"`
	Filename             string    `db:"filename" json:"filename"`
	FileType             string    `db:"file_type" json:"file_type"` // document, image, video, audio, archive, other
	FileSize             int64     `db:"file_size" json:"file_size"`
	MimeType             string    `db:"mime_type" json:"mime_type"`
	S3Key                string    `db:"s3_key" json:"s3_key"`
	S3Bucket             string    `db:"s3_bucket" json:"s3_bucket"`
	FileHashEncrypted    []byte    `db:"file_hash_encrypted" json:"-"`
	FileHashIV           []byte    `db:"file_hash_iv" json:"-"`
	IsEncrypted          bool      `db:"is_encrypted" json:"is_encrypted"`
	EncryptionKeyVersion int       `db:"encryption_key_version" json:"encryption_key_version"`
	VirusScanStatus      string    `db:"virus_scan_status" json:"virus_scan_status"` // pending, clean, infected
	VirusScanDate        *time.Time `db:"virus_scan_date" json:"virus_scan_date"`
	DownloadCount        int       `db:"download_count" json:"download_count"`
	LastDownloadedAt     *time.Time `db:"last_downloaded_at" json:"last_downloaded_at"`
	CreatedAt            time.Time `db:"created_at" json:"created_at"`
	DeletedAt            *time.Time `db:"deleted_at" json:"deleted_at"`
}

// UploadFileRequest represents a file upload request
type UploadFileRequest struct {
	Filename             string `form:"filename" binding:"required"`
	FileType             string `form:"file_type" binding:"required"`
	IsEncrypted          bool   `form:"is_encrypted"`
	EncryptionKeyVersion int    `form:"encryption_key_version"`
}

// FileDTO represents a file data transfer object
type FileDTO struct {
	ID                   uuid.UUID  `json:"id"`
	UploadedBy           uuid.UUID  `json:"uploaded_by"`
	Filename             string     `json:"filename"`
	FileType             string     `json:"file_type"`
	FileSize             int64      `json:"file_size"`
	MimeType             string     `json:"mime_type"`
	IsEncrypted          bool       `json:"is_encrypted"`
	EncryptionKeyVersion int        `json:"encryption_key_version"`
	VirusScanStatus      string     `json:"virus_scan_status"`
	DownloadCount        int        `json:"download_count"`
	UploadedBy_User      *UserDTO   `json:"uploaded_by_user,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// FileListResponse represents a list of files
type FileListResponse struct {
	Files  []FileDTO `json:"files"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
}

// DeleteFileRequest represents a delete file request
type DeleteFileRequest struct {
	Reason string `json:"reason"`
}

// FileShareRequest represents a file share request
type FileShareRequest struct {
	UserIDs  []uuid.UUID `json:"user_ids" binding:"required"`
	GroupIDs []uuid.UUID `json:"group_ids"`
}

// FileMetadata represents file metadata
type FileMetadata struct {
	ID            uuid.UUID `json:"id"`
	Filename      string    `json:"filename"`
	FileSize      int64     `json:"file_size"`
	MimeType      string    `json:"mime_type"`
	FileType      string    `json:"file_type"`
	CreatedAt     time.Time `json:"created_at"`
	DownloadURL   string    `json:"download_url"`
}

// VirusScanResult represents virus scan result
type VirusScanResult struct {
	FileID     uuid.UUID  `json:"file_id"`
	Status     string     `json:"status"`
	DetectedAt *time.Time `json:"detected_at"`
	Signature  string     `json:"signature"`
}

// Helper functions

// ToDTO converts a File to FileDTO
func (f *File) ToDTO(uploader *User) *FileDTO {
	dto := &FileDTO{
		ID:                   f.ID,
		UploadedBy:           f.UploadedBy,
		Filename:             f.Filename,
		FileType:             f.FileType,
		FileSize:             f.FileSize,
		MimeType:             f.MimeType,
		IsEncrypted:          f.IsEncrypted,
		EncryptionKeyVersion: f.EncryptionKeyVersion,
		VirusScanStatus:      f.VirusScanStatus,
		DownloadCount:        f.DownloadCount,
		CreatedAt:            f.CreatedAt,
	}

	if uploader != nil {
		dto.UploadedBy_User = uploader.ToDTO()
	}

	return dto
}

// IsImage checks if file is an image
func (f *File) IsImage() bool {
	return f.FileType == "image"
}

// IsVideo checks if file is a video
func (f *File) IsVideo() bool {
	return f.FileType == "video"
}

// IsDocument checks if file is a document
func (f *File) IsDocument() bool {
	return f.FileType == "document"
}

// IsArchive checks if file is an archive
func (f *File) IsArchive() bool {
	return f.FileType == "archive"
}

// IsClean checks if file passed virus scan
func (f *File) IsClean() bool {
	return f.VirusScanStatus == "clean"
}

// IsInfected checks if file is infected
func (f *File) IsInfected() bool {
	return f.VirusScanStatus == "infected"
}

// IsPendingScan checks if file is pending virus scan
func (f *File) IsPendingScan() bool {
	return f.VirusScanStatus == "pending"
}

// CanDownload checks if file can be downloaded
func (f *File) CanDownload() bool {
	return !f.IsInfected() && f.DeletedAt == nil
}

// GetHumanReadableSize returns human-readable file size
func (f *File) GetHumanReadableSize() string {
	const unit = 1024
	if f.FileSize < unit {
		return fmt.Sprintf("%d B", f.FileSize)
	}
	div, exp := int64(unit), 0
	for n := f.FileSize / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(f.FileSize)/float64(div), "KMGTPE"[exp])
}
