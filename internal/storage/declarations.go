package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const MaxDeclarationBytes = 16 << 20

var (
	ErrInvalidDeclaration          = errors.New("invalid declaration document")
	ErrDeclarationTooLarge         = errors.New("declaration document exceeds size limit")
	ErrDeclarationRevisionConflict = errors.New("declaration revision conflict")
	ErrDeclarationNotFound         = errors.New("declaration revision not found")
)

type DeclarationRevision struct {
	Revision       uint64
	ParentRevision *uint64
	DocumentJSON   []byte
	SHA256         string
	Source         string
	CreatedAt      time.Time
}

func (s *Store) CurrentDeclaration(ctx context.Context) (DeclarationRevision, error) {
	var current sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT current_revision
		FROM declaration_state
		WHERE singleton = 1
	`).Scan(&current); err != nil {
		return DeclarationRevision{}, fmt.Errorf("read current declaration state: %w", err)
	}
	if !current.Valid {
		return DeclarationRevision{Revision: 0}, nil
	}
	return s.Declaration(ctx, uint64(current.Int64))
}

func (s *Store) Declaration(ctx context.Context, revision uint64) (DeclarationRevision, error) {
	if revision == 0 {
		return DeclarationRevision{Revision: 0}, nil
	}
	var (
		parent    sql.NullInt64
		document  []byte
		hash      string
		source    string
		createdAt string
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT parent_revision, document_json, document_sha256, source, created_at
		FROM declaration_revisions
		WHERE revision = ?
	`, revision).Scan(&parent, &document, &hash, &source, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeclarationRevision{}, fmt.Errorf("%w: %d", ErrDeclarationNotFound, revision)
		}
		return DeclarationRevision{}, fmt.Errorf("read declaration revision %d: %w", revision, err)
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("parse declaration revision %d timestamp: %w", revision, err)
	}
	var parentRevision *uint64
	if parent.Valid {
		value := uint64(parent.Int64)
		parentRevision = &value
	}
	return DeclarationRevision{
		Revision:       revision,
		ParentRevision: parentRevision,
		DocumentJSON:   append([]byte(nil), document...),
		SHA256:         hash,
		Source:         source,
		CreatedAt:      created,
	}, nil
}

func (s *Store) CommitDeclaration(
	ctx context.Context,
	expectedRevision uint64,
	document []byte,
	source string,
) (DeclarationRevision, error) {
	if len(document) == 0 || !json.Valid(document) {
		return DeclarationRevision{}, ErrInvalidDeclaration
	}
	if len(document) > MaxDeclarationBytes {
		return DeclarationRevision{}, fmt.Errorf("%w: %d bytes > %d bytes", ErrDeclarationTooLarge, len(document), MaxDeclarationBytes)
	}
	if err := validateDeclarationSource(source); err != nil {
		return DeclarationRevision{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("begin declaration transaction: %w", err)
	}
	defer tx.Rollback()

	var current sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT current_revision
		FROM declaration_state
		WHERE singleton = 1
	`).Scan(&current); err != nil {
		return DeclarationRevision{}, fmt.Errorf("read declaration state before commit: %w", err)
	}
	actualRevision := uint64(0)
	if current.Valid {
		actualRevision = uint64(current.Int64)
	}
	if actualRevision != expectedRevision {
		return DeclarationRevision{}, fmt.Errorf(
			"%w: expected %d, current %d",
			ErrDeclarationRevisionConflict,
			expectedRevision,
			actualRevision,
		)
	}

	targetRevision := expectedRevision + 1
	now := time.Now().UTC()
	sum := sha256.Sum256(document)
	hash := hex.EncodeToString(sum[:])

	var parent any
	if expectedRevision != 0 {
		parent = expectedRevision
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO declaration_revisions(
			revision,
			parent_revision,
			document_json,
			document_sha256,
			source,
			created_at
		)
		VALUES(?, ?, ?, ?, ?, ?)
	`,
		targetRevision,
		parent,
		document,
		hash,
		source,
		now.Format(time.RFC3339Nano),
	); err != nil {
		return DeclarationRevision{}, fmt.Errorf("insert declaration revision %d: %w", targetRevision, err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE declaration_state
		SET current_revision = ?
		WHERE singleton = 1
	`, targetRevision)
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("advance declaration state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("read declaration state update result: %w", err)
	}
	if affected != 1 {
		return DeclarationRevision{}, fmt.Errorf("advance declaration state: updated %d rows", affected)
	}

	if err := tx.Commit(); err != nil {
		return DeclarationRevision{}, fmt.Errorf("commit declaration revision %d: %w", targetRevision, err)
	}

	var parentRevision *uint64
	if expectedRevision != 0 {
		value := expectedRevision
		parentRevision = &value
	}
	return DeclarationRevision{
		Revision:       targetRevision,
		ParentRevision: parentRevision,
		DocumentJSON:   append([]byte(nil), document...),
		SHA256:         hash,
		Source:         source,
		CreatedAt:      now,
	}, nil
}

func validateDeclarationSource(source string) error {
	if source == "" {
		return fmt.Errorf("%w: source must not be empty", ErrInvalidDeclaration)
	}
	if len(source) > 128 {
		return fmt.Errorf("%w: source exceeds 128 bytes", ErrInvalidDeclaration)
	}
	if strings.TrimSpace(source) != source {
		return fmt.Errorf("%w: source must not have leading or trailing whitespace", ErrInvalidDeclaration)
	}
	for _, r := range source {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':', '/':
			continue
		default:
			return fmt.Errorf("%w: source contains unsupported character %q", ErrInvalidDeclaration, r)
		}
	}
	return nil
}
