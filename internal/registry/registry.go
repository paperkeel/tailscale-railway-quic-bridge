package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrIdentityConflict = errors.New("a different identity key is pending or active")
	ErrPoolExhausted    = errors.New("the virtual address pool is exhausted")
	ErrRequestExpired   = errors.New("the registration request expired")
	ErrReplay           = errors.New("the OIDC token was already used")
	ErrNotFound         = errors.New("the registry entry does not exist")
	ErrRateLimited      = errors.New("the pending registration limit is full")
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

type PendingRequest struct {
	ID               string
	Kind             string
	ProjectID        string
	EnvironmentID    string
	EnvironmentName  string
	ProjectAlias     string
	EnvironmentAlias string
	IdentityKey      []byte
	IdentityKeyID    string
	TransportKey     []byte
	Proof            []byte
	SourceAddress    string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	State            string
}

type Registration struct {
	ID               int64
	ProjectID        string
	EnvironmentID    string
	EnvironmentName  string
	ProjectAlias     string
	EnvironmentAlias string
	State            string
	IdentityType     string
	LeaseClass       string
	LeaseExpiresAt   time.Time
	VirtualPrefix    netip.Prefix
	RealPrefix       netip.Prefix
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Approval struct {
	RequestID      string
	ProviderID     string
	JTI            string
	JTIExpiresAt   time.Time
	LeaseClass     string
	LeaseDuration  time.Duration
	RealPrefix     netip.Prefix
	CertificatePEM []byte
	CertificateID  string
	CertificateEnd time.Time
	AuditJSON      string
}

type RouteGeneration struct {
	ID            int64
	DesiredRoutes []netip.Prefix
	State         string
	LastError     string
	CreatedAt     time.Time
}

type Credential struct {
	CertificatePEM []byte
	NotAfter       time.Time
	IdentityKeyID  string
}

type Stats struct {
	Registrations     int64
	Active            int64
	Allocated         int64
	Available         int64
	Quarantined       int64
	Pending           int64
	RoutesPending     int64
	CertificatesSoon  int64
	LeasesSoon        int64
	RegistrationState map[string]int64
}

type StaticRegistration struct {
	ProjectID       string
	EnvironmentID   string
	EnvironmentName string
	ConnectorID     string
	VirtualPrefix   netip.Prefix
	RealPrefix      netip.Prefix
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("registry path must not be empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create registry directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("set registry directory permissions: %w", err)
	}
	databaseURL := &url.URL{Scheme: "file", Path: path}
	query := databaseURL.Query()
	for _, pragma := range []string{"journal_mode(WAL)", "foreign_keys(ON)", "busy_timeout(5000)", "synchronous(FULL)"} {
		query.Add("_pragma", pragma)
	}
	databaseURL.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", databaseURL.String())
	if err != nil {
		return nil, fmt.Errorf("open registry: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, now: time.Now}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set registry permissions: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ImportStatic(ctx context.Context, registrations []StaticRegistration) error {
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start static registry import: %w", err)
	}
	defer tx.Rollback()
	for _, registration := range registrations {
		if registration.ProjectID == "" || registration.EnvironmentID == "" || registration.ConnectorID == "" || !registration.VirtualPrefix.IsValid() || !registration.RealPrefix.IsValid() {
			return errors.New("static registration import is not valid")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO registrations (
				project_id, environment_id, environment_name, project_alias,
				environment_alias, state, identity_type, lease_class, lease_expires_at,
				virtual_prefix, real_prefix, created_at, updated_at
			) VALUES (?, ?, ?, ?, 'legacy', 'ready', 'static-v2', 'persistent', ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, environment_id) DO UPDATE SET
				environment_name = excluded.environment_name,
				project_alias = excluded.project_alias,
				virtual_prefix = excluded.virtual_prefix,
				real_prefix = excluded.real_prefix,
				updated_at = excluded.updated_at
			WHERE registrations.identity_type = 'static-v2'`,
			registration.ProjectID, registration.EnvironmentID, registration.EnvironmentName,
			registration.ConnectorID, now.AddDate(10, 0, 0), registration.VirtualPrefix.String(),
			registration.RealPrefix.String(), now, now); err != nil {
			return fmt.Errorf("import static registration %q: %w", registration.ConnectorID, err)
		}
	}
	return tx.Commit()
}

func (s *Store) initialize(ctx context.Context) error {
	var check string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil {
		return fmt.Errorf("registry integrity check failed: %w", err)
	}
	if check != "ok" {
		return fmt.Errorf("registry integrity check failed: %s", check)
	}
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate registry: %w", err)
	}
	return nil
}

func (s *Store) CreatePending(ctx context.Context, request PendingRequest) (PendingRequest, bool, error) {
	if request.ID == "" || request.ProjectID == "" || request.EnvironmentID == "" || len(request.IdentityKey) != 32 || len(request.Proof) != sha256.Size {
		return PendingRequest{}, false, errors.New("pending registration request is not valid")
	}
	request.IdentityKeyID = Fingerprint(request.IdentityKey)
	now := s.now().UTC()
	if request.CreatedAt.IsZero() {
		request.CreatedAt = now
	}
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = now.Add(30 * time.Minute)
	}
	request.State = "pending"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingRequest{}, false, fmt.Errorf("start pending registration: %w", err)
	}
	defer tx.Rollback()
	var registrationID int64
	var identityType string
	if err := tx.QueryRowContext(ctx, `SELECT id, identity_type FROM registrations WHERE project_id = ? AND environment_id = ? AND state IN ('approved', 'ready')`, request.ProjectID, request.EnvironmentID).Scan(&registrationID, &identityType); err == nil {
		var matching int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_keys WHERE registration_id = ? AND key_id = ? AND state IN ('active', 'overlap'))`, registrationID, request.IdentityKeyID).Scan(&matching); err != nil {
			return PendingRequest{}, false, err
		}
		if matching == 0 && request.Kind != "rotate" && identityType != "static-v2" {
			return PendingRequest{}, false, ErrIdentityConflict
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return PendingRequest{}, false, err
	}
	var existing PendingRequest
	err = tx.QueryRowContext(ctx, `
		SELECT id, kind, project_id, environment_id, environment_name, project_alias,
		       environment_alias, identity_key, identity_key_id, transport_key, proof,
		       source_address, created_at, expires_at, state
		FROM pending_requests
		WHERE project_id = ? AND environment_id = ? AND state = 'pending'
		ORDER BY created_at DESC LIMIT 1`, request.ProjectID, request.EnvironmentID).Scan(
		&existing.ID, &existing.Kind, &existing.ProjectID, &existing.EnvironmentID,
		&existing.EnvironmentName, &existing.ProjectAlias, &existing.EnvironmentAlias,
		&existing.IdentityKey, &existing.IdentityKeyID, &existing.TransportKey,
		&existing.Proof, &existing.SourceAddress, &existing.CreatedAt, &existing.ExpiresAt,
		&existing.State,
	)
	if err == nil {
		if existing.IdentityKeyID != request.IdentityKeyID {
			return PendingRequest{}, false, ErrIdentityConflict
		}
		if existing.ExpiresAt.After(now) {
			return existing, false, nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE pending_requests SET state = 'expired' WHERE id = ?`, existing.ID); err != nil {
			return PendingRequest{}, false, fmt.Errorf("expire pending request: %w", err)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return PendingRequest{}, false, fmt.Errorf("find pending request: %w", err)
	}
	var projectPending, sourcePending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_requests WHERE project_id = ? AND state = 'pending' AND expires_at > ?`, request.ProjectID, now).Scan(&projectPending); err != nil {
		return PendingRequest{}, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_requests WHERE source_address = ? AND state = 'pending' AND expires_at > ?`, request.SourceAddress, now).Scan(&sourcePending); err != nil {
		return PendingRequest{}, false, err
	}
	if projectPending >= 10 || sourcePending >= 30 {
		return PendingRequest{}, false, ErrRateLimited
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pending_requests (
			id, kind, project_id, environment_id, environment_name, project_alias,
			environment_alias, identity_key, identity_key_id, transport_key, proof,
			source_address, created_at, expires_at, state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
		request.ID, request.Kind, request.ProjectID, request.EnvironmentID,
		request.EnvironmentName, request.ProjectAlias, request.EnvironmentAlias,
		request.IdentityKey, request.IdentityKeyID, request.TransportKey, request.Proof,
		request.SourceAddress, request.CreatedAt, request.ExpiresAt,
	)
	if err != nil {
		return PendingRequest{}, false, fmt.Errorf("create pending request: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PendingRequest{}, false, fmt.Errorf("commit pending registration: %w", err)
	}
	return request, true, nil
}

func (s *Store) Pending(ctx context.Context, id string) (PendingRequest, error) {
	var request PendingRequest
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, project_id, environment_id, environment_name, project_alias,
		       environment_alias, identity_key, identity_key_id, transport_key, proof,
		       source_address, created_at, expires_at, state
		FROM pending_requests WHERE id = ?`, id).Scan(
		&request.ID, &request.Kind, &request.ProjectID, &request.EnvironmentID,
		&request.EnvironmentName, &request.ProjectAlias, &request.EnvironmentAlias,
		&request.IdentityKey, &request.IdentityKeyID, &request.TransportKey,
		&request.Proof, &request.SourceAddress, &request.CreatedAt, &request.ExpiresAt,
		&request.State,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingRequest{}, ErrNotFound
	}
	if err != nil {
		return PendingRequest{}, fmt.Errorf("read pending request: %w", err)
	}
	return request, nil
}

func (s *Store) PendingForIdentity(ctx context.Context, projectID, environmentID string) ([]PendingRequest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, project_id, environment_id, environment_name, project_alias,
		       environment_alias, identity_key, identity_key_id, transport_key, proof,
		       source_address, created_at, expires_at, state
		FROM pending_requests
		WHERE project_id = ? AND environment_id = ? AND state = 'pending'
		ORDER BY created_at`, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("list pending requests: %w", err)
	}
	defer rows.Close()
	var result []PendingRequest
	for rows.Next() {
		var request PendingRequest
		if err := rows.Scan(
			&request.ID, &request.Kind, &request.ProjectID, &request.EnvironmentID,
			&request.EnvironmentName, &request.ProjectAlias, &request.EnvironmentAlias,
			&request.IdentityKey, &request.IdentityKeyID, &request.TransportKey,
			&request.Proof, &request.SourceAddress, &request.CreatedAt, &request.ExpiresAt,
			&request.State,
		); err != nil {
			return nil, fmt.Errorf("scan pending request: %w", err)
		}
		result = append(result, request)
	}
	return result, rows.Err()
}

func (s *Store) Approve(ctx context.Context, approval Approval) (Registration, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Registration{}, false, fmt.Errorf("start approval: %w", err)
	}
	defer tx.Rollback()
	request, err := pendingTx(ctx, tx, approval.RequestID)
	if err != nil {
		return Registration{}, false, err
	}
	now := s.now().UTC()
	if request.State == "approved" {
		registration, err := registrationByIdentityTx(ctx, tx, request.ProjectID, request.EnvironmentID)
		return registration, false, err
	}
	if request.State != "pending" || !request.ExpiresAt.After(now) {
		return Registration{}, false, ErrRequestExpired
	}
	if approval.JTI == "" || !approval.JTIExpiresAt.After(now) {
		return Registration{}, false, errors.New("OIDC replay record is not valid")
	}
	jtiHash := sha256.Sum256([]byte(approval.ProviderID + "\x00" + approval.JTI))
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_replays(provider_id, jti_hash, expires_at) VALUES (?, ?, ?)`, approval.ProviderID, jtiHash[:], approval.JTIExpiresAt); err != nil {
		if isUniqueConstraint(err) {
			return Registration{}, false, ErrReplay
		}
		return Registration{}, false, fmt.Errorf("record OIDC replay protection: %w", err)
	}
	registration, err := registrationByIdentityTx(ctx, tx, request.ProjectID, request.EnvironmentID)
	created := false
	if errors.Is(err, ErrNotFound) {
		prefix, allocateErr := allocatePrefixTx(ctx, tx, now)
		if allocateErr != nil {
			return Registration{}, false, allocateErr
		}
		result, insertErr := tx.ExecContext(ctx, `
			INSERT INTO registrations (
				project_id, environment_id, environment_name, project_alias,
				environment_alias, state, identity_type, lease_class, lease_expires_at,
				virtual_prefix, real_prefix, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, 'approved', 'dynamic-v3', ?, ?, ?, ?, ?, ?)`,
			request.ProjectID, request.EnvironmentID, request.EnvironmentName,
			request.ProjectAlias, request.EnvironmentAlias, approval.LeaseClass,
			now.Add(approval.LeaseDuration), prefix.String(), approval.RealPrefix.String(),
			now, now,
		)
		if insertErr != nil {
			return Registration{}, false, fmt.Errorf("create registration: %w", insertErr)
		}
		registration.ID, err = result.LastInsertId()
		if err != nil {
			return Registration{}, false, fmt.Errorf("read registration id: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE route_allocations SET registration_id = ? WHERE prefix = ?`, registration.ID, prefix.String()); err != nil {
			return Registration{}, false, fmt.Errorf("assign route allocation: %w", err)
		}
		registration, err = registrationByIDTx(ctx, tx, registration.ID)
		created = true
	}
	if err != nil {
		return Registration{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE registrations SET environment_name = ?, project_alias = ?, environment_alias = ?,
			state = 'approved', identity_type = 'dynamic-v3', lease_class = ?,
			lease_expires_at = ?, real_prefix = ?, updated_at = ? WHERE id = ?`,
		request.EnvironmentName, request.ProjectAlias, request.EnvironmentAlias,
		approval.LeaseClass, now.Add(approval.LeaseDuration), approval.RealPrefix.String(),
		now, registration.ID); err != nil {
		return Registration{}, false, fmt.Errorf("activate dynamic registration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO identity_keys(registration_id, key_id, public_key, state, created_at, rotate_after)
		VALUES (?, ?, ?, 'active', ?, ?)
		ON CONFLICT(registration_id, key_id) DO UPDATE SET state = 'active'`,
		registration.ID, request.IdentityKeyID, request.IdentityKey, now, now.AddDate(1, 0, 0)); err != nil {
		return Registration{}, false, fmt.Errorf("activate identity key: %w", err)
	}
	if len(approval.CertificatePEM) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET state = 'superseded' WHERE registration_id = ? AND state = 'active'`, registration.ID); err != nil {
			return Registration{}, false, fmt.Errorf("supersede previous certificate: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO certificates(id, registration_id, identity_key_id, certificate_pem, state, not_after, created_at)
			VALUES (?, ?, ?, ?, 'active', ?, ?)
			ON CONFLICT(id) DO NOTHING`, approval.CertificateID, registration.ID,
			request.IdentityKeyID, approval.CertificatePEM, approval.CertificateEnd, now); err != nil {
			return Registration{}, false, fmt.Errorf("store certificate: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO leases(registration_id, lease_class, starts_at, expires_at, renewed_at, source)
		VALUES (?, ?, ?, ?, ?, 'approval')`, registration.ID, approval.LeaseClass, now,
		now.Add(approval.LeaseDuration), now); err != nil {
		return Registration{}, false, fmt.Errorf("store lease: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pending_requests SET state = 'approved' WHERE id = ?`, request.ID); err != nil {
		return Registration{}, false, fmt.Errorf("complete pending request: %w", err)
	}
	if err := createRouteGenerationTx(ctx, tx, now); err != nil {
		return Registration{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, request_id, registration_id, occurred_at, data_json)
		VALUES ('registration.approved', ?, ?, ?, ?)`, request.ID, registration.ID, now, approval.AuditJSON); err != nil {
		return Registration{}, false, fmt.Errorf("record approval audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Registration{}, false, fmt.Errorf("commit approval: %w", err)
	}
	registration, err = s.Registration(ctx, request.ProjectID, request.EnvironmentID)
	return registration, created, err
}

func (s *Store) Registration(ctx context.Context, projectID, environmentID string) (Registration, error) {
	return scanRegistration(s.db.QueryRowContext(ctx, registrationSelect+` WHERE project_id = ? AND environment_id = ?`, projectID, environmentID))
}

func (s *Store) RegistrationByAlias(ctx context.Context, projectAlias, environmentAlias string) (Registration, error) {
	return scanRegistration(s.db.QueryRowContext(ctx, registrationSelect+` WHERE project_alias = ? AND environment_alias = ? AND state IN ('approved', 'ready') AND lease_expires_at > ?`, projectAlias, environmentAlias, s.now().UTC()))
}

func (s *Store) ProjectKnown(ctx context.Context, projectID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM registrations WHERE project_id = ?)`, projectID).Scan(&exists)
	return exists == 1, err
}

func (s *Store) ConsumeReplay(ctx context.Context, providerID, jti string, expiresAt time.Time) error {
	if providerID == "" || jti == "" || !expiresAt.After(s.now().UTC()) {
		return errors.New("OIDC replay record is not valid")
	}
	digest := sha256.Sum256([]byte(providerID + "\x00" + jti))
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_replays(provider_id, jti_hash, expires_at) VALUES (?, ?, ?)`, providerID, digest[:], expiresAt)
	if isUniqueConstraint(err) {
		return ErrReplay
	}
	return err
}

func (s *Store) Credential(ctx context.Context, registrationID int64) (Credential, error) {
	var credential Credential
	err := s.db.QueryRowContext(ctx, `SELECT certificate_pem, not_after, identity_key_id FROM certificates WHERE registration_id = ? AND state = 'active' ORDER BY created_at DESC, rowid DESC LIMIT 1`, registrationID).Scan(&credential.CertificatePEM, &credential.NotAfter, &credential.IdentityKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("read active certificate: %w", err)
	}
	return credential, nil
}

func (s *Store) ActiveIdentityKey(ctx context.Context, registrationID int64, keyID string) ([]byte, error) {
	var publicKey []byte
	err := s.db.QueryRowContext(ctx, `SELECT public_key FROM identity_keys WHERE registration_id = ? AND key_id = ? AND (state = 'active' OR (state = 'overlap' AND overlap_until > ?))`, registrationID, keyID, s.now().UTC()).Scan(&publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return publicKey, err
}

func (s *Store) CompleteIdentityRotation(ctx context.Context, registrationID int64, keyID string, overlap time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_keys WHERE registration_id = ? AND key_id = ? AND state = 'active')`, registrationID, keyID).Scan(&active); err != nil {
		return fmt.Errorf("check active identity key: %w", err)
	}
	if active != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_keys SET state = 'overlap', overlap_until = ? WHERE registration_id = ? AND key_id <> ? AND state = 'active'`, now.Add(overlap), registrationID, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, registration_id, occurred_at, data_json) VALUES ('identity.rotation.completed', ?, ?, '{}')`, registrationID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Renew(ctx context.Context, registration Registration, keyID string, certificatePEM []byte, certificateID string, certificateEnd time.Time, leaseDuration time.Duration) (Registration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Registration{}, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	if registration.State != "approved" && registration.State != "ready" || !registration.LeaseExpiresAt.After(now) {
		return Registration{}, ErrRequestExpired
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_keys WHERE registration_id = ? AND key_id = ? AND state = 'active')`, registration.ID, keyID).Scan(&active); err != nil {
		return Registration{}, fmt.Errorf("check active identity key: %w", err)
	}
	if active != 1 {
		return Registration{}, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET state = 'superseded' WHERE registration_id = ? AND state = 'active'`, registration.ID); err != nil {
		return Registration{}, fmt.Errorf("supersede previous certificate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO certificates(id, registration_id, identity_key_id, certificate_pem, state, not_after, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`, certificateID, registration.ID, keyID, certificatePEM, certificateEnd, now); err != nil {
		return Registration{}, fmt.Errorf("store renewed certificate: %w", err)
	}
	leaseEnd := now.Add(leaseDuration)
	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET lease_expires_at = ?, updated_at = ? WHERE id = ?`, leaseEnd, now, registration.ID); err != nil {
		return Registration{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO leases(registration_id, lease_class, starts_at, expires_at, renewed_at, source) VALUES (?, ?, ?, ?, ?, 'certificate-renewal')`, registration.ID, registration.LeaseClass, now, leaseEnd, now); err != nil {
		return Registration{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, registration_id, occurred_at, data_json) VALUES ('certificate.renewed', ?, ?, '{}')`, registration.ID, now); err != nil {
		return Registration{}, err
	}
	if err := tx.Commit(); err != nil {
		return Registration{}, err
	}
	return s.Registration(ctx, registration.ProjectID, registration.EnvironmentID)
}

func (s *Store) Active(ctx context.Context) ([]Registration, error) {
	rows, err := s.db.QueryContext(ctx, registrationSelect+` WHERE state IN ('approved', 'ready') AND lease_expires_at > ? ORDER BY virtual_prefix`, s.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("list active registrations: %w", err)
	}
	defer rows.Close()
	var registrations []Registration
	for rows.Next() {
		registration, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		registrations = append(registrations, registration)
	}
	return registrations, rows.Err()
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{RegistrationState: make(map[string]int64)}
	now := s.now().UTC()
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM registrations),
			(SELECT COUNT(*) FROM registrations WHERE state IN ('approved', 'ready') AND lease_expires_at > ?),
			(SELECT COUNT(*) FROM route_allocations WHERE state = 'allocated'),
			(SELECT COUNT(*) FROM route_allocations WHERE state = 'free'),
			(SELECT COUNT(*) FROM route_allocations WHERE state = 'quarantined'),
			(SELECT COUNT(*) FROM pending_requests WHERE state = 'pending' AND expires_at > ?),
			(SELECT COUNT(*) FROM route_generations WHERE state = 'pending'),
			(SELECT COUNT(*) FROM certificates WHERE state = 'active' AND not_after <= ?),
			(SELECT COUNT(*) FROM registrations WHERE state IN ('approved', 'ready') AND lease_expires_at > ? AND lease_expires_at <= ?)`, now, now, now.Add(7*24*time.Hour), now, now.Add(7*24*time.Hour)).Scan(&stats.Registrations, &stats.Active, &stats.Allocated, &stats.Available, &stats.Quarantined, &stats.Pending, &stats.RoutesPending, &stats.CertificatesSoon, &stats.LeasesSoon)
	if err != nil {
		return stats, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT state, lease_class, COUNT(*) FROM registrations GROUP BY state, lease_class`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, leaseClass string
		var count int64
		if err := rows.Scan(&state, &leaseClass, &count); err != nil {
			return stats, err
		}
		stats.RegistrationState[state+"\x00"+leaseClass] = count
	}
	return stats, rows.Err()
}

func (s *Store) MarkReady(ctx context.Context, projectID, environmentID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE registrations SET state = 'ready', updated_at = ? WHERE project_id = ? AND environment_id = ? AND state = 'approved'`, s.now().UTC(), projectID, environmentID)
	if err != nil {
		return fmt.Errorf("mark registration ready: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Revoke(ctx context.Context, projectID, environmentID string, quarantine time.Duration, auditJSON string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start revocation: %w", err)
	}
	defer tx.Rollback()
	registration, err := registrationByIdentityTx(ctx, tx, projectID, environmentID)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET state = 'revoked', updated_at = ? WHERE id = ?`, now, registration.ID); err != nil {
		return fmt.Errorf("revoke registration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET state = 'revoked' WHERE registration_id = ? AND state = 'active'`, registration.ID); err != nil {
		return fmt.Errorf("revoke certificates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_allocations SET state = 'quarantined', quarantine_until = ? WHERE registration_id = ?`, now.Add(quarantine), registration.ID); err != nil {
		return fmt.Errorf("quarantine route: %w", err)
	}
	if err := createRouteGenerationTx(ctx, tx, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, registration_id, occurred_at, data_json) VALUES ('registration.revoked', ?, ?, ?)`, registration.ID, now, auditJSON); err != nil {
		return fmt.Errorf("record revocation audit event: %w", err)
	}
	return tx.Commit()
}

func (s *Store) Expire(ctx context.Context, quarantine time.Duration) ([]Registration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("start lease expiry: %w", err)
	}
	defer tx.Rollback()
	now := s.now().UTC()
	rows, err := tx.QueryContext(ctx, registrationSelect+` WHERE state IN ('approved', 'ready') AND lease_expires_at <= ?`, now)
	if err != nil {
		return nil, fmt.Errorf("find expired registrations: %w", err)
	}
	var expired []Registration
	for rows.Next() {
		registration, scanErr := scanRegistration(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		expired = append(expired, registration)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close expired registration rows: %w", err)
	}
	for _, registration := range expired {
		if _, err := tx.ExecContext(ctx, `UPDATE registrations SET state = 'lease-expired', updated_at = ? WHERE id = ?`, now, registration.ID); err != nil {
			return nil, fmt.Errorf("expire registration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE route_allocations SET state = 'quarantined', quarantine_until = ? WHERE registration_id = ?`, now.Add(quarantine), registration.ID); err != nil {
			return nil, fmt.Errorf("quarantine expired route: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET state = 'expired' WHERE registration_id = ? AND state = 'active'`, registration.ID); err != nil {
			return nil, fmt.Errorf("expire connector certificates: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, registration_id, occurred_at, data_json) VALUES ('lease.expired', ?, ?, '{}')`, registration.ID, now); err != nil {
			return nil, fmt.Errorf("record lease expiry: %w", err)
		}
	}
	if len(expired) > 0 {
		if err := createRouteGenerationTx(ctx, tx, now); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_allocations SET state = 'free', registration_id = NULL, quarantine_until = NULL WHERE state = 'quarantined' AND quarantine_until <= ?`, now); err != nil {
		return nil, fmt.Errorf("release quarantined routes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_replays WHERE expires_at <= ?`, now); err != nil {
		return nil, fmt.Errorf("delete expired replay records: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_keys SET state = 'retired' WHERE state = 'overlap' AND overlap_until <= ?`, now); err != nil {
		return nil, fmt.Errorf("retire overlapping identity keys: %w", err)
	}
	return expired, tx.Commit()
}

func (s *Store) InitializePool(ctx context.Context, network netip.Prefix, excluded []netip.Prefix) error {
	if !network.Addr().Is6() || network.Bits() < 10 || network.Bits() > 16 || network != network.Masked() {
		return errors.New("virtual network must be a canonical IPv6 prefix from /10 through /16")
	}
	if !netip.MustParsePrefix("fd00::/8").Contains(network.Addr()) {
		return errors.New("virtual network must be inside fd00::/8")
	}
	count := 1 << (16 - network.Bits())
	base := network.Addr().As16()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for slot := range count {
		address := base
		address[1] += byte(slot)
		prefix := netip.PrefixFrom(netip.AddrFrom16(address), 16).Masked()
		rejected := false
		for _, reserved := range excluded {
			if prefixesOverlap(prefix, reserved) {
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO route_allocations(prefix, state) VALUES (?, 'free') ON CONFLICT(prefix) DO NOTHING`, prefix.String()); err != nil {
			return fmt.Errorf("initialize route allocation %s: %w", prefix, err)
		}
	}
	return tx.Commit()
}

func (s *Store) PendingRouteGeneration(ctx context.Context) (RouteGeneration, error) {
	var generation RouteGeneration
	var encoded string
	err := s.db.QueryRowContext(ctx, `SELECT id, desired_routes, state, last_error, created_at FROM route_generations WHERE state = 'pending' ORDER BY id LIMIT 1`).Scan(&generation.ID, &encoded, &generation.State, &generation.LastError, &generation.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RouteGeneration{}, ErrNotFound
	}
	if err != nil {
		return RouteGeneration{}, err
	}
	for _, value := range splitRoutes(encoded) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return RouteGeneration{}, fmt.Errorf("stored route generation is invalid: %w", err)
		}
		generation.DesiredRoutes = append(generation.DesiredRoutes, prefix)
	}
	return generation, nil
}

func (s *Store) CompleteRouteGeneration(ctx context.Context, id int64, reconcileErr error) error {
	state := "applied"
	message := ""
	if reconcileErr != nil {
		state = "pending"
		message = reconcileErr.Error()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE route_generations SET state = ?, last_error = ?, applied_at = CASE WHEN ? = 'applied' THEN ? ELSE applied_at END WHERE id = ?`, state, message, state, s.now().UTC(), id)
	return err
}

func Fingerprint(key []byte) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:])
}

const registrationSelect = `SELECT id, project_id, environment_id, environment_name, project_alias, environment_alias, state, identity_type, lease_class, lease_expires_at, virtual_prefix, real_prefix, created_at, updated_at FROM registrations`

type scanner interface{ Scan(...any) error }

func scanRegistration(row scanner) (Registration, error) {
	var registration Registration
	var virtualPrefix, realPrefix string
	err := row.Scan(&registration.ID, &registration.ProjectID, &registration.EnvironmentID,
		&registration.EnvironmentName, &registration.ProjectAlias, &registration.EnvironmentAlias,
		&registration.State, &registration.IdentityType, &registration.LeaseClass,
		&registration.LeaseExpiresAt, &virtualPrefix, &realPrefix, &registration.CreatedAt,
		&registration.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Registration{}, ErrNotFound
	}
	if err != nil {
		return Registration{}, fmt.Errorf("scan registration: %w", err)
	}
	registration.VirtualPrefix, err = netip.ParsePrefix(virtualPrefix)
	if err != nil {
		return Registration{}, fmt.Errorf("parse stored virtual prefix: %w", err)
	}
	registration.RealPrefix, err = netip.ParsePrefix(realPrefix)
	if err != nil {
		return Registration{}, fmt.Errorf("parse stored real prefix: %w", err)
	}
	return registration, nil
}

func pendingTx(ctx context.Context, tx *sql.Tx, id string) (PendingRequest, error) {
	var request PendingRequest
	err := tx.QueryRowContext(ctx, `SELECT id, kind, project_id, environment_id, environment_name, project_alias, environment_alias, identity_key, identity_key_id, transport_key, proof, source_address, created_at, expires_at, state FROM pending_requests WHERE id = ?`, id).Scan(
		&request.ID, &request.Kind, &request.ProjectID, &request.EnvironmentID,
		&request.EnvironmentName, &request.ProjectAlias, &request.EnvironmentAlias,
		&request.IdentityKey, &request.IdentityKeyID, &request.TransportKey,
		&request.Proof, &request.SourceAddress, &request.CreatedAt, &request.ExpiresAt,
		&request.State)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingRequest{}, ErrNotFound
	}
	return request, err
}

func registrationByIdentityTx(ctx context.Context, tx *sql.Tx, projectID, environmentID string) (Registration, error) {
	return scanRegistration(tx.QueryRowContext(ctx, registrationSelect+` WHERE project_id = ? AND environment_id = ?`, projectID, environmentID))
}

func registrationByIDTx(ctx context.Context, tx *sql.Tx, id int64) (Registration, error) {
	return scanRegistration(tx.QueryRowContext(ctx, registrationSelect+` WHERE id = ?`, id))
}

func allocatePrefixTx(ctx context.Context, tx *sql.Tx, now time.Time) (netip.Prefix, error) {
	if _, err := tx.ExecContext(ctx, `UPDATE route_allocations SET state = 'free', registration_id = NULL, quarantine_until = NULL WHERE state = 'quarantined' AND quarantine_until <= ?`, now); err != nil {
		return netip.Prefix{}, fmt.Errorf("release route quarantine: %w", err)
	}
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT prefix FROM route_allocations WHERE state = 'free' ORDER BY prefix LIMIT 1`).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return netip.Prefix{}, ErrPoolExhausted
	} else if err != nil {
		return netip.Prefix{}, fmt.Errorf("select route allocation: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE route_allocations SET state = 'allocated' WHERE prefix = ? AND state = 'free'`, raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("reserve route allocation: %w", err)
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("confirm route allocation: %w", err)
	}
	if claimed != 1 {
		return netip.Prefix{}, ErrPoolExhausted
	}
	return netip.ParsePrefix(raw)
}

func createRouteGenerationTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT virtual_prefix FROM registrations WHERE state IN ('approved', 'ready') AND lease_expires_at > ? ORDER BY virtual_prefix`, now)
	if err != nil {
		return fmt.Errorf("render route generation: %w", err)
	}
	defer rows.Close()
	var encoded string
	first := true
	for rows.Next() {
		var route string
		if err := rows.Scan(&route); err != nil {
			return fmt.Errorf("scan route generation: %w", err)
		}
		if !first {
			encoded += ","
		}
		first = false
		encoded += route
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_generations SET state = 'superseded' WHERE state = 'pending'`); err != nil {
		return fmt.Errorf("supersede route generation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_generations(desired_routes, state, created_at, last_error) VALUES (?, 'pending', ?, '')`, encoded, now); err != nil {
		return fmt.Errorf("create route generation: %w", err)
	}
	return nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func splitRoutes(value string) []string {
	if value == "" {
		return nil
	}
	var result []string
	start := 0
	for index := range len(value) {
		if value[index] == ',' {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	return append(result, value[start:])
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TIMESTAMP NOT NULL
);
INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS registrations (
	id INTEGER PRIMARY KEY,
	project_id TEXT NOT NULL,
	environment_id TEXT NOT NULL,
	environment_name TEXT NOT NULL,
	project_alias TEXT NOT NULL,
	environment_alias TEXT NOT NULL,
	state TEXT NOT NULL,
	identity_type TEXT NOT NULL,
	lease_class TEXT NOT NULL,
	lease_expires_at TIMESTAMP NOT NULL,
	virtual_prefix TEXT NOT NULL UNIQUE,
	real_prefix TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	UNIQUE(project_id, environment_id),
	UNIQUE(project_alias, environment_alias)
);

CREATE TABLE IF NOT EXISTS pending_requests (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	project_id TEXT NOT NULL,
	environment_id TEXT NOT NULL,
	environment_name TEXT NOT NULL,
	project_alias TEXT NOT NULL,
	environment_alias TEXT NOT NULL,
	identity_key BLOB NOT NULL,
	identity_key_id TEXT NOT NULL,
	transport_key BLOB NOT NULL,
	proof BLOB NOT NULL,
	source_address TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	state TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_identity ON pending_requests(project_id, environment_id, state);
CREATE INDEX IF NOT EXISTS pending_source ON pending_requests(source_address, state);

CREATE TABLE IF NOT EXISTS identity_keys (
	id INTEGER PRIMARY KEY,
	registration_id INTEGER NOT NULL REFERENCES registrations(id),
	key_id TEXT NOT NULL,
	public_key BLOB NOT NULL,
	state TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	rotate_after TIMESTAMP NOT NULL,
	overlap_until TIMESTAMP,
	UNIQUE(registration_id, key_id)
);

CREATE TABLE IF NOT EXISTS certificates (
	id TEXT PRIMARY KEY,
	registration_id INTEGER NOT NULL REFERENCES registrations(id),
	identity_key_id TEXT NOT NULL,
	certificate_pem BLOB NOT NULL,
	state TEXT NOT NULL,
	not_after TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS leases (
	id INTEGER PRIMARY KEY,
	registration_id INTEGER NOT NULL REFERENCES registrations(id),
	lease_class TEXT NOT NULL,
	starts_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	renewed_at TIMESTAMP NOT NULL,
	source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS route_allocations (
	prefix TEXT PRIMARY KEY,
	state TEXT NOT NULL,
	registration_id INTEGER REFERENCES registrations(id),
	quarantine_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS route_generations (
	id INTEGER PRIMARY KEY,
	desired_routes TEXT NOT NULL,
	state TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	applied_at TIMESTAMP,
	last_error TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_replays (
	provider_id TEXT NOT NULL,
	jti_hash BLOB NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	PRIMARY KEY(provider_id, jti_hash)
);

CREATE TABLE IF NOT EXISTS dns_aliases (
	id INTEGER PRIMARY KEY,
	registration_id INTEGER REFERENCES registrations(id),
	project_alias TEXT NOT NULL,
	environment_alias TEXT NOT NULL,
	state TEXT NOT NULL,
	quarantine_until TIMESTAMP,
	UNIQUE(project_alias, environment_alias)
);

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY,
	event_type TEXT NOT NULL,
	request_id TEXT,
	registration_id INTEGER REFERENCES registrations(id),
	occurred_at TIMESTAMP NOT NULL,
	data_json TEXT NOT NULL
);
`
