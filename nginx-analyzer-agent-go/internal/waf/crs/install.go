package crs

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Limites et hotes autorises (contrat : github.com / codeload.github.com uniquement).
const (
	MaxDownloadBytes = 50 << 20  // taille max de l'archive telechargee
	maxFileBytes     = 20 << 20  // taille max d'un fichier extrait
	maxTotalBytes    = 100 << 20 // taille max cumulee extraite
	maxRedirects     = 5
)

// DefaultAllowedHosts : seuls hotes de telechargement acceptes (URL initiale ET redirections).
var DefaultAllowedHosts = []string{"github.com", "codeload.github.com"}

// DefaultURLTemplate : modele d'URL du tarball CRS.
const DefaultURLTemplate = "https://github.com/coreruleset/coreruleset/archive/refs/tags/%s.tar.gz"

var (
	reVersion  = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){1,3}([-.][A-Za-z0-9]{1,16}){0,2}$`)
	reBaseName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$`)
)

// ValidVersion : tag CRS accepte (evite toute injection dans l'URL).
func ValidVersion(v string) bool { return len(v) <= 40 && reVersion.MatchString(v) }

// Downloader telecharge et installe le CRS. Les champs sont exportes pour les tests.
type Downloader struct {
	Client       *http.Client
	AllowedHosts []string
	Template     string
	MaxBytes     int64
}

// NewDownloader : client HTTP avec delai global et verification des redirections.
func NewDownloader(template string) *Downloader {
	if template == "" {
		template = DefaultURLTemplate
	}
	return &Downloader{
		Client:       &http.Client{Timeout: 3 * time.Minute},
		AllowedHosts: DefaultAllowedHosts,
		Template:     template,
		MaxBytes:     MaxDownloadBytes,
	}
}

func (d *Downloader) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("schema non autorise : %q (https uniquement)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("identifiants dans l'URL interdits")
	}
	for _, h := range d.AllowedHosts {
		if strings.EqualFold(u.Host, h) {
			return nil
		}
	}
	return fmt.Errorf("hote non autorise : %q", u.Host)
}

// URLFor construit et valide l'URL du tarball pour une version.
func (d *Downloader) URLFor(version string) (*url.URL, error) {
	if !ValidVersion(version) {
		return nil, fmt.Errorf("version CRS invalide : %q", truncate(version, 40))
	}
	if strings.Count(d.Template, "%s") != 1 {
		return nil, errors.New("CRS_URL_TEMPLATE doit contenir exactement un %s")
	}
	raw := fmt.Sprintf(strings.Replace(d.Template, "%s", "%[1]s", 1), version)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("URL invalide : %v", err)
	}
	if err := d.checkURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

type limitedReader struct {
	r   io.Reader
	n   int64
	err error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, l.err
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// Install telecharge version et remplace atomiquement rulesDir/crs.
func (d *Downloader) Install(ctx context.Context, rulesDir, version string) error {
	u, err := d.URLFor(version)
	if err != nil {
		return err
	}
	client := *d.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("trop de redirections")
		}
		return d.checkURL(req.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nginx-analyzer-waf")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telechargement : %v", sanitizeErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telechargement : HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > d.MaxBytes {
		return fmt.Errorf("archive trop volumineuse (> %d Mo)", d.MaxBytes>>20)
	}
	return InstallTarball(resp.Body, rulesDir, version, d.MaxBytes)
}

// sanitizeErr retire l'URL eventuelle d'une erreur reseau (pas de donnee sensible dans les logs).
func sanitizeErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s : %v", ue.Op, ue.Err)
	}
	return err
}

// InstallTarball extrait un .tar.gz CRS dans un dossier temporaire de rulesDir puis echange
// atomiquement rulesDir/crs. Seuls rules/*.conf, rules/*.data et crs-setup.conf.example sont
// extraits ; tout nom contenant "..", absolu ou avec antislash fait refuser l'archive ; un
// lien (symbolique/dur) visant un fichier a extraire aussi.
func InstallTarball(src io.Reader, rulesDir, version string, maxBytes int64) error {
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(rulesDir, ".crs-tmp-")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	if err := extract(src, tmp, maxBytes); err != nil {
		return err
	}
	matches, _ := filepath.Glob(filepath.Join(tmp, "rules", "REQUEST-9*.conf"))
	if len(matches) == 0 {
		return errors.New("archive invalide : aucun fichier rules/REQUEST-9*.conf")
	}
	if err := os.WriteFile(filepath.Join(tmp, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		return err
	}
	crsDir := filepath.Join(rulesDir, "crs")
	old := filepath.Join(rulesDir, ".crs-old")
	os.RemoveAll(old)
	hadOld := false
	if _, err := os.Lstat(crsDir); err == nil {
		if err := os.Rename(crsDir, old); err != nil {
			return fmt.Errorf("echange atomique : %w", err)
		}
		hadOld = true
	}
	if err := os.Rename(tmp, crsDir); err != nil {
		if hadOld {
			_ = os.Rename(old, crsDir)
		}
		return fmt.Errorf("echange atomique : %w", err)
	}
	ok = true
	os.RemoveAll(old)
	return nil
}

func wanted(rel string) bool {
	if rel == "crs-setup.conf.example" {
		return true
	}
	dir, base := path.Split(rel)
	if dir != "rules/" {
		return false
	}
	ext := path.Ext(base)
	return ext == ".conf" || ext == ".data"
}

func extract(src io.Reader, dest string, maxBytes int64) error {
	lr := &limitedReader{r: src, n: maxBytes + 1, err: fmt.Errorf("archive trop volumineuse (> %d Mo)", maxBytes>>20)}
	gz, err := gzip.NewReader(lr)
	if err != nil {
		return fmt.Errorf("archive gzip invalide : %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("archive tar invalide : %v", err)
		}
		name := hdr.Name
		if name == "" || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
			return fmt.Errorf("entree d'archive refusee (chemin non sur) : %q", truncate(name, 80))
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return fmt.Errorf("entree d'archive refusee (..) : %q", truncate(name, 80))
			}
		}
		clean := path.Clean(name)
		_, rel, found := strings.Cut(clean, "/") // retire le dossier racine coreruleset-x.y.z
		if !found || hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			if wanted(rel) {
				return fmt.Errorf("lien refuse dans l'archive : %q", truncate(name, 80))
			}
			continue
		default:
			continue
		}
		if !wanted(rel) {
			continue
		}
		if !reBaseName.MatchString(path.Base(rel)) {
			return fmt.Errorf("nom de fichier refuse : %q", truncate(rel, 80))
		}
		if hdr.Size > maxFileBytes {
			return fmt.Errorf("fichier trop volumineux dans l'archive : %q", truncate(rel, 80))
		}
		total += hdr.Size
		if total > maxTotalBytes {
			return errors.New("contenu extrait trop volumineux")
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
		cerr := f.Close()
		if err != nil {
			return fmt.Errorf("extraction : %v", err)
		}
		if cerr != nil {
			return cerr
		}
		if n != hdr.Size {
			return errors.New("extraction tronquee")
		}
	}
	return nil
}

// Status est l'etat expose dans /api/status.crs.
type Status struct {
	Version     string  `json:"version"`
	Installed   bool    `json:"installed"`
	UpdatedAt   string  `json:"updatedAt,omitempty"`
	Downloading bool    `json:"downloading"`
	LastError   *string `json:"lastError"`
}

// Manager serialise les telechargements et garde l'etat.
type Manager struct {
	rulesDir string
	dl       *Downloader
	defVer   string

	mu          sync.Mutex
	downloading bool
	lastErr     string
	updatedAt   time.Time
}

// NewManager : defVer = CRS_VERSION.
func NewManager(rulesDir, defVer string, dl *Downloader) *Manager {
	return &Manager{rulesDir: rulesDir, dl: dl, defVer: defVer}
}

// Dir renvoie rulesDir/crs.
func (m *Manager) Dir() string { return filepath.Join(m.rulesDir, "crs") }

// Empty : crs/ absent ou sans rules/REQUEST-9*.conf.
func (m *Manager) Empty() bool {
	matches, _ := filepath.Glob(filepath.Join(m.Dir(), "rules", "REQUEST-9*.conf"))
	return len(matches) == 0
}

var reOWASPVer = regexp.MustCompile(`OWASP_CRS/(\d+\.\d+\.\d+)`)

// InstalledVersion lit crs/VERSION, sinon deduit la version des regles ("" si inconnue).
func (m *Manager) InstalledVersion() string {
	if b, err := os.ReadFile(filepath.Join(m.Dir(), "VERSION")); err == nil {
		v := strings.TrimSpace(string(b))
		if ValidVersion(v) {
			return v
		}
	}
	if b, err := os.ReadFile(filepath.Join(m.Dir(), "rules", "REQUEST-901-INITIALIZATION.conf")); err == nil {
		if mm := reOWASPVer.FindSubmatch(b); mm != nil {
			return "v" + string(mm[1])
		}
	}
	return ""
}

// Status renvoie l'etat courant.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Installed: !m.Empty(), Downloading: m.downloading}
	st.Version = m.InstalledVersion()
	if st.Version == "" {
		st.Version = m.defVer
	}
	if st.Installed && m.updatedAt.IsZero() {
		if fi, err := os.Stat(filepath.Join(m.Dir(), "rules")); err == nil {
			m.updatedAt = fi.ModTime()
		}
	}
	if !m.updatedAt.IsZero() {
		st.UpdatedAt = m.updatedAt.UTC().Format(time.RFC3339)
	}
	if m.lastErr != "" {
		e := m.lastErr
		st.LastError = &e
	}
	return st
}

// ErrBusy : un telechargement est deja en cours.
var ErrBusy = errors.New("un telechargement est deja en cours")

// Start lance un telechargement asynchrone (version vide = CRS_VERSION). onDone est appele
// (dans la goroutine) apres succes uniquement. L'echec n'arrete jamais le processus.
func (m *Manager) Start(ctx context.Context, version string, onDone func()) error {
	if version == "" {
		version = m.defVer
	}
	if !ValidVersion(version) {
		return fmt.Errorf("version CRS invalide : %q", truncate(version, 40))
	}
	m.mu.Lock()
	if m.downloading {
		m.mu.Unlock()
		return ErrBusy
	}
	m.downloading = true
	m.mu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				m.finish(fmt.Errorf("panique pendant l'installation : %v", r))
			}
		}()
		err := m.dl.Install(ctx, m.rulesDir, version)
		m.finish(err)
		if err == nil && onDone != nil {
			onDone()
		}
	}()
	return nil
}

func (m *Manager) finish(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downloading = false
	if err != nil {
		m.lastErr = truncate(err.Error(), 300)
		return
	}
	m.lastErr = ""
	m.updatedAt = time.Now()
}
