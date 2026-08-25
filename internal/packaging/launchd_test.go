package packaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Fake launchctl runner ---

type fakeLaunchctl struct {
	// out and err answer every call; outFor overrides them per first argument.
	out    []byte
	err    error
	outFor map[string][]byte
	errFor map[string]error

	calls [][]string
}

func (f *fakeLaunchctl) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if len(args) > 0 {
		if out, ok := f.outFor[args[0]]; ok {
			return out, f.errFor[args[0]]
		}
		if err, ok := f.errFor[args[0]]; ok {
			return f.out, err
		}
	}
	return f.out, f.err
}

// lastCall returns the arguments of the most recent launchctl invocation.
func (f *fakeLaunchctl) lastCall(t *testing.T) []string {
	t.Helper()
	if len(f.calls) == 0 {
		t.Fatal("launchctl was never called")
	}
	return f.calls[len(f.calls)-1]
}

// newTestLaunchdManager returns a launchd manager whose plist and newsyslog
// rule live under t.TempDir(), so the file flow runs on every platform.
func newTestLaunchdManager(t *testing.T, run *fakeLaunchctl) (*launchdManager, InstallConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	mgr := &launchdManager{
		run:          run.run,
		newsyslogDir: filepath.Join(tmpDir, "etc", "newsyslog.d"),
		logger:       testLogger(),
	}
	cfg := InstallConfig{
		BinaryPath:   filepath.Join(tmpDir, "usr", "local", "bin", "plexd"),
		ConfigDir:    filepath.Join(tmpDir, "etc", "plexd"),
		DataDir:      filepath.Join(tmpDir, "var", "lib", "plexd"),
		RunDir:       filepath.Join(tmpDir, "var", "run", "plexd"),
		UnitFilePath: filepath.Join(tmpDir, "Library", "LaunchDaemons", "com.plexsphere.plexd.plist"),
		LogDir:       filepath.Join(tmpDir, "Library", "Logs", "plexd"),
		ServiceName:  "plexd",
	}
	return mgr, cfg
}

// --- Plist rendering ---

// macosDefaultConfig names the macOS defaults explicitly rather than relying on
// ApplyDefaults, so the document under test is the same on every runner.
func macosDefaultConfig() InstallConfig {
	return InstallConfig{
		BinaryPath:   "/usr/local/bin/plexd",
		ConfigDir:    "/Library/Application Support/plexd",
		DataDir:      "/Library/Application Support/plexd/data",
		RunDir:       "/var/run/plexd",
		UnitFilePath: "/Library/LaunchDaemons/com.plexsphere.plexd.plist",
		LogDir:       "/Library/Logs/plexd",
		ServiceName:  "plexd",
	}
}

func TestGenerateLaunchdPlist_Default(t *testing.T) {
	got := GenerateLaunchdPlist(macosDefaultConfig())

	wants := []string{
		"<string>com.plexsphere.plexd</string>",
		"<string>/usr/local/bin/plexd</string>",
		"<string>up</string>",
		"<string>--config</string>",
		"<string>/Library/Application Support/plexd/config.yaml</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>ThrottleInterval</key>\n\t<integer>5</integer>",
		"<key>StandardOutPath</key>\n\t<string>/Library/Logs/plexd/plexd.log</string>",
		"<key>StandardErrorPath</key>\n\t<string>/Library/Logs/plexd/plexd.log</string>",
		"<key>SoftResourceLimits</key>\n\t<dict>\n\t\t<key>NumberOfFiles</key>\n\t\t<integer>65536</integer>",
		"<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>NumberOfFiles</key>\n\t\t<integer>65536</integer>",
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("plist missing %q, got:\n%s", want, got)
		}
	}

	// The four ProgramArguments strings must appear in the order launchd
	// passes them to the binary.
	order := []string{"/usr/local/bin/plexd", "up", "--config", "/Library/Application Support/plexd/config.yaml"}
	pos := 0
	for _, arg := range order {
		idx := strings.Index(got[pos:], "<string>"+arg+"</string>")
		if idx < 0 {
			t.Fatalf("ProgramArguments out of order: %q does not follow the previous argument", arg)
		}
		pos += idx
	}
}

// A path holding an XML metacharacter must not produce a plist launchd refuses
// to parse. & is the one that appears in a real directory name.
func TestGenerateLaunchdPlist_EscapesXML(t *testing.T) {
	cfg := macosDefaultConfig()
	cfg.BinaryPath = "/opt/a&b/plexd"

	got := GenerateLaunchdPlist(cfg)
	if !strings.Contains(got, "<string>/opt/a&amp;b/plexd</string>") {
		t.Errorf("plist did not escape &, got:\n%s", got)
	}
	if strings.Contains(got, "/opt/a&b/plexd") {
		t.Error("plist carries the raw & from BinaryPath")
	}
}

func TestGenerateNewsyslogConf(t *testing.T) {
	got := GenerateNewsyslogConf(macosDefaultConfig())

	if !strings.HasPrefix(got, "# plexd log rotation, written by plexd install\n") {
		t.Errorf("newsyslog config missing its comment line, got:\n%s", got)
	}
	want := "/Library/Logs/plexd/plexd.log\t644\t5\t10240\t*\tJ\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("newsyslog rule = %q, want it to end with %q", got, want)
	}
}

// --- Manager ---

func TestLaunchdManager_RegisterWritesPlistAndNewsyslog(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)

	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	data, err := os.ReadFile(cfg.UnitFilePath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", cfg.UnitFilePath, err)
	}
	if !strings.Contains(string(data), "<string>com.plexsphere.plexd</string>") {
		t.Errorf("plist missing the label, got:\n%s", data)
	}

	confPath := filepath.Join(mgr.newsyslogDir, "com.plexsphere.plexd.conf")
	if _, err := os.Stat(confPath); err != nil {
		t.Errorf("Stat(%q) = %v, want the newsyslog rule to exist", confPath, err)
	}

	// plexd install registers without starting, so launchd is never asked to
	// load anything here.
	if len(run.calls) != 0 {
		t.Errorf("launchctl called %v, want no call from Register", run.calls)
	}
}

func TestLaunchdManager_RegisterRequiresLogDir(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)
	cfg.LogDir = ""

	err := mgr.Register(cfg)
	if err == nil {
		t.Fatal("Register() = nil, want error for empty LogDir")
	}
	if want := "packaging: config: LogDir is required"; err.Error() != want {
		t.Errorf("Register() error = %q, want %q", err.Error(), want)
	}
}

func TestLaunchdManager_RegisterRequiresUnitFilePath(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)
	cfg.UnitFilePath = ""

	err := mgr.Register(cfg)
	if err == nil {
		t.Fatal("Register() = nil, want error for empty UnitFilePath")
	}
	if want := "packaging: config: UnitFilePath is required"; err.Error() != want {
		t.Errorf("Register() error = %q, want %q", err.Error(), want)
	}
}

func TestLaunchdManager_StartBootstraps(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)

	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("Start() = %v", err)
	}

	want := []string{"bootstrap", "system", cfg.UnitFilePath}
	if got := run.lastCall(t); !equalArgs(got, want) {
		t.Errorf("launchctl args = %v, want %v", got, want)
	}
}

func TestLaunchdManager_StopBootsOutWhenRunning(t *testing.T) {
	run := &fakeLaunchctl{outFor: map[string][]byte{
		"print": []byte("system/com.plexsphere.plexd = {\n\tstate = running\n}"),
	}}
	mgr, cfg := newTestLaunchdManager(t, run)
	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	if err := mgr.Stop(cfg); err != nil {
		t.Fatalf("Stop() = %v", err)
	}

	if len(run.calls) != 2 {
		t.Fatalf("launchctl calls = %v, want a print followed by a bootout", run.calls)
	}
	if got, want := run.calls[0], []string{"print", "system/com.plexsphere.plexd"}; !equalArgs(got, want) {
		t.Errorf("first call = %v, want %v", got, want)
	}
	if got, want := run.calls[1], []string{"bootout", "system/com.plexsphere.plexd"}; !equalArgs(got, want) {
		t.Errorf("second call = %v, want %v", got, want)
	}
}

func TestLaunchdManager_StopNoopWhenNotLoaded(t *testing.T) {
	run := &fakeLaunchctl{errFor: map[string]error{"print": errors.New("could not find service")}}
	mgr, cfg := newTestLaunchdManager(t, run)
	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	if err := mgr.Stop(cfg); err != nil {
		t.Fatalf("Stop() = %v, want nil when the daemon is not loaded", err)
	}

	for _, call := range run.calls {
		if len(call) > 0 && call[0] == "bootout" {
			t.Errorf("Stop() ran bootout %v on a daemon launchd does not hold", call)
		}
	}
}

func TestLaunchdManager_RestartKickstarts(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)

	if err := mgr.Restart(context.Background(), cfg); err != nil {
		t.Fatalf("Restart() = %v", err)
	}

	want := []string{"kickstart", "-k", "system/com.plexsphere.plexd"}
	if got := run.lastCall(t); !equalArgs(got, want) {
		t.Errorf("launchctl args = %v, want %v", got, want)
	}
}

func TestLaunchdManager_RestartError(t *testing.T) {
	run := &fakeLaunchctl{out: []byte("Could not find service\n"), err: errors.New("exit status 113")}
	mgr, cfg := newTestLaunchdManager(t, run)

	err := mgr.Restart(context.Background(), cfg)
	if err == nil {
		t.Fatal("Restart() = nil, want the runner's failure")
	}
	want := "packaging: launchctl kickstart: Could not find service: exit status 113"
	if err.Error() != want {
		t.Errorf("Restart() error = %q, want %q", err.Error(), want)
	}
}

func TestLaunchdManager_StatusNotRegistered(t *testing.T) {
	run := &fakeLaunchctl{}
	mgr, cfg := newTestLaunchdManager(t, run)

	_, err := mgr.Status(cfg)
	if !errors.Is(err, ErrNotRegistered) {
		t.Errorf("Status() error = %v, want ErrNotRegistered", err)
	}
}

// A daemon that is not loaded answers bootout with an error, and an uninstall
// that gave up there would leave the plist behind for good.
func TestLaunchdManager_UnregisterRemovesFilesToleratingBootout(t *testing.T) {
	run := &fakeLaunchctl{out: []byte("Boot-out failed: 3: No such process"), err: errors.New("exit status 3")}
	mgr, cfg := newTestLaunchdManager(t, run)
	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	if err := mgr.Unregister(cfg); err != nil {
		t.Fatalf("Unregister() = %v, want nil despite the bootout failure", err)
	}

	if _, err := os.Stat(cfg.UnitFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(plist) = %v, want os.ErrNotExist", err)
	}
	confPath := filepath.Join(mgr.newsyslogDir, "com.plexsphere.plexd.conf")
	if _, err := os.Stat(confPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(newsyslog rule) = %v, want os.ErrNotExist", err)
	}
}

func equalArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
