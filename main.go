package main

import (
	"bufio"
	"crypto/sha256"
	_ "embed" // required for //go:embed
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

// Paths

// getScriptRoot returns the directory containing the executable.
func getScriptRoot() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not determine executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("could not resolve executable path: %w", err)
	}
	return filepath.Dir(exePath), nil
}

// addToolsToPath prepends Tools\Sysinternals to PATH and returns the Tools directory.
func addToolsToPath(scriptRoot string) (string, error) {
	tools := filepath.Join(scriptRoot, "Tools")

	newPath := strings.Join([]string{
		filepath.Join(tools, "Sysinternals"),
		os.Getenv("PATH"),
	}, string(os.PathListSeparator))

	if err := os.Setenv("PATH", newPath); err != nil {
		return "", fmt.Errorf("could not set PATH: %w", err)
	}
	return tools, nil
}

// buildCaseDir returns this run's case folder: Cases\<host>_<UTC timestamp>.
func buildCaseDir(scriptRoot string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	computerName := os.Getenv("COMPUTERNAME")
	return filepath.Join(scriptRoot, "Cases", computerName+"_"+stamp)
}

// Banner

// ANSI color codes for console output.
const (
	reset    = "\033[0m"
	darkGray = "\033[90m"
	gray     = "\033[37m"
	yellow   = "\033[93m"
	darkRed  = "\033[31m"
	cyan     = "\033[96m"
	white    = "\033[97m"
	green    = "\033[92m"
	red      = "\033[91m"

	// Black text on a colored background, used for section headers.
	blackOnYellow = "\033[30;103m"
	blackOnGreen  = "\033[30;102m"
)

// color wraps text in a color code and resets afterward.
func color(c, text string) string {
	return c + text + reset
}

// showBanner clears the screen and prints the banner, host details and admin status.
func showBanner() {
	fmt.Print("\033[2J\033[H") // clear the screen

	beamL := "= = = = = = = "
	beamR := " = = = = = = ="

	// Fog + lighthouse
	fmt.Println(color(darkGray, "  ~    ~   ~     ~     ~   ~    ~      ~"))
	fmt.Println(color(gray, `                    /\`))
	fmt.Println(color(gray, `                   /  \`))
	fmt.Println(color(gray, `                  /____\`))

	// Lamp row
	fmt.Println(
		color(yellow, "   "+beamL) +
			color(gray, "|  ") +
			color(yellow, "()") +
			color(gray, "  |") +
			color(yellow, beamR))

	// Tower
	fmt.Println(color(gray, "                 |______|"))
	fmt.Println(color(gray, "                  |") + color(darkRed, "####") + color(gray, "|"))
	fmt.Println(color(gray, "                  |    |"))
	fmt.Println(color(gray, "                  |") + color(darkRed, "####") + color(gray, "|"))
	fmt.Println(color(gray, "                  |    |"))
	fmt.Println(color(gray, "                 /######\\"))
	fmt.Println(color(darkGray, "  ~   ~   ~   ~  ~~~~~~~~~~  ~   ~   ~   ~"))
	fmt.Println()

	// Title
	title := ` _____    ___     ____   _       _           _       _
|  ___|  / _ \   / ___| | |     (_)   __ _  | |__   | |_
| |_    | | | | | |  _  | |     | |  / _` + "`" + ` | | '_ \  | __|
|  _|   | |_| | | |_| | | |___  | | | (_| | | | | | | |_
|_|      \___/   \____| |_____| |_|  \__, | |_| |_|  \__|
                                     |___/`
	fmt.Println(color(cyan, title))
	fmt.Println()

	// Info block
	prefix := color(darkGray, "+ -- --=[ ")
	fmt.Println(color(darkGray, "       =[ ") + color(white, "FOGLight v0.1 beta - Windows Triage Collector"))
	fmt.Println(prefix + color(gray, "Memory | Live Response"))
	fmt.Println(prefix + color(gray, fmt.Sprintf("Host: %s   User: %s",
		os.Getenv("COMPUTERNAME"), os.Getenv("USERNAME"))))

	if isAdmin() {
		fmt.Println(prefix + color(green, "Admin: YES"))
	} else {
		fmt.Println(prefix + color(red, "Admin: NO - memory capture will fail"))
	}
	fmt.Println()
}

// Menu

// prompt prints a message and reads one line of input.
// It returns false if input has been closed.
func prompt(reader *bufio.Reader, message string) (string, bool) {
	fmt.Print(message + ": ")
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(line), true
}

// showMenu prints the collection options.
func showMenu() {
	fmt.Println(color(cyan, "  [1]") + " Full collection (Memory + Live Response)")
	fmt.Println(color(cyan, "  [2]") + " Raw Memory only")
	fmt.Println(color(cyan, "  [3]") + " Live Response only")
	fmt.Println(color(cyan, "  [Q]") + " Quit")
	fmt.Println()
}

// runMenu shows the menu and runs the selected collection until the user quits.
func runMenu(caseDir string) {
	reader := bufio.NewReader(os.Stdin)

	for {
		showMenu()

		choice, ok := prompt(reader, "Select")
		if !ok {
			return
		}

		switch strings.ToUpper(choice) {
		case "1":
			startRawMemory(caseDir)
			startLiveResponse(caseDir)
		case "2":
			startRawMemory(caseDir)
		case "3":
			startLiveResponse(caseDir)
		case "Q":
			return
		default:
			fmt.Println(color(red, "Invalid choice"))
		}

		prompt(reader, "Press Enter to continue")
	}
}

// Step helpers

// printMu serializes console output so parallel steps never interleave mid-line.
var printMu sync.Mutex

// say prints one line safely from any goroutine.
func say(line string) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Println(line)
}

// runStep runs one collection step and reports success or failure with its duration.
func runStep(name string, action func() error) {
	say("Getting " + name + "...")
	start := time.Now()

	err := safeCall(action)
	took := time.Since(start).Round(100 * time.Millisecond)

	if err != nil {
		say(color(red, fmt.Sprintf("%s FAILED: %v", name, err)))
		return
	}
	say(color(green, fmt.Sprintf("%s recorded (%s)", name, took)))
}

// safeCall runs action and converts a panic into an error,
// so one failing step cannot crash the whole program.
func safeCall(action func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("crashed: %v", r)
		}
	}()
	return action()
}

// stepRunner runs steps in parallel, but never more than a set number at once.
type stepRunner struct {
	wg    sync.WaitGroup // counts steps that haven't finished yet
	slots chan struct{}  // one "seat" per step allowed to run at the same time
}

// newStepRunner returns a runner that allows up to maxAtOnce steps at the same time.
func newStepRunner(maxAtOnce int) *stepRunner {
	return &stepRunner{slots: make(chan struct{}, maxAtOnce)}
}

// Go starts a step in the background. It returns right away.
func (r *stepRunner) Go(name string, action func() error) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		r.slots <- struct{}{}        // take a seat (waits here if all seats are full)
		defer func() { <-r.slots }() // give the seat back when done

		runStep(name, action)
	}()
}

// Wait blocks until every step started with Go has finished.
func (r *stepRunner) Wait() {
	r.wg.Wait()
}

// runToFile runs an external command and saves its stdout and stderr to outPath.
// A non-zero exit code is returned as an error; the output is saved either way.
func runToFile(outPath, name string, args ...string) error {
	output, runErr := exec.Command(name, args...).CombinedOutput()
	if err := os.WriteFile(outPath, output, 0o644); err != nil {
		return err
	}
	return runErr
}

// writeLines writes lines of text to a file with Windows line endings.
func writeLines(path string, lines []string) error {
	text := strings.Join(lines, "\r\n") + "\r\n"
	return os.WriteFile(path, []byte(text), 0o644)
}

// hashFile returns a file's SHA256 as uppercase hex.
// The file is streamed, so large images are never loaded into memory.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// sectionHeader prints a highlighted line like "Raw Memory Started".
func sectionHeader(c, text string) {
	fmt.Println(color(c, " "+text+" "))
}

// gb converts bytes to gigabytes for display.
func gb(bytes uint64) float64 {
	return float64(bytes) / (1 << 30)
}

// Windows API calls

// Kernel32 functions not wrapped by golang.org/x/sys/windows.
var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
)

// enableColors turns on ANSI color support in older Windows consoles.
func enableColors() {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return // not a real console (e.g. output redirected), so skip
	}
	windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

// isAdmin reports whether the process is running elevated.
func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// memoryStatusEx matches the MEMORYSTATUSEX struct Windows fills in.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// totalRAM returns usable physical memory in bytes.
func totalRAM() (uint64, error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	ok, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if ok == 0 {
		return 0, err
	}
	return m.TotalPhys, nil
}

// uptime returns how long the system has been running.
func uptime() time.Duration {
	ms, _, _ := procGetTickCount64.Call()
	return time.Duration(ms) * time.Millisecond
}

// volumeInfo returns the filesystem name (NTFS, exFAT, FAT32...) and the
// free space available for the drive that holds path.
func volumeInfo(path string) (fsName string, freeBytes uint64, err error) {
	root := filepath.VolumeName(path) + `\` // e.g. "E:\"
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", 0, err
	}

	var total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(rootPtr, &freeBytes, &total, &totalFree); err != nil {
		return "", 0, fmt.Errorf("free space on %s: %w", root, err)
	}

	fsBuf := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeInformation(rootPtr, nil, 0, nil, nil, nil, &fsBuf[0], uint32(len(fsBuf))); err != nil {
		return "", 0, fmt.Errorf("volume info for %s: %w", root, err)
	}
	return windows.UTF16ToString(fsBuf), freeBytes, nil
}

// fileVersion returns the file version from an executable's version resource.
func fileVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", err
	}

	var fixed *windows.VS_FIXEDFILEINFO
	var fixedLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &fixedLen); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		fixed.FileVersionMS>>16, fixed.FileVersionMS&0xffff,
		fixed.FileVersionLS>>16, fixed.FileVersionLS&0xffff), nil
}

// timeZoneName returns the Windows time zone name, e.g. "Pacific Standard Time".
func timeZoneName() string {
	var tz windows.Timezoneinformation
	if _, err := windows.GetTimeZoneInformation(&tz); err != nil {
		return "unknown"
	}
	return windows.UTF16ToString(tz.StandardName[:])
}

// Raw memory

// winpmemExe is the bundled WinPmem filename. It must match the //go:embed path below.
const winpmemExe = "go-winpmem_amd64_1.0-rc2_signed.exe"

// winpmemBinary is the official WinPmem release, embedded at build time.
//
//go:embed tools/winpmem/go-winpmem_amd64_1.0-rc2_signed.exe
var winpmemBinary []byte

// extractWinpmem writes the embedded WinPmem to the case Tools folder on the
// collection drive and returns its path. The copy is kept as a record of what ran.
func extractWinpmem(caseDir string) (string, error) {
	toolDir := filepath.Join(caseDir, "Tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(toolDir, winpmemExe)
	if err := os.WriteFile(path, winpmemBinary, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// startRawMemory checks prerequisites, captures RAM with WinPmem, verifies the
// image, and documents the capture in memory_info.txt.
func startRawMemory(caseDir string) {
	outDir := filepath.Join(caseDir, "RawMemory")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Println(color(red, "Could not create output folder: "+err.Error()))
		return
	}

	sectionHeader(blackOnYellow, "Raw Memory Started")

	host := os.Getenv("COMPUTERNAME")
	outFile := filepath.Join(outDir, host+"_memory.raw")
	infoFile := filepath.Join(outDir, "memory_info.txt")

	// Pre-checks
	if !isAdmin() {
		fmt.Println(color(red, "Memory capture requires admin. Skipping."))
		return
	}

	// Extract the embedded WinPmem
	pmemPath, err := extractWinpmem(caseDir)
	if err != nil {
		fmt.Println(color(red, "Could not extract winpmem: "+err.Error()+". Skipping."))
		return
	}

	ram, err := totalRAM()
	if err != nil {
		fmt.Println(color(red, "Could not read RAM size: "+err.Error()+". Skipping."))
		return
	}

	fsName, free, err := volumeInfo(outDir)
	if err != nil {
		fmt.Println(color(yellow, "Could not check output drive space - continuing anyway."))
	} else {
		if fsName == "FAT32" {
			fmt.Println(color(red, "Output drive is FAT32 (4 GB file limit). Use exFAT or NTFS. Skipping."))
			return
		}
		if float64(free) < float64(ram)*1.1 {
			fmt.Println(color(red, fmt.Sprintf(
				"Not enough space: need ~%.1f GB, have %.1f GB. Skipping.", gb(ram), gb(free))))
			return
		}
	}

	// Capture
	fmt.Printf("Capturing %.1f GB of RAM to %s\n", gb(ram), outFile)
	fmt.Println(color(yellow, "This can take several minutes. Do not unplug the USB."))

	start := time.Now()
	runStep("Memory Capture", func() error {
		cmd := exec.Command(pmemPath, "acquire", "--progress", "--nosparse", outFile)
		cmd.Stdout = os.Stdout // show winpmem's progress live
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})
	end := time.Now()

	// Verify
	info, err := os.Stat(outFile)
	if err != nil || info.Size() == 0 {
		fmt.Println(color(red, "No memory image was written. Check whether EDR/AV blocked WinPmem."))
		return
	}

	size := uint64(info.Size())
	if float64(size) < float64(ram)*0.9 {
		fmt.Println(color(yellow, fmt.Sprintf(
			"Warning: image is %.1f GB but RAM is %.1f GB - capture may be incomplete.", gb(size), gb(ram))))
	}

	// Hash + document
	imageHash := "FAILED"
	runStep("Memory Image Hash", func() error {
		h, err := hashFile(outFile)
		if err != nil {
			return err
		}
		imageHash = h
		return nil
	})

	toolHash, err := hashFile(pmemPath)
	if err != nil {
		toolHash = "ERROR: " + err.Error()
	}
	toolVersion, err := fileVersion(pmemPath)
	if err != nil {
		toolVersion = "unknown"
	}

	duration := end.Sub(start)

	lines := []string{
		"Host          : " + host,
		"Image         : " + outFile,
		fmt.Sprintf("Image Size    : %d bytes (%.2f GB)", size, gb(size)),
		"Image SHA256  : " + imageHash,
		fmt.Sprintf("RAM (OS)      : %d bytes (%.2f GB)", ram, gb(ram)),
		"Start (UTC)   : " + start.UTC().Format(time.RFC3339Nano),
		"End (UTC)     : " + end.UTC().Format(time.RFC3339Nano),
		fmt.Sprintf("Duration      : %.0f seconds", duration.Seconds()),
		"Tool          : " + pmemPath,
		"Tool Version  : " + toolVersion,
		"Tool SHA256   : " + toolHash,
		"Command       : " + winpmemExe + " acquire --progress --nosparse <image>",
	}
	if err := writeLines(infoFile, lines); err != nil {
		fmt.Println(color(red, "Could not write "+infoFile+": "+err.Error()))
	}

	fmt.Println(color(green, fmt.Sprintf("Memory captured: %.1f GB in %.0fs", gb(size), duration.Seconds())))
	fmt.Println("Details saved to " + infoFile)
}

// Output helpers (CSV and text files from Go structs)

// writeCSV writes a slice of structs to a CSV file, using the field names as the header row.
func writeCSV[T any](path string, rows []T) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM so Excel detects the encoding
	w := csv.NewWriter(f)
	w.UseCRLF = true

	t := reflect.TypeOf((*T)(nil)).Elem()
	header := make([]string, t.NumField())
	for i := range header {
		header[i] = t.Field(i).Name
	}
	w.Write(header)

	for _, row := range rows {
		v := reflect.ValueOf(row)
		record := make([]string, v.NumField())
		for i := range record {
			record[i] = formatValue(v.Field(i).Interface())
		}
		w.Write(record)
	}

	w.Flush()
	return w.Error()
}

// writeFields writes each struct as aligned "Field : value" lines.
func writeFields[T any](path string, items []T) error {
	var lines []string
	for _, item := range items {
		v := reflect.ValueOf(item)
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			lines = append(lines, fmt.Sprintf("%-32s: %s", t.Field(i).Name, formatValue(v.Field(i).Interface())))
		}
		lines = append(lines, "")
	}
	return writeLines(path, lines)
}

// formatValue turns one field into text for a CSV cell or a text line.
func formatValue(v any) string {
	switch x := v.(type) {
	case time.Time:
		if x.IsZero() {
			return ""
		}
		return x.UTC().Format(time.RFC3339)
	case []string:
		return strings.Join(x, " | ")
	default:
		return fmt.Sprint(x)
	}
}

// enumName looks up a number in a table of names, falling back to the number.
func enumName[K comparable](names map[K]string, value K) string {
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprint(value)
}

// WMI

// WMI namespaces used during collection.
const (
	nsCimv2    = `root\cimv2`
	nsStdCimv2 = `root\StandardCimv2`
	nsSMB      = `root\Microsoft\Windows\SMB`
	nsDefender = `root\Microsoft\Windows\Defender`
	nsSub      = `root\subscription`
)

// queryWMI runs "SELECT <struct fields> FROM <class>" and fills dst.
// Field names in the struct must match the WMI property names exactly.
func queryWMI[T any](namespace, class string, dst *[]T) error {
	query := wmi.CreateQuery(dst, "", class)
	return wmi.QueryNamespace(query, dst, namespace)
}

// WMI result types. Field names must match WMI property names exactly.

type wmiProcess struct {
	ProcessId       uint32
	ParentProcessId uint32
	Name            string
	ExecutablePath  string
	CommandLine     string
	CreationDate    time.Time
}

type wmiTCP struct {
	LocalAddress  string
	LocalPort     uint16
	RemoteAddress string
	RemotePort    uint16
	State         uint8
	OwningProcess uint32
	CreationTime  time.Time
}

type wmiUDP struct {
	LocalAddress  string
	LocalPort     uint16
	OwningProcess uint32
	CreationTime  time.Time
}

type wmiDNSCache struct {
	Entry      string
	Name       string
	Type       uint16
	Status     uint32
	TimeToLive uint32
	Data       string
}

type wmiShare struct {
	Name         string
	Path         string
	Description  string
	CurrentUsers uint32
}

type wmiService struct {
	Name        string
	DisplayName string
	State       string
	StartMode   string
	PathName    string
	StartName   string
	ProcessId   uint32
}

type wmiStartupCommand struct {
	Name     string
	Command  string
	Location string
	User     string
}

type wmiCommandLineConsumer struct {
	Name                string
	CommandLineTemplate string
	ExecutablePath      string
}

type wmiScriptConsumer struct {
	Name            string
	ScriptingEngine string
	ScriptText      string
	ScriptFileName  string
}

type wmiEventFilter struct {
	Name           string
	Query          string
	QueryLanguage  string
	EventNamespace string
}

type wmiFilterBinding struct {
	Filter   string
	Consumer string
}

type wmiDefenderStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	AntispywareEnabled            bool
	RealTimeProtectionEnabled     bool
	OnAccessProtectionEnabled     bool
	BehaviorMonitorEnabled        bool
	IoavProtectionEnabled         bool
	NISEnabled                    bool
	IsTamperProtected             bool
	AMProductVersion              string
	AMEngineVersion               string
	AntivirusSignatureVersion     string
	AntivirusSignatureLastUpdated time.Time
	QuickScanEndTime              time.Time
	FullScanEndTime               time.Time
}

type wmiDefenderPrefs struct {
	ExclusionPath      []string
	ExclusionProcess   []string
	ExclusionExtension []string
	ExclusionIpAddress []string
}

type wmiFirewallProfile struct {
	Name                  string
	Enabled               uint16
	DefaultInboundAction  uint16
	DefaultOutboundAction uint16
	LogFileName           string
}

type wmiOS struct {
	CSName         string
	Caption        string
	Version        string
	BuildNumber    string
	OSArchitecture string
	InstallDate    time.Time
	LastBootUpTime time.Time
	RegisteredUser string
	SystemDrive    string
}

type wmiComputerSystem struct {
	Name                string
	Domain              string
	PartOfDomain        bool
	Manufacturer        string
	Model               string
	TotalPhysicalMemory uint64
	UserName            string
}

type wmiHotfix struct {
	HotFixID    string
	Description string
	InstalledOn string
	InstalledBy string
}

type wmiPartition struct {
	Name             string
	DiskIndex        uint32
	Type             string
	Size             uint64
	BootPartition    bool
	PrimaryPartition bool
}

type wmiVolume struct {
	DriveLetter string
	Label       string
	FileSystem  string
	DriveType   uint32
	Capacity    uint64
	FreeSpace   uint64
}

// Output row types, used where the CSV columns differ from the WMI result.

type processRow struct {
	ProcessId       uint32
	ParentProcessId uint32
	Name            string
	ExecutablePath  string
	CommandLine     string
	CreationDate    time.Time
	Owner           string
}

type tcpRow struct {
	LocalAddress  string
	LocalPort     uint16
	RemoteAddress string
	RemotePort    uint16
	State         string
	OwningProcess uint32
	ProcessName   string
	CreationTime  time.Time
}

type udpRow struct {
	LocalAddress  string
	LocalPort     uint16
	OwningProcess uint32
	ProcessName   string
	CreationTime  time.Time
}

type dnsRow struct {
	Entry      string
	Name       string
	Type       string
	Status     uint32
	TimeToLive uint32
	Data       string
}

type hashRow struct {
	Path   string
	SHA256 string
	Signed string
	Signer string
}

type consumerRow struct {
	Type                string
	Name                string
	CommandLineTemplate string
	ExecutablePath      string
	ScriptingEngine     string
	ScriptText          string
	ScriptFileName      string
}

type firewallRow struct {
	Name                  string
	Enabled               string
	DefaultInboundAction  string
	DefaultOutboundAction string
	LogFileName           string
}

type volumeRow struct {
	DriveLetter     string
	FileSystemLabel string
	FileSystem      string
	DriveType       string
	Size            uint64
	SizeRemaining   uint64
}

type localUserRow struct {
	Name            string
	Enabled         bool
	LastLogon       time.Time
	PasswordLastSet time.Time
	SID             string
	Description     string
}

// Lookup tables for WMI enum values.

var tcpStates = map[uint8]string{
	1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived", 5: "Established",
	6: "FinWait1", 7: "FinWait2", 8: "CloseWait", 9: "Closing", 10: "LastAck",
	11: "TimeWait", 12: "DeleteTCB", 100: "Bound",
}

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS",
}

var gpoBooleans = map[uint16]string{0: "False", 1: "True", 2: "NotConfigured"}

var firewallActions = map[uint16]string{0: "NotConfigured", 2: "Allow", 4: "Block"}

var driveTypes = map[uint32]string{
	0: "Unknown", 1: "NoRootDirectory", 2: "Removable", 3: "Fixed", 4: "Network", 5: "CD-ROM", 6: "RAMDisk",
}

// Process owners, signatures and local users

// processOwner returns DOMAIN\user for a process.
// cache stores resolved SIDs so each account is looked up only once.
func processOwner(pid uint32, cache map[string]string) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	sid := user.User.Sid.String()
	if name, ok := cache[sid]; ok {
		return name
	}
	name := sid
	if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
		name = domain + `\` + account
	}
	cache[sid] = name
	return name
}

// checkSignature returns sigcheck's verification status and publisher for a file.
// sigcheck validates both embedded and catalog signatures.
func checkSignature(sigcheck, path string) (verified, publisher string) {
	output, err := exec.Command(sigcheck, "-accepteula", "-nobanner", "-c", path).Output()
	if len(output) == 0 {
		if err != nil {
			return "ERROR: " + err.Error(), ""
		}
		return "unknown", ""
	}

	reader := csv.NewReader(strings.NewReader(decodeOutput(output)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return "unknown", ""
	}

	header, values := records[0], records[1]
	for i, column := range header {
		if i >= len(values) {
			break
		}
		switch column {
		case "Verified":
			verified = values[i]
		case "Publisher":
			publisher = values[i]
		}
	}
	return verified, publisher
}

// decodeOutput converts tool output to a string, handling UTF-16 output
// that some Windows tools produce when redirected.
func decodeOutput(b []byte) string {
	start := 0
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		start = 2 // UTF-16 with a byte order mark
	case len(b) >= 2 && b[1] == 0:
		// UTF-16 without a marker (ASCII text with a zero after every byte)
	default:
		return string(b) // already plain text
	}
	u := make([]uint16, (len(b)-start)/2)
	for i := range u {
		u[i] = uint16(b[start+2*i]) | uint16(b[start+2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// userInfo2 matches the USER_INFO_2 struct that NetUserEnum fills in.
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

// NetUserEnum constants.
const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
	ufAccountDisable    = 0x0002
)

// localUsers lists local accounts from the SAM.
func localUsers() ([]localUserRow, error) {
	var buf *byte
	var read, total, resume uint32
	if err := windows.NetUserEnum(nil, 2, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume); err != nil {
		return nil, err
	}
	defer windows.NetApiBufferFree(buf)

	now := time.Now()
	entries := unsafe.Slice((*userInfo2)(unsafe.Pointer(buf)), read)

	rows := make([]localUserRow, 0, len(entries))
	for _, u := range entries {
		row := localUserRow{
			Name:            windows.UTF16PtrToString(u.Name),
			Enabled:         u.Flags&ufAccountDisable == 0,
			PasswordLastSet: now.Add(-time.Duration(u.PasswordAge) * time.Second),
			Description:     windows.UTF16PtrToString(u.Comment),
		}
		if u.LastLogon != 0 {
			row.LastLogon = time.Unix(int64(u.LastLogon), 0)
		}
		if sid, _, _, err := windows.LookupSID("", row.Name); err == nil {
			row.SID = sid.String()
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Live response

// maxParallelSteps limits concurrent Live Response steps to keep load and noise
// on the target host low.
const maxParallelSteps = 4

// startLiveResponse collects volatile system artifacts into the LiveResponse folder,
// running independent steps in parallel.
func startLiveResponse(caseDir string) {
	outDir := filepath.Join(caseDir, "LiveResponse")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Println(color(red, "Could not create output folder: "+err.Error()))
		return
	}

	sectionHeader(blackOnYellow, "Live Response Started")

	// out returns a path inside the LiveResponse folder
	out := func(name string) string { return filepath.Join(outDir, name) }

	// Query processes once before the steps start; the network and process
	// steps share this list read-only.
	var procs []wmiProcess
	procErr := queryWMI(nsCimv2, "Win32_Process", &procs)
	procNames := make(map[uint32]string)
	for _, p := range procs {
		procNames[p.ProcessId] = p.Name
	}

	start := time.Now()
	steps := newStepRunner(maxParallelSteps)

	// Time
	steps.Go("System Time", func() error {
		now := time.Now()
		up := uptime()
		return writeLines(out("time.txt"), []string{
			"Local    : " + now.Format(time.RFC3339Nano),
			"UTC      : " + now.UTC().Format(time.RFC3339Nano),
			"TimeZone : " + timeZoneName(),
			"Uptime   : " + up.Round(time.Second).String(),
			"Boot UTC : " + now.Add(-up).UTC().Format(time.RFC3339),
		})
	})

	// Network
	steps.Go("TCP Connections", func() error {
		var conns []wmiTCP
		if err := queryWMI(nsStdCimv2, "MSFT_NetTCPConnection", &conns); err != nil {
			return err
		}
		rows := make([]tcpRow, 0, len(conns))
		for _, c := range conns {
			rows = append(rows, tcpRow{
				LocalAddress:  c.LocalAddress,
				LocalPort:     c.LocalPort,
				RemoteAddress: c.RemoteAddress,
				RemotePort:    c.RemotePort,
				State:         enumName(tcpStates, c.State),
				OwningProcess: c.OwningProcess,
				ProcessName:   procNames[c.OwningProcess],
				CreationTime:  c.CreationTime,
			})
		}
		return writeCSV(out("net_tcp.csv"), rows)
	})

	steps.Go("UDP Endpoints", func() error {
		var endpoints []wmiUDP
		if err := queryWMI(nsStdCimv2, "MSFT_NetUDPEndpoint", &endpoints); err != nil {
			return err
		}
		rows := make([]udpRow, 0, len(endpoints))
		for _, e := range endpoints {
			rows = append(rows, udpRow{
				LocalAddress:  e.LocalAddress,
				LocalPort:     e.LocalPort,
				OwningProcess: e.OwningProcess,
				ProcessName:   procNames[e.OwningProcess],
				CreationTime:  e.CreationTime,
			})
		}
		return writeCSV(out("net_udp.csv"), rows)
	})

	steps.Go("netstat", func() error { return runToFile(out("netstat.txt"), "netstat", "-anob") })

	steps.Go("DNS Cache", func() error {
		var entries []wmiDNSCache
		if err := queryWMI(nsStdCimv2, "MSFT_DNSClientCache", &entries); err != nil {
			return err
		}
		rows := make([]dnsRow, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, dnsRow{
				Entry:      e.Entry,
				Name:       e.Name,
				Type:       enumName(dnsTypes, e.Type),
				Status:     e.Status,
				TimeToLive: e.TimeToLive,
				Data:       e.Data,
			})
		}
		return writeCSV(out("dns_cache.csv"), rows)
	})

	steps.Go("ARP Table", func() error { return runToFile(out("arp.txt"), "arp", "-a") })
	steps.Go("Routes", func() error { return runToFile(out("routes.txt"), "route", "print") })
	steps.Go("ipconfig", func() error { return runToFile(out("ipconfig.txt"), "ipconfig", "/all") })

	// Processes
	steps.Go("Processes", func() error {
		if procErr != nil {
			return procErr
		}
		owners := make(map[string]string)
		rows := make([]processRow, 0, len(procs))
		for _, p := range procs {
			rows = append(rows, processRow{
				ProcessId:       p.ProcessId,
				ParentProcessId: p.ParentProcessId,
				Name:            p.Name,
				ExecutablePath:  p.ExecutablePath,
				CommandLine:     p.CommandLine,
				CreationDate:    p.CreationDate,
				Owner:           processOwner(p.ProcessId, owners),
			})
		}
		return writeCSV(out("processes.csv"), rows)
	})

	steps.Go("Process Hashes", func() error {
		if procErr != nil {
			return procErr
		}
		sigcheck, sigErr := exec.LookPath("sigcheck64.exe")

		seen := make(map[string]bool)
		var rows []hashRow
		for _, p := range procs {
			key := strings.ToLower(p.ExecutablePath)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true

			row := hashRow{Path: p.ExecutablePath}
			if h, err := hashFile(p.ExecutablePath); err == nil {
				row.SHA256 = h
			} else {
				row.SHA256 = "ERROR: " + err.Error()
			}
			if sigErr != nil {
				row.Signed = "sigcheck64.exe not found"
			} else {
				row.Signed, row.Signer = checkSignature(sigcheck, p.ExecutablePath)
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
		return writeCSV(out("process_hashes.csv"), rows)
	})

	// Users & Sessions
	steps.Go("Logged On Users", func() error { return runToFile(out("logged_on_users.txt"), "query", "user") })

	steps.Go("Local Users", func() error {
		rows, err := localUsers()
		if err != nil {
			return err
		}
		return writeCSV(out("local_users.csv"), rows)
	})

	steps.Go("Local Admins", func() error {
		return runToFile(out("local_admins.txt"), "net", "localgroup", "administrators")
	})
	steps.Go("SMB Sessions", func() error { return runToFile(out("net_sessions.txt"), "net", "session") })
	steps.Go("Mapped Drives", func() error { return runToFile(out("net_use.txt"), "net", "use") })

	steps.Go("Shares", func() error {
		var shares []wmiShare
		if err := queryWMI(nsSMB, "MSFT_SmbShare", &shares); err != nil {
			return err
		}
		return writeCSV(out("shares.csv"), shares)
	})

	// Persistence
	steps.Go("Services", func() error {
		var services []wmiService
		if err := queryWMI(nsCimv2, "Win32_Service", &services); err != nil {
			return err
		}
		return writeCSV(out("services.csv"), services)
	})

	steps.Go("Scheduled Tasks", func() error {
		return runToFile(out("scheduled_tasks.csv"), "schtasks", "/query", "/fo", "csv", "/v")
	})

	steps.Go("Startup Commands", func() error {
		var cmds []wmiStartupCommand
		if err := queryWMI(nsCimv2, "Win32_StartupCommand", &cmds); err != nil {
			return err
		}
		return writeCSV(out("startup_commands.csv"), cmds)
	})

	steps.Go("WMI Persistence", func() error {
		var cmdConsumers []wmiCommandLineConsumer
		if err := queryWMI(nsSub, "CommandLineEventConsumer", &cmdConsumers); err != nil {
			return err
		}
		var scriptConsumers []wmiScriptConsumer
		if err := queryWMI(nsSub, "ActiveScriptEventConsumer", &scriptConsumers); err != nil {
			return err
		}

		var rows []consumerRow
		for _, c := range cmdConsumers {
			rows = append(rows, consumerRow{
				Type:                "CommandLineEventConsumer",
				Name:                c.Name,
				CommandLineTemplate: c.CommandLineTemplate,
				ExecutablePath:      c.ExecutablePath,
			})
		}
		for _, c := range scriptConsumers {
			rows = append(rows, consumerRow{
				Type:            "ActiveScriptEventConsumer",
				Name:            c.Name,
				ScriptingEngine: c.ScriptingEngine,
				ScriptText:      c.ScriptText,
				ScriptFileName:  c.ScriptFileName,
			})
		}
		if err := writeCSV(out("wmi_consumers.csv"), rows); err != nil {
			return err
		}

		// Filters and bindings show what triggers each consumer
		var filters []wmiEventFilter
		if err := queryWMI(nsSub, "__EventFilter", &filters); err != nil {
			return err
		}
		if err := writeCSV(out("wmi_filters.csv"), filters); err != nil {
			return err
		}
		var bindings []wmiFilterBinding
		if err := queryWMI(nsSub, "__FilterToConsumerBinding", &bindings); err != nil {
			return err
		}
		return writeCSV(out("wmi_bindings.csv"), bindings)
	})

	if autoruns, err := exec.LookPath("autorunsc64.exe"); err == nil {
		steps.Go("Autoruns", func() error {
			return runToFile(out("autoruns.csv"), autoruns,
				"-accepteula", "-nobanner", "-a", "*", "-c", "-h", "-s", "*")
		})
	} else {
		say(color(yellow, "autorunsc64.exe not found - skipping Autoruns"))
	}

	// Security posture
	steps.Go("BitLocker Status", func() error { return runToFile(out("bitlocker.txt"), "manage-bde", "-status") })

	steps.Go("Defender Status", func() error {
		var status []wmiDefenderStatus
		if err := queryWMI(nsDefender, "MSFT_MpComputerStatus", &status); err != nil {
			return err
		}
		return writeFields(out("defender_status.txt"), status)
	})

	steps.Go("Defender Exclusions", func() error {
		var prefs []wmiDefenderPrefs
		if err := queryWMI(nsDefender, "MSFT_MpPreference", &prefs); err != nil {
			return err
		}
		return writeFields(out("defender_exclusions.txt"), prefs)
	})

	steps.Go("Firewall Profiles", func() error {
		var profiles []wmiFirewallProfile
		if err := queryWMI(nsStdCimv2, "MSFT_NetFirewallProfile", &profiles); err != nil {
			return err
		}
		rows := make([]firewallRow, 0, len(profiles))
		for _, p := range profiles {
			rows = append(rows, firewallRow{
				Name:                  p.Name,
				Enabled:               enumName(gpoBooleans, p.Enabled),
				DefaultInboundAction:  enumName(firewallActions, p.DefaultInboundAction),
				DefaultOutboundAction: enumName(firewallActions, p.DefaultOutboundAction),
				LogFileName:           p.LogFileName,
			})
		}
		return writeCSV(out("firewall_profiles.csv"), rows)
	})

	// System info
	steps.Go("Operating System", func() error {
		var osInfo []wmiOS
		if err := queryWMI(nsCimv2, "Win32_OperatingSystem", &osInfo); err != nil {
			return err
		}
		return writeCSV(out("OS.csv"), osInfo)
	})

	steps.Go("Computer System", func() error {
		var cs []wmiComputerSystem
		if err := queryWMI(nsCimv2, "Win32_ComputerSystem", &cs); err != nil {
			return err
		}
		return writeCSV(out("computer_system.csv"), cs)
	})

	steps.Go("Hotfixes", func() error {
		var fixes []wmiHotfix
		if err := queryWMI(nsCimv2, "Win32_QuickFixEngineering", &fixes); err != nil {
			return err
		}
		return writeCSV(out("hotfixes.csv"), fixes)
	})

	steps.Go("Disk Partitions", func() error {
		var parts []wmiPartition
		if err := queryWMI(nsCimv2, "Win32_DiskPartition", &parts); err != nil {
			return err
		}
		return writeCSV(out("disk_partitions.csv"), parts)
	})

	steps.Go("Volumes", func() error {
		var vols []wmiVolume
		if err := queryWMI(nsCimv2, "Win32_Volume", &vols); err != nil {
			return err
		}
		rows := make([]volumeRow, 0, len(vols))
		for _, v := range vols {
			rows = append(rows, volumeRow{
				DriveLetter:     v.DriveLetter,
				FileSystemLabel: v.Label,
				FileSystem:      v.FileSystem,
				DriveType:       enumName(driveTypes, v.DriveType),
				Size:            v.Capacity,
				SizeRemaining:   v.FreeSpace,
			})
		}
		return writeCSV(out("volumes.csv"), rows)
	})

	steps.Go("Environment Variables", func() error {
		env := os.Environ()
		sort.Strings(env)
		return writeLines(out("env_vars.txt"), env)
	})

	steps.Wait() // wait for all steps to finish

	sectionHeader(blackOnGreen, "Live Response Complete")
	fmt.Printf("Finished in %s\n", time.Since(start).Round(time.Second))
}

// Main

// main sets up paths, shows the banner and starts the menu.
func main() {
	enableColors()

	scriptRoot, err := getScriptRoot()
	if err != nil {
		log.Fatal(err)
	}

	// Only the error is needed; tools are resolved through PATH.
	if _, err := addToolsToPath(scriptRoot); err != nil {
		log.Fatal(err)
	}

	caseDir := buildCaseDir(scriptRoot)

	showBanner()
	runMenu(caseDir)
}
