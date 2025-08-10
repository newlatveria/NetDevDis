package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os" // Import os to check for command-line arguments
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DeviceFacts struct to hold information about a discovered device
type DeviceFacts struct {
	IPAddress    string   `json:"ip_address"`
	Hostname     string   `json:"hostname,omitempty"`
	IsReachable  bool     `json:"is_reachable"`
	OpenPorts    []int    `json:"open_ports,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
}

// PageData struct to pass data to the HTML template
type PageData struct {
	CIDR    string
	Devices []DeviceFacts // Changed from template.HTML to hold structured data
	Error   string
}

// Common ports to scan
var commonPorts = []int{22, 80, 443, 23, 21, 25, 110, 135, 139, 445, 3389, 8080}

// parseCIDR parses a CIDR string and returns all IP addresses in the range
func parseCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []net.IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, copyIP(ip))
	}
	// Remove network and broadcast addresses if they are included
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil // Exclude network and broadcast for typical host scanning
	}
	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// copyIP creates a copy of an IP address
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// pingHost pings a single host and returns true if reachable
func pingHost(ip string) bool {
	// Using system ping command for simplicity. For a more robust solution,
	// consider using a Go-native ICMP library (e.g., github.com/go-ping/ping)
	// which doesn't require elevated privileges on all systems.
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip) // -c 1: 1 packet, -W 1: 1 second timeout
	err := cmd.Run()
	return err == nil
}

// scanPort attempts to connect to a specific port on an IP address
func scanPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// resolveHostname resolves the hostname for a given IP address
func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Return the first resolved hostname, removing trailing dot if present
	return strings.TrimSuffix(names[0], ".")
}

// getLocalIP attempts to determine the local non-loopback IP address
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Connect to a public DNS server (doesn't send data)
	if err != nil {
		return "", fmt.Errorf("could not dial UDP for IP detection: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}


// indexTemplate is the HTML template for the web interface
const indexTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6;
        }
        .container {
            max-width: 960px; /* Increased max-width for better table display */
        }
        pre {
            white-space: pre-wrap; /* Ensures long lines wrap */
            word-wrap: break-word; /* Breaks long words */
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0; /* Tailwind gray-200 */
        }
        th {
            background-color: #edf2f7; /* Tailwind gray-100 */
            font-weight: 600;
            color: #4a5568; /* Tailwind gray-700 */
        }
        tr:hover {
            background-color: #f7fafc; /* Tailwind gray-50 */
        }
        .reachable-true {
            color: #10b981; /* Tailwind green-500 */
            font-weight: 600;
        }
        .reachable-false {
            color: #ef4444; /* Tailwind red-500 */
            font-weight: 600;
        }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen p-4">
    <div class="container bg-white shadow-lg rounded-xl p-8 space-y-6 w-full">
        <h1 class="text-3xl font-bold text-center text-gray-800 mb-6">Go Network Scanner</h1>

        <form action="/scan" method="POST" class="flex flex-col sm:flex-row gap-4">
            <input type="text" name="cidr" placeholder="Enter CIDR range (e.g., 192.168.1.0/24)"
                   value="{{.CIDR}}"
                   class="flex-grow p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ease-in-out shadow-sm"
                   required>
            <button type="submit"
                    class="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-75">
                Scan Network
            </button>
        </form>

        {{if .Error}}
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative" role="alert">
                <strong class="font-bold">Error:</strong>
                <span class="block sm:inline">{{.Error}}</span>
            </div>
        {{end}}

        {{if .Devices}}
            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200 shadow-inner overflow-x-auto">
                <h2 class="text-xl font-semibold text-gray-700 mb-4">Scan Results:</h2>
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-100">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider rounded-tl-lg">IP Address</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hostname</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reachable</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider rounded-tr-lg">Open Ports</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {{range .Devices}}
                        {{$currentDevice := .}} {{/* Capture the current DeviceFacts into a new variable */}}
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{.IPAddress}}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{{if .Hostname}}{{.Hostname}}{{else}}N/A{{end}}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm {{if .IsReachable}}reachable-true{{else}}reachable-false{{end}}">
                                {{if .IsReachable}}Yes{{else}}No{{end}}
                                {{if not .IsReachable}}<span class="text-xs text-gray-500"> ({{.ErrorMessage}})</span>{{end}}
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                                {{if .OpenPorts}}
                                    {{range $i, $port := .OpenPorts}}
                                        {{$port}}{{if ne (len $currentDevice.OpenPorts) (add $i 1)}}, {{end}} {{/* Use $currentDevice.OpenPorts */}}
                                    {{end}}
                                {{else}}
                                    None
                                {{end}}
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        {{else if .CIDR}}
            <div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded-lg relative" role="alert">
                <strong class="font-bold">Scanning...</strong> Please wait.
            </div>
        {{end}}
    </div>
</body>
</html>
`

// homeHandler serves the initial HTML form
func homeHandler(w http.ResponseWriter, r *http.Request, defaultCIDR string) { // Added defaultCIDR parameter
	// Create a new template with a custom function for addition (used in template for comma separation)
	tmpl := template.New("index").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	})
	_, err := tmpl.Parse(indexTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}
	tmpl.Execute(w, PageData{CIDR: defaultCIDR}) // Render with default CIDR
}

// scanHandler processes the CIDR range and performs the scan
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// If it's not a POST request (e.g., a GET request from direct navigation or refresh),
		// redirect to the home page.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	cidr := r.FormValue("cidr")
	if cidr == "" {
		renderPage(w, PageData{Error: "CIDR range cannot be empty"})
		return
	}

	ips, err := parseCIDR(cidr)
	if err != nil {
		renderPage(w, PageData{CIDR: cidr, Error: fmt.Sprintf("Error parsing CIDR: %v", err)})
		return
	}

	log.Printf("Scanning %d potential hosts in %s...\n", len(ips), cidr)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex // Mutex to protect access to discoveredDevices
		allDevices []DeviceFacts // Renamed to avoid confusion with filtered list
	)

	maxGoroutines := 20
	guard := make(chan struct{}, maxGoroutines)

	for _, ip := range ips {
		guard <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-guard }()

			ipStr := ip.String()
			// log.Printf("Processing %s...\n", ipStr) // Too verbose for web output

			device := DeviceFacts{
				IPAddress:   ipStr,
				IsReachable: false,
			}

			if pingHost(ipStr) {
				device.IsReachable = true
				hostname := resolveHostname(ipStr)
				if hostname != "" {
					device.Hostname = hostname
				}

				var openPorts []int
				var portWg sync.WaitGroup
				portScanTimeout := 500 * time.Millisecond

				for _, port := range commonPorts {
					portWg.Add(1)
					go func(p int) {
						defer portWg.Done()
						if scanPort(ipStr, p, portScanTimeout) {
							openPorts = append(openPorts, p)
						}
					}(port)
				}
				portWg.Wait()

				if len(openPorts) > 0 {
					for i := 0; i < len(openPorts)-1; i++ {
						for j := 0; j < len(openPorts)-i-1; j++ {
							if openPorts[j] > openPorts[j+1] {
								openPorts[j], openPorts[j+1] = openPorts[j+1], openPorts[j]
							}
						}
					}
					device.OpenPorts = openPorts
				}
			} else {
				device.ErrorMessage = "Host not reachable (ping failed)"
			}

			mu.Lock()
			allDevices = append(allDevices, device) // Append to allDevices
			mu.Unlock()

		}(ip)
	}

	wg.Wait()

	// Filter to include only reachable devices
	var reachableDevices []DeviceFacts
	for _, dev := range allDevices {
		if dev.IsReachable {
			reachableDevices = append(reachableDevices, dev)
		}
	}

	renderPage(w, PageData{
		CIDR:    cidr,
		Devices: reachableDevices, // Pass the filtered slice of DeviceFacts
	})
}

// renderPage is a helper to parse and execute the template
func renderPage(w http.ResponseWriter, data PageData) {
	// Create a new template with a custom function for addition (used in template for comma separation)
	tmpl := template.New("index").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	})
	_, err := tmpl.Parse(indexTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return // Crucial: return after sending an error
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Template execution error: %v", err)
		// Only send HTTP error if it hasn't been sent already (e.g., by tmpl.Execute itself)
		// This check is a bit tricky, but generally, if Execute fails, it might have
		// already written something, or the header might be sent.
		// For simplicity, we'll just log here and assume Execute might have partially written.
		// A more robust solution might involve buffering the response.
		// For now, removing http.Error here to avoid the "superfluous" warning.
	}
}

func main() {
	// Check if ping command is available
	_, err := exec.LookPath("ping")
	if err != nil {
		log.Fatalf("Error: 'ping' command not found in PATH. This tool relies on the system ping utility. Please ensure it's installed and accessible.")
	}

	log.Println("Starting web server on :8080")

	// Determine the CIDR range to use. Prioritize command-line argument, then default.
	var defaultCIDR string
	if len(os.Args) > 1 {
		defaultCIDR = os.Args[1] // Use command-line argument if provided
	} else {
		// Attempt to get local IP and construct CIDR
		localIP, err := getLocalIP()
		if err != nil {
			log.Printf("Warning: Could not determine local IP for default CIDR. Using fallback 192.168.1.0/24. Error: %v", err)
			defaultCIDR = "192.168.1.0/24" // Fallback if local IP detection fails
		} else {
			// Extract network part (e.g., 192.168.1) and append .0/24
			ipParts := strings.Split(localIP, ".")
			if len(ipParts) >= 3 {
				defaultCIDR = fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
				log.Printf("Determined local IP: %s, setting default CIDR to: %s", localIP, defaultCIDR)
			} else {
				log.Printf("Warning: Could not parse local IP %s for default CIDR. Using fallback 192.168.1.0/24.", localIP)
				defaultCIDR = "192.168.1.0/24" // Fallback if IP parsing fails
			}
		}
	}

	// Pass the defaultCIDR to the homeHandler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		homeHandler(w, r, defaultCIDR)
	})
	http.HandleFunc("/scan", scanHandler)

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
