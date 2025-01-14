# **Contributing to Caddy Defender**

Welcome! If you want to add new responders or IP ranges to block, you're in the right place. This guide will walk you through the process.

---
## **Adding New IP Ranges to Block**

To add new IP ranges, you need to create a new fetcher in the `ranges/fetchers` package. Here's how:

---

### **1. Create a New IP Fetcher**

1. **Create a New File**:
   Create a new file in the `ranges/fetchers` directory, e.g., `my_service.go`.

2. **Implement the Fetcher**:
   Your fetcher must implement the `IPRangeFetcher` interface:
   ```go
   package fetchers

   // MyServiceFetcher implements the IPRangeFetcher interface for MyService.
   type MyServiceFetcher struct{}

   func (f MyServiceFetcher) Name() string {
       return "MyService"
   }

   func (f MyServiceFetcher) Description() string {
       return "Fetches IP ranges for MyService."
   }

   func (f MyServiceFetcher) FetchIPRanges() ([]string, error) {
       // Hardcoded IP ranges for MyService
       return []string{
           "203.0.113.0/24",
           "198.51.100.0/24",
       }, nil
   }
   ```

   If your service provides an API to fetch IP ranges dynamically, you can use HTTP requests and JSON parsing (like in `OpenAIFetcher`).

---

### **2. Add the Fetcher to the List**

Update the `fetchersList` in `ranges/main.go` to include your new fetcher:

```go
func main() {
	// Define flags
	flag.StringVar(&outputFormat, "format", "json", "Output format: json or go")
	flag.StringVar(&outputFile, "output", "output.json", "Output file path")
	flag.Parse()

	// Create an array of all IP range fetchers
	fetchersList := []fetchers.IPRangeFetcher{
		fetchers.OpenAIFetcher{},
		fetchers.DeepSeekFetcher{},
		fetchers.GithubCopilotFetcher{},
		fetchers.MyServiceFetcher{}, // Add your new fetcher here
	}

	// Rest of the code...
}
```

---

### **3. Rebuild the Plugin**

Rebuild the plugin using `xcaddy` to include your new fetcher:

```bash
xcaddy build --with github.com/jasonlovesdoggo/caddy-defender
```

---

### **4. Test the Changes**

Run Caddy with your updated configuration and verify that the new IP ranges are blocked or manipulated as expected.

---

## **Dynamic IP Range Fetching**

If your service provides an API to fetch IP ranges dynamically, you can use HTTP requests and JSON parsing (like in `OpenAIFetcher`). Here’s an example:

```go
package fetchers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// MyServiceFetcher implements the IPRangeFetcher interface for MyService.
type MyServiceFetcher struct{}

func (f MyServiceFetcher) Name() string {
	return "MyService"
}

func (f MyServiceFetcher) Description() string {
	return "Fetches IP ranges for MyService."
}

func (f MyServiceFetcher) FetchIPRanges() ([]string, error) {
	// Fetch IP ranges from an API
	url := "https://api.myservice.com/ip-ranges"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP ranges from %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %v", url, err)
	}

	var ipRanges struct {
		Prefixes []string `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON from %s: %v", url, err)
	}

	return ipRanges.Prefixes, nil
}
```

---

## **Adding New Responders**

Responders are responsible for handling requests that match the specified IP ranges. To add a new responder:

1. **Create a New Responder File**:
   Create a new file in the `caddy-plugin/responders` directory, e.g., `my_responder.go`.

2. **Implement the Responder Interface**:
   Your responder must implement the `Responder` interface:
   ```go
   package responders

   import "net/http"

   type MyResponder struct {
       // Add any fields you need here
   }

   func (m MyResponder) Respond(w http.ResponseWriter, r *http.Request) error {
       // Implement your custom response logic here
       w.WriteHeader(http.StatusOK)
       _, err := w.Write([]byte("This is my custom responder!"))
       return err
   }
   ```

3. **Register the Responder**:
   Update the `UnmarshalCaddyfile` method in `caddy-plugin/plugin.go` to support your new responder:
   ```go
   func (m *DefenderMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
       for d.Next() {
           for d.NextArg() {
               m.AdditionalRanges = append(m.AdditionalRanges, d.Val())
           }

           if d.NextArg() {
               switch d.Val() {
               case "block":
                   m.Responder = responders.BlockResponder{}
               case "garbage":
                   m.Responder = responders.GarbageResponder{}
               case "custom":
                   if !d.NextArg() {
                       return d.ArgErr()
                   }
                   m.Responder = responders.CustomResponder{Message: d.Val()}
               case "my_responder": // Add your new responder here
                   m.Responder = responders.MyResponder{}
               default:
                   return d.Errf("unknown responder: %s", d.Val())
               }
           }
       }
       return nil
   }
   ```

4. **Test Your Responder**:
   Add tests for your responder in a `_test.go` file and run them:
   ```bash
   go test ./...
   ```

5. **Update the Caddyfile Documentation**:
   Add your new responder to the `README.md` and `docs/index.md` so users know how to use it.
