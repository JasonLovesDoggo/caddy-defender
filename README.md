## **Caddy Defender Plugin**

The **Caddy Defender** plugin is a middleware for Caddy that allows you to block or manipulate requests based on the client's IP address. It is particularly useful for preventing unwanted traffic or polluting AI training data by returning garbage responses.

---

## **Features**

- **IP Range Filtering**: Block or manipulate requests from specific IP ranges.
- **Embedded IP Ranges**: Predefined IP ranges for popular AI services (e.g., OpenAI, DeepSeek, GitHub Copilot).
- **Custom IP Ranges**: Add your own IP ranges via Caddyfile configuration.
- **Multiple Responder Backends**:
  - **Block**: Return a `403 Forbidden` response.
  - **Garbage**: Return garbage data to pollute AI training.
  - **Custom**: Return a custom message.
  - **File**: Return a file with specified headers.

---

## **Installation**

### **Using `xcaddy`**

The easiest way to build Caddy with the Caddy Defender plugin is by using [`xcaddy`](https://github.com/caddyserver/xcaddy), a tool for building custom Caddy binaries.

1. **Install `xcaddy`**:
   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   ```

2. **Build Caddy with the Plugin**:
   Run the following command to build Caddy with the Caddy Defender plugin:
   ```bash
   xcaddy build --with github.com/jasonlovesdoggo/caddy-defender
   ```

   This will produce a `caddy` binary in the current directory.

3. **Run Caddy**:
   Use the built binary to run Caddy with your configuration:
   ```bash
   ./caddy run --config Caddyfile
   ```

---

### **Manual Build**

If you prefer to build the plugin manually:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/jasonlovesdoggo/caddy-defender.git
   cd caddy-defender
   ```

2. **Build the Plugin**:
   ```bash
   go build -o caddy-defender
   ```

3. **Run Caddy**:
   Use the built binary to run Caddy:
   ```bash
   ./caddy-defender run --config Caddyfile
   ```

---

## **Configuration**

### **Caddyfile Syntax**

```caddyfile
defender <responder> [responder_args...] <ip_ranges...>
```

- `<ip_ranges...>`: A list of CIDR ranges to match against the client's IP.
- `<responder>`: The responder backend to use (`block`, `garbage`, `custom`, or `file`).
- `[responder_args...]`: Additional arguments for the responder backend (e.g., a custom message for the `custom` responder, file path and headers for the `file` responder).

---

### **Examples**

#### **Block Requests**
Block requests from specific IP ranges:
```caddyfile
{
    order defender before basicauth
}
localhost:8080 {
    defender block {
        range 203.0.113.0/24 openai 198.51.100.0/24 
    } 
    respond "Hello, world!" # what humans see
}
```

#### **Return Garbage Data**
Return garbage data for requests from specific IP ranges:
```caddyfile
{
    order defender before basicauth
}
localhost:8081 {
    defender garbage {
        range 192.168.0.0/24 
    }
    respond "Hello, world!" # what humans see
}
```

#### **Custom Response**
Return a custom message for requests from specific IP ranges:
```caddyfile
{
    order defender before basicauth
}
localhost:8082 {
    defender custom "Custom response message" {
        range 10.0.0.0/8
    } 
    respond "Hello, world!" # what humans see
} 
```

#### **File Response**
Return a file with specified headers for requests from specific IP ranges:
```caddyfile
{
    order defender before basicauth
}
localhost:8083 {
    defender file "/path/to/file.txt" {
        header Content-Type text/plain
        header Content-Encoding gzip
        range 203.0.113.0/24
    }
    respond "Hello, world!" # what humans see
}
```

---

## **Embedded IP Ranges**

The plugin includes predefined IP ranges for popular AI services. These ranges are embedded in the binary and can be used without additional configuration.

| Service         | IP Ranges                                  |
|-----------------|--------------------------------------------|
| OpenAI          | [openai.go](ranges/fetchers/openai.go)     |
| DeepSeek        | [deepseek.go](ranges/fetchers/deepseek.go) |
| GitHub Copilot  | [github.go](ranges/fetchers/github.go)     |

More are welcome! for a precompiled list, see the [embedded results](ranges/data/generated.go)

## **Contributing**

We welcome contributions! Here’s how you can get started:

### Adding New IP Ranges
To add new IP ranges, you need to create a new fetcher in the `ranges/fetchers` package. Follow the steps in the [Contributing Guide](CONTRIBUTING.md).

### Adding a New Responder

To add a new responder, you need to create a new responder in the `responders` package and update the `UnmarshalCaddyfile` method in the `DefenderMiddleware` struct to handle the new responder. Follow the steps in the [Contributing Guide](CONTRIBUTING.md).

---

## **License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## **Acknowledgments**

- [The inspiration for this project](https://www.reddit.com/r/selfhosted/comments/1i154h7/comment/m73pj9t/).
- Built with ❤️ using [Caddy](https://caddyserver.com).

---

Let me know if you need further assistance! 😊
