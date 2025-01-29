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

---

## **Installation**

### **Using Docker**

The easiest way to use the Caddy Defender plugin is by using the pre-built Docker image.

1. **Pull the Docker Image**:
   ```bash
   docker pull ghcr.io/jasonlovesdoggo/caddy-defender:latest
   ```

2. **Run the Container**:
   Use the following command to run the container with your `Caddyfile`:
   ```bash
   docker run -d \
     --name caddy \
     -v /path/to/Caddyfile:/etc/caddy/Caddyfile \
     -p 80:80 -p 443:443 \
     ghcr.io/jasonlovesdoggo/caddy-defender:latest
   ```

   Replace `/path/to/Caddyfile` with the path to your `Caddyfile`.
---

### **Using `xcaddy`**

You can also build Caddy with the Caddy Defender plugin using [`xcaddy`](https://github.com/caddyserver/xcaddy), a tool for building custom Caddy binaries.

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

## **Configuration**

### **Caddyfile Syntax**

The `defender` directive is used to configure the Caddy Defender plugin. It has the following syntax:

```caddyfile
defender <responder> {
    message <custom message>
    ranges <ip_ranges...>
}
```

- `<responder>`: The responder backend to use. Supported values are:
  - `block`: Returns a `403 Forbidden` response.
  - `garbage`: Returns garbage data to pollute AI training.
  - `custom`: Returns a custom message (requires `responder_args`).
  - `ratelimit`: Marks requests for rate limiting (requires [Caddy-Ratelimit](https://github.com/mholt/caddy-ratelimit) to be installed as well ).
- `<ip_ranges...>`: An optional list of CIDR ranges or predefined range keys to match against the client's IP. Defaults to `aws azurepubliccloud deepseek gcloud githubcopilot openai private`.
- `<custom message>`: A custom message to return when using the `custom` responder.
---


## For examples, check out [docs/examples.md](docs/examples.md)

---

## **Embedded IP Ranges**

The plugin includes predefined IP ranges for popular AI services. These ranges are embedded in the binary and can be used without additional configuration.

|                               Service                                |                     Key                     |                     IP Ranges                      |
|:--------------------------------------------------------------------:|:-------------------------------------------:|:--------------------------------------------------:|
|                                 AWS                                  |                     aws                     |        [aws.go](ranges/fetchers/aws/aws.go)        |
|                              AWS Region                              | aws-us-east-1, aws-us-west-1, aws-eu-west-1 | [aws_region.go](ranges/fetchers/aws/aws_region.go) |
|                               DeepSeek                               |                  deepseek                   |     [deepseek.go](ranges/fetchers/deepseek.go)     |
|                            GitHub Copilot                            |                githubcopilot                |       [github.go](ranges/fetchers/github.go)       |
|                        Google Cloud Platform                         |                   gcloud                    |       [gcloud.go](ranges/fetchers/gcloud.go)       |
|                           Microsoft Azure                            |              azurepubliccloud               |        [azure.go](ranges/fetchers/azure.go)        |
|                                OpenAI                                |                   openai                    |       [openai.go](ranges/fetchers/openai.go)       |
| [Private](https://caddyserver.com/docs/caddyfile/matchers#remote-ip) |                   private                   |      [private.go](ranges/fetchers/private.go)      |

More are welcome! for a precompiled list, see the [embedded results](ranges/data/generated.go)

## **Contributing**

We welcome contributions! To get started, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## **License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## **Acknowledgments**
- [The inspiration for this project](https://www.reddit.com/r/selfhosted/comments/1i154h7/comment/m73pj9t/).
- [bart](https://github.com/gaissmai/bart) - [Karl Gaissmaier](https://github.com/gaissmai)'s efficient routing table implementation (Balanced ART adaptation) enabling our high-performance IP matching
- Built with ❤️ using [Caddy](https://caddyserver.com).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=JasonLovesDoggo/caddy-defender&type=Date)](https://star-history.com/#JasonLovesDoggo/caddy-defender&Date)
