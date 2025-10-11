## **Caddy Defender Plugin**

The **Caddy Defender** plugin is a middleware for Caddy that allows you to block or manipulate requests based on the client's IP address. It is particularly useful for preventing unwanted traffic or polluting AI training data by returning garbage responses.

---

## **Features**

- **IP Range Filtering**: Block or manipulate requests from specific IP ranges.
- **Embedded IP Ranges**: Predefined IP ranges for popular AI services (e.g., OpenAI, DeepSeek, GitHub Copilot).
- **Custom IP Ranges**: Add your own IP ranges via Caddyfile configuration.
- **File-Based Blocklists**: Load IP addresses from a file with automatic reload on changes (perfect for Docker volume mounts).
- **Admin API**: Dynamically manage blocklists via RESTful API endpoints without restarting Caddy.
- **Multiple Responder Backends**:
  - **Block**: Return a `403 Forbidden` response.
  - **Custom**: Return a custom message.
  - **Drop**: Drops the connection.
  - **Garbage**: Return garbage data to pollute AI training.
  - **Redirect**: Return a `308 Permanent Redirect` response with a custom URL.
  - **Ratelimit**: Ratelimit requests, configurable via [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit).
  - **Tarpit**: Stream data at a slow, but configurable rate to stall bots and pollute AI training.

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

Please see the [online documentation](https://JasonLovesDoggo.github.io/caddy-defender/installation/) for other methods of installation.

---

## **Configuration**

### **Caddyfile Syntax**

The `defender` directive is used to configure the Caddy Defender plugin. It has the following syntax:

```caddyfile
defender <responder> {
    message <custom message>
    ranges <ip_ranges...>
    url <url>
    blocklist_file <path>
}
```

- `<responder>`: The responder backend to use. Supported values are:
  - `block`: Returns a `403 Forbidden` response.
  - `custom`: Returns a custom message (requires `message`).
  - `drop`: Drops the connection.
  - `garbage`: Returns garbage data to pollute AI training.
  - `redirect`: Returns a `308 Permanent Redirect` response (requires `url`).
  - `ratelimit`: Marks requests for rate limiting (requires [Caddy-Ratelimit](https://github.com/mholt/caddy-ratelimit) to be installed as well ).
  - `tarpit`: Stream data at a slow, but configurable rate to stall bots and pollute AI training.
- `<ip_ranges...>`: An optional list of CIDR ranges or predefined range keys to match against the client's IP. Defaults to [`aws azurepubliccloud deepseek gcloud githubcopilot openai`](./plugin.go).
- `<custom message>`: A custom message to return when using the `custom` responder.
- `<url>`: The URI that the `redirect` responder would redirect to.
- `<path>`: Path to a file containing IP addresses/CIDR ranges (one per line) to block. The file is automatically monitored for changes.

For more information about the configuration, refer to the [configuration page](https://JasonLovesDoggo.github.io/caddy-defender/config/) on the website.

---

## **Quick Start**

The [documentation website](https://JasonLovesDoggo.github.io/caddy-defender/) has info that includes the configurations of the plugin, code examples, and more.

For a quick start, follow the [Getting Started](https://JasonLovesDoggo.github.io/caddy-defender/intro/) guide to protect your server using the _Caddy Defender Plugin_.

---

## For examples, check out [docs/examples.md](docs/examples.md)

---

## **Embedded IP Ranges**

The plugin includes predefined IP ranges for popular AI services. These ranges are embedded in the binary and can be used without additional configuration.

|                               Service                                |                     Key                     |                     IP Ranges                      |
| :------------------------------------------------------------------: | :-----------------------------------------: | :------------------------------------------------: |
|                            Alibaba Cloud                             |                   aliyun                    |       [aliyun.go](ranges/fetchers/aliyun.go)       |
|                                 VPNs                                 |                     vpn                     |          [vpn.go](ranges/fetchers/vpn.go)          |
|                                 AWS                                  |                     aws                     |        [aws.go](ranges/fetchers/aws/aws.go)        |
|                              AWS Region                              | aws-us-east-1, aws-us-west-1, aws-eu-west-1 | [aws_region.go](ranges/fetchers/aws/aws_region.go) |
|                               DeepSeek                               |                  deepseek                   |     [deepseek.go](ranges/fetchers/deepseek.go)     |
|                            GitHub Copilot                            |                githubcopilot                |       [github.go](ranges/fetchers/github.go)       |
|                        Google Cloud Platform                         |                   gcloud                    |       [gcloud.go](ranges/fetchers/gcloud.go)       |
|                     Oracle Cloud Infrastructure                      |                     oci                     |       [oracle.go](ranges/fetchers/oracle.go)       |
|                           Microsoft Azure                            |              azurepubliccloud               |        [azure.go](ranges/fetchers/azure.go)        |
|                                OpenAI                                |                   openai                    |       [openai.go](ranges/fetchers/openai.go)       |
|                               Mistral                                |                   mistral                   |      [mistral.go](ranges/fetchers/mistral.go)      |
|                                Vultr                                 |                    vultr                    |        [vultr.go](ranges/fetchers/vultr.go)        |
|                              Cloudflare                              |                 cloudflare                  |   [cloudflare.go](ranges/fetchers/cloudflare.go)   |
|                            Digital Ocean                             |                digitalocean                 | [digitalocean.go](ranges/fetchers/digitalocean.go) |
|                                Linode                                |                   linode                    |       [linode.go](ranges/fetchers/linode.go)       |
| [Private](https://caddyserver.com/docs/caddyfile/matchers#remote-ip) |                   private                   |      [private.go](ranges/fetchers/private.go)      |
|                           All IP addresses                           |                     all                     |          [all.go](ranges/fetchers/all.go)          |

## Disabled by default (require manual inclusion at build time)

|             Service             | Key |            IP Ranges             |
| :-----------------------------: | :-: | :------------------------------: |
|         Tor Exit Nodes          | tor | [tor.go](ranges/fetchers/tor.go) |
| ASN (Autonomous System Numbers) | asn | [asn.go](ranges/fetchers/asn.go) |

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
