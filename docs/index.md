# **Caddy Defender Plugin**

The **Caddy Defender** plugin is a middleware for Caddy that allows you to block or manipulate requests based on the client's IP address. It is particularly useful for preventing unwanted traffic or polluting AI training data by returning garbage responses.

---

## **Features**

- **IP Range Filtering**: Block or manipulate requests from specific IP ranges.
- **Embedded IP Ranges**: Predefined IP ranges for popular AI services (e.g., OpenAI, DeepSeek, GitHub Copilot).
- **Custom IP Ranges**: Add your own IP ranges via Caddyfile configuration.
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

For installation, please see the [installation page](installation.md).

## **Configuration**

To get started quickly, check the [Getting Started page](intro.md).

For specific information about configurations, see the [configurations page](config.md).

---

## **Contributing**

We welcome contributions! To get started, see the [CONTRIBUTING page](CONTRIBUTING.md).

---

## **License**

This project is licensed under the **MIT License**. See the [LICENSE](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/LICENSE) file for details.

---

## **Acknowledgments**

- [The inspiration for this project](https://www.reddit.com/r/selfhosted/comments/1i154h7/comment/m73pj9t/).
- [bart](https://github.com/gaissmai/bart) - [Karl Gaissmaier](https://github.com/gaissmai)'s efficient routing table implementation (Balanced ART adaptation) enabling our high-performance IP matching
- Built with ❤️ using [Caddy](https://caddyserver.com).

## **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=JasonLovesDoggo/caddy-defender&type=Date)](https://star-history.com/#JasonLovesDoggo/caddy-defender&Date)
