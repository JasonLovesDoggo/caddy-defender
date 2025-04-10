# **Contributing to Caddy Defender**

We welcome contributions to enhance Caddy Defender's capabilities! This guide outlines how to add new functionality through IP range sources or response handlers.

---

## **Adding New IP Range Sources**

### **Overview**

To block new IP ranges, you can create fetchers for different services or networks. These can be either:

- **Static ranges**: Predefined lists of IPs/CIDRs
- **Dynamic sources**: API-driven updates from service providers

### **Implementation Steps**

1. **Create a new fetcher**

   - Make a new file in `ranges/fetchers`
   - Implement the core interface with:
     - Service name and description
     - Range fetching logic
     - Error handling

2. **Register your fetcher**  
   Add your new fetcher to the main registry list

3. **Rebuild and test**  
   Use standard build tools to compile and verify your changes

4. **Update documentation**  
   Add your source to the predefined ranges list in documentation

---

## **Creating New Response Handlers**

### **Overview**

Response handlers determine how Caddy Defender interacts with matched requests. Common patterns include:

- Blocking requests
- Returning custom content
- Triggering security workflows

### **Implementation Steps**

1. **Create response handler**

   - Make a new file in `responders`
   - Implement the core response interface
   - Include any configuration parameters

2. **Register handler type**  
   Add your handler to the configuration parser

3. **Add validation**  
   Implement sanity checks for required parameters

4. **Update documentation**  
   Document your handler in:
   - Caddyfile syntax examples
   - JSON configuration reference
   - Responder type matrix

---

## **General Contribution Guidelines**

1. **Testing**  
   Include unit tests for new features using the standard Go testing framework

2. **Documentation**  
   Keep both developer and user documentation updated

3. **Backwards Compatibility**  
   Maintain existing functionality unless deprecating features

4. **Code Style**  
   Follow existing patterns and Go community standards

5. **Security Considerations**  
   Highlight any security implications in pull requests

---

## **Getting Started**

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add/update tests
5. Update documentation
6. Submit a pull request

For complex changes, please open an issue first to discuss the implementation approach.

---

## **Need Help?**

Reach out through:

- GitHub Issues
- Email: caddydefender@jasoncameron.dev

We appreciate your contributions to making Caddy Defender more powerful and flexible!
