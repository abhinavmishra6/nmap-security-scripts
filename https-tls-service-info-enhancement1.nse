local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Establishes a TLS connection to an HTTPS service
and measures the TLS connection establishment time.
]]

author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local start_ms = nmap.clock_ms()

    local status, err = socket:connect(host, port, "ssl")

    local elapsed_ms = nmap.clock_ms() - start_ms

    if not status then
        socket:close()
        return "TLS connection failed: " .. (err or "unknown error")
    end

    socket:close()

    local output = {}

    output[#output + 1] =
        "TLS connection established successfully"

    output[#output + 1] =
        string.format(
            "TLS connection establishment time: %.2f ms",
            elapsed_ms
        )

    return table.concat(output, "\n")
end
