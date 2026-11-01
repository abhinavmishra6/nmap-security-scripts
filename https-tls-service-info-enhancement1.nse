description = [[
HTTPS/TLS Service Information

Connects to an HTTPS/TLS service and displays TLS connection information.
]]
author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local stdnse = require "stdnse"

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and port.number == 443
end

action = function(host, port)
    local output = {"HTTPS/TLS Service Information"}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    -- Base: establish a TLS connection.
    local status, err = socket:connect(host, port, "ssl")
    if not status then
        socket:close()
        return "TLS connection failed: " .. (err or "unknown error")
    end
    output[#output + 1] = "Status: TLS connection established"
    socket:close()

    -- Enhancement 1: measure TLS connection establishment time.
    socket = nmap.new_socket()
    socket:set_timeout(5000)
    local start_time = nmap.clock_ms()
    local timed_status, timed_error = socket:connect(host, port, "ssl")
    local end_time = nmap.clock_ms()

    if not timed_status then
        socket:close()
        return "TLS connection established\nTLS timing failed: " ..
               (timed_error or "unknown error")
    end

    output[#output + 1] =
        string.format("TLS connection time: %d ms", end_time - start_time)

    socket:close()
    return stdnse.format_output(true, output)
end
