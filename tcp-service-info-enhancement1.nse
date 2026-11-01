description = [[
TCP Service Information

Connects to open TCP services and displays service information detected by Nmap.
]]
author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local stdnse = require "stdnse"

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end

local function get_service_information(port)
    local output = {}
    if port.service then
        output[#output + 1] = "Service: " .. port.service
    end
    if port.version then
        if port.version.product then
            output[#output + 1] = "Product: " .. port.version.product
        end
        if port.version.version then
            output[#output + 1] = "Version: " .. port.version.version
        end
        if port.version.extrainfo then
            output[#output + 1] = "Extra information: " .. port.version.extrainfo
        end
    end
    return output
end

action = function(host, port)
    local output = {"TCP Service Information"}
    local socket = nmap.new_socket()
    socket:set_timeout(3000)

    -- Base: establish a TCP connection.
    local status, err = socket:connect(host, port)
    if not status then
        socket:close()
        return "Connection failed: " .. (err or "unknown error")
    end
    output[#output + 1] = "Status: Connected"
    socket:close()

    -- Enhancement 1: measure TCP connection establishment time.
    socket = nmap.new_socket()
    socket:set_timeout(3000)
    local start_time = nmap.clock_ms()
    local reconnect_status, reconnect_error = socket:connect(host, port)
    local end_time = nmap.clock_ms()

    if not reconnect_status then
        socket:close()
        return "TCP connection successful\nTiming connection failed: " ..
               (reconnect_error or "unknown error")
    end

    output[#output + 1] =
        string.format("Connection time: %d ms", end_time - start_time)

    for _, item in ipairs(get_service_information(port)) do
        output[#output + 1] = item
    end

    socket:close()
    return stdnse.format_output(true, output)
end
