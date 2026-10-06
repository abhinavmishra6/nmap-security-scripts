description = [[
TCP Service Information

Connects to open TCP services and displays service information
detected by Nmap. The script also measures TCP connection time
and attempts to retrieve an initial service banner.
]]

author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local stdnse = require "stdnse"


-- Check whether the target port is an open TCP port.
portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end


-- Clean unwanted characters from a received banner.
local function clean_banner(data)

    if not data then
        return nil
    end

    data = data:gsub("[%c]", " ")
    data = data:gsub("%s+", " ")
    data = data:gsub("^%s+", "")
    data = data:gsub("%s+$", "")

    -- Keep the NSE output short and readable.
    if #data > 120 then
        data = data:sub(1, 120) .. "..."
    end

    return data
end


-- Get service information detected by Nmap.
local function get_service_information(port)

    local output = {}

    if port.service then
        output[#output + 1] =
            "Service: " .. port.service
    end

    if port.version then

        if port.version.product then
            output[#output + 1] =
                "Product: " .. port.version.product
        end

        if port.version.version then
            output[#output + 1] =
                "Version: " .. port.version.version
        end

        if port.version.extrainfo then
            output[#output + 1] =
                "Extra information: " ..
                port.version.extrainfo
        end
    end

    return output
end


action = function(host, port)

    local socket = nmap.new_socket()

    -- Set a three-second timeout for the TCP operation.
    socket:set_timeout(3000)

    local output = {}

    --------------------------------------------------
    -- BASE FUNCTIONALITY
    -- Establish a TCP connection to the open port.
    --------------------------------------------------

    output[#output + 1] = "TCP Service Information"

    local status, err = socket:connect(host, port)

    if not status then
        socket:close()

        return "Connection failed: " ..
               (err or "unknown error")
    end

    output[#output + 1] = "Status: Connected"


    --------------------------------------------------
    -- ENHANCEMENT 1
    -- Measure TCP connection establishment time.
    --------------------------------------------------

    -- Reconnect so that the timing measures the
    -- TCP connection establishment itself.

    socket:close()

    socket = nmap.new_socket()
    socket:set_timeout(3000)

    local start_time = nmap.clock_ms()

    local reconnect_status, reconnect_error =
        socket:connect(host, port)

    local end_time = nmap.clock_ms()

    if not reconnect_status then
        socket:close()

        return "TCP connection successful\n" ..
               "Timing connection failed: " ..
               (reconnect_error or "unknown error")
    end

    local connection_time =
        end_time - start_time

    output[#output + 1] =
        string.format(
            "Connection time: %d ms",
            connection_time
        )


    --------------------------------------------------
    -- BASE SERVICE INFORMATION
    -- Display information already detected by Nmap.
    --------------------------------------------------

    local service_information =
        get_service_information(port)

    for _, information in
        ipairs(service_information) do

        output[#output + 1] = information
    end


    --------------------------------------------------
    -- ENHANCEMENT 2
    -- Attempt to retrieve a service banner.
    --------------------------------------------------

    local banner_status, banner =
        socket:receive_lines(1)

    if banner_status and banner then

        banner = clean_banner(banner)

        if banner and #banner > 0 then

            output[#output + 1] =
                "Banner: " .. banner

        else

            output[#output + 1] =
                "Banner: Empty response"
        end

    else

        output[#output + 1] =
            "Banner: Not provided"
    end


    socket:close()

    return stdnse.format_output(
        true,
        output
    )
end
