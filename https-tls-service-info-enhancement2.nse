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

local function format_date(date)
    if not date then return "Unknown" end
    return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        date.year or 0, date.month or 0, date.day or 0,
        date.hour or 0, date.min or 0, date.sec or 0)
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

    -- Enhancement 2: retrieve TLS certificate information.
    local certificate = socket:get_ssl_certificate()
    if certificate then
        if certificate.subject and certificate.subject.commonName then
            output[#output + 1] =
                "Certificate Common Name: " .. certificate.subject.commonName
        end
        if certificate.issuer and certificate.issuer.commonName then
            output[#output + 1] =
                "Certificate Issuer: " .. certificate.issuer.commonName
        end
        if certificate.pubkey then
            if certificate.pubkey.type then
                output[#output + 1] = "Public Key Type: " .. certificate.pubkey.type
            end
            if certificate.pubkey.bits then
                output[#output + 1] = "Public Key Bits: " .. certificate.pubkey.bits
            end
        end
        if certificate.validity then
            if certificate.validity.notBefore then
                output[#output + 1] =
                    "Valid From: " .. format_date(certificate.validity.notBefore)
            end
            if certificate.validity.notAfter then
                output[#output + 1] =
                    "Valid Until: " .. format_date(certificate.validity.notAfter)
            end
        end
    else
        output[#output + 1] = "Certificate: Not retrieved"
    end

    socket:close()
    return stdnse.format_output(true, output)
end
