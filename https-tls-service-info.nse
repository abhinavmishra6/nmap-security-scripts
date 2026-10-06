description = [[
HTTPS/TLS Service Information

Connects to an HTTPS/TLS service and displays basic TLS
connection and certificate information.

Base:
Establishes a TLS connection to TCP port 443.

Enhancement 1:
Measures TLS connection establishment time.

Enhancement 2:
Retrieves and displays TLS certificate information.
]]

author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local stdnse = require "stdnse"


--------------------------------------------------
-- PORT RULE
-- Run against open TCP port 443.
--------------------------------------------------

portrule = function(host, port)
    return port.protocol == "tcp" and
           port.state == "open" and
           port.number == 443
end


--------------------------------------------------
-- FORMAT CERTIFICATE DATE
--------------------------------------------------

local function format_date(date)

    if not date then
        return "Unknown"
    end

    return string.format(
        "%04d-%02d-%02d %02d:%02d:%02d",
        date.year,
        date.month,
        date.day,
        date.hour,
        date.min,
        date.sec
    )
end


--------------------------------------------------
-- MAIN ACTION
--------------------------------------------------

action = function(host, port)

    local output = {}

    output[#output + 1] =
        "HTTPS/TLS Service Information"


    --------------------------------------------------
    -- BASE FUNCTIONALITY
    -- Establish a TLS connection.
    --------------------------------------------------

    local socket = nmap.new_socket()

    socket:set_timeout(5000)

    local status, err =
        socket:connect(host, port, "ssl")

    if not status then

        socket:close()

        return "TLS connection failed: " ..
               (err or "unknown error")
    end

    output[#output + 1] =
        "Status: TLS connection established"


    --------------------------------------------------
    -- ENHANCEMENT 1
    -- Measure TLS connection establishment time.
    --------------------------------------------------

    socket:close()

    socket = nmap.new_socket()

    socket:set_timeout(5000)

    local start_time =
        nmap.clock_ms()

    local timed_status, timed_error =
        socket:connect(host, port, "ssl")

    local end_time =
        nmap.clock_ms()

    if not timed_status then

        socket:close()

        return "TLS connection established\n" ..
               "TLS timing failed: " ..
               (timed_error or "unknown error")
    end

    local tls_time =
        end_time - start_time

    output[#output + 1] =
        string.format(
            "TLS connection time: %d ms",
            tls_time
        )


    --------------------------------------------------
    -- ENHANCEMENT 2
    -- Retrieve TLS certificate information.
    --------------------------------------------------

    local certificate =
        socket:get_ssl_certificate()

    if certificate then

        --------------------------------------------------
        -- Certificate Common Name
        --------------------------------------------------

        if certificate.subject and
           certificate.subject.commonName then

            output[#output + 1] =
                "Certificate Common Name: " ..
                certificate.subject.commonName
        end


        --------------------------------------------------
        -- Certificate Issuer
        --------------------------------------------------

        if certificate.issuer and
           certificate.issuer.commonName then

            output[#output + 1] =
                "Certificate Issuer: " ..
                certificate.issuer.commonName
        end


        --------------------------------------------------
        -- Public Key Information
        --------------------------------------------------

        if certificate.pubkey then

            if certificate.pubkey.type then

                output[#output + 1] =
                    "Public Key Type: " ..
                    certificate.pubkey.type
            end

            if certificate.pubkey.bits then

                output[#output + 1] =
                    "Public Key Bits: " ..
                    certificate.pubkey.bits
            end
        end


        --------------------------------------------------
        -- Certificate Validity
        --------------------------------------------------

        if certificate.validity then

            if certificate.validity.notBefore then

                output[#output + 1] =
                    "Valid From: " ..
                    format_date(
                        certificate.validity.notBefore
                    )
            end

            if certificate.validity.notAfter then

                output[#output + 1] =
                    "Valid Until: " ..
                    format_date(
                        certificate.validity.notAfter
                    )
            end
        end

    else

        output[#output + 1] =
            "Certificate: Not retrieved"
    end


    --------------------------------------------------
    -- CLOSE CONNECTION
    --------------------------------------------------

    socket:close()


    --------------------------------------------------
    -- RETURN RESULTS
    --------------------------------------------------

    return stdnse.format_output(
        true,
        output
    )
end
