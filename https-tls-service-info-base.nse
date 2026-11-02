local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Establishes a TLS connection to an HTTPS service
and reports whether the connection was successful.
]]

author = "David Fifield"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port, "ssl")

    if not status then
        socket:close()
        return "TLS connection failed: " .. (err or "unknown error")
    end

    socket:close()

    return "TLS connection established successfully"
end
