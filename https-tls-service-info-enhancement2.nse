
local sslcert = require "sslcert"
local shortport = require "shortport"

description = [[
Retrieves HTTPS certificate information and analyzes
certificate expiry and remaining validity days.
]]

author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

-- Convert a calendar date into a day number.
-- This avoids local timezone conversion problems.
local function days_from_date(y, m, d)

    y = y - (m <= 2 and 1 or 0)

    local era = math.floor(y / 400)
    local yoe = y - era * 400

    local mp = m + (m > 2 and -3 or 9)
    local doy = math.floor((153 * mp + 2) / 5) + d - 1

    local doe = yoe * 365
        + math.floor(yoe / 4)
        - math.floor(yoe / 100)
        + doy

    return era * 146097 + doe
end

-- Format certificate date.
local function format_date(date)

    if type(date) == "table" then
        return string.format(
            "%04d-%02d-%02d %02d:%02d:%02d",
            date.year, date.month, date.day,
            date.hour or 0, date.min or 0, date.sec or 0
        )

    elseif type(date) == "number" then
        return os.date("!%Y-%m-%d %H:%M:%S", date)

    else
        return tostring(date)
    end
end

-- Calculate remaining validity in calendar days.
local function remaining_days(date)

    local today = os.date("!*t")

    local current_day = days_from_date(
        today.year, today.month, today.day
    )

    if type(date) == "table" then

        local expiry_day = days_from_date(
            date.year, date.month, date.day
        )

        return expiry_day - current_day

    elseif type(date) == "number" then

        return math.floor(date / 86400) - current_day
    end

    return nil
end

action = function(host, port)

    local status, cert = sslcert.getCertificate(host, port)

    if not status or not cert then
        return "Unable to retrieve TLS certificate"
    end

    local output = {}

    output[#output + 1] =
        "TLS certificate retrieved successfully"

    -- Certificate subject
    if cert.subject and cert.subject.commonName then
        output[#output + 1] =
            "Certificate subject: " .. cert.subject.commonName
    end

    -- Certificate issuer
    if cert.issuer and cert.issuer.commonName then
        output[#output + 1] =
            "Certificate issuer: " .. cert.issuer.commonName
    end

    -- Public key information
    if cert.pubkey then

        if cert.pubkey.type then
            output[#output + 1] =
                "Public key type: " .. cert.pubkey.type
        end

        if cert.pubkey.bits then
            output[#output + 1] =
                "Public key size: " .. cert.pubkey.bits .. " bits"
        end
    end

    -- Certificate validity
    local not_before = cert.validity and cert.validity.notBefore
    local not_after = cert.validity and cert.validity.notAfter

    if not_before then
        output[#output + 1] =
            "Valid from: " .. format_date(not_before)
    end

    if not_after then

        output[#output + 1] =
            "Valid until: " .. format_date(not_after)

        local days = remaining_days(not_after)

        if days then

            if days < 0 then

                output[#output + 1] =
                    "Certificate status: EXPIRED"

                output[#output + 1] =
                    "Expired " .. math.abs(days) .. " days ago"

            elseif days <= 30 then

                output[#output + 1] =
                    "Certificate status: EXPIRING SOON"

                output[#output + 1] =
                    "Remaining validity: " .. days .. " days"

            else

                output[#output + 1] =
                    "Certificate status: VALID"

                output[#output + 1] =
                    "Remaining validity: " .. days .. " days"
            end

        else

            output[#output + 1] =
                "Expiry analysis unavailable: unsupported date format"
        end
    end

    return table.concat(output, "\n")
end

