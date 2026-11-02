-- Enhancement 2: Adds TCP banner timing and banner byte analysis.
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local U = require "lpeg-utility"

description = [[
A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.

The banner will be truncated to fit into a single line, but an extra line may be printed for every
increase in the level of verbosity requested on the command line.
]]

---
-- @output
-- 21/tcp open  ftp
-- |_ banner: 220 FTP version 1.0\x0D\x0A
-- @arg banner.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @arg banner.timeout How long to wait for a banner. Default: 5s

author = "Abhinav Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg then
  if portarg == "common" then
    portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
  end
  -- ensure TCP
  portarg = portarg:gsub("^[T:]*", "T:")
  portrule = shortport.port_range(portarg)
else
  portrule = function(host, port) return port.protocol == "tcp" end
end

---
-- Grabs a banner and outputs it nicely formatted.
action = function(host, port)
  -- Measure the complete banner-retrieval operation, including any wait.
  local start_ms = nmap.clock_ms()
  local out = grab_banner(host, port)
  local elapsed_ms = nmap.clock_ms() - start_ms

  if type(out) ~= "string" or out == "" then
    return ("No banner received (retrieval time: %.2f ms)"):format(elapsed_ms)
  end

  local formatted = output(out)
  local total_bytes = #out
  local printable_bytes = 0
  local nonprintable_bytes = 0

  for i = 1, total_bytes do
    local byte = out:byte(i)
    if byte >= 32 and byte <= 126 then
      printable_bytes = printable_bytes + 1
    else
      nonprintable_bytes = nonprintable_bytes + 1
    end
  end

  local report = {
    formatted,
    ("TCP banner retrieval time: %.2f ms"):format(elapsed_ms),
    ("Banner length: %d bytes"):format(total_bytes),
    ("Printable bytes: %d"):format(printable_bytes),
    ("Non-printable bytes: %d"):format(nonprintable_bytes)
  }

  return table.concat(report, "\n")
end

---
-- Connects to the target on the given port and returns any data issued by a listening service.
-- @param host Host Table.
-- @param port Port Table.
-- @return String or nil if data was not received.
function grab_banner(host, port)
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    local response = U.get_response(port.version.service_fp, "NULL")
    if response then
      return response:match("^%s*(.-)%s*$")
    end
  end

  local opts = {}
  opts.timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  opts.timeout = (opts.timeout or 5) * 1000

  local status, response = comm.get_banner(host, port, opts)

  if not status then
    local errlvl = { ["EOF"]=3, ["TIMEOUT"]=3, ["ERROR"]=2 }
    stdnse.debug(errlvl[response] or 1,
      "failed for %s on %s port %s. Message: %s",
      host.ip, port.protocol, port.number, response or "No Message.")
    return nil
  end

  return response:match("^%s*(.-)%s*$")
end

---
-- Formats the banner for printing to the port script result.
-- Non-printable characters are hex encoded and the banner is truncated.
function output(out)
  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75
  local fline_offset = 5

  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len - 1 - filename:len() - fline_offset
  else
    fline_len = 0
  end

  local sline_len = line_len - 1 - (fline_offset-2)

  local total_out_chars
  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output()*sline_len)
  else
    total_out_chars = (1+extra_output())*sline_len
  end

  out = replace_nonprint(out, 1+total_out_chars)

  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if (out:sub(-4,-1)):match("\\x%x%x") then
        out = out:sub(1,-5)
      else
        out = out:sub(1,-2)
      end
    end
    out = ("%s..."):format(out:sub(1,total_out_chars-3))
  end

  local ptr = fline_len
  local t = {}
  while true do
    if out:len() >= ptr then
      t[#t+1] = (ptr > 0 and out:sub(1,ptr)) or " "
      out = out:sub(ptr+1,-1)
      ptr = sline_len
    else
      t[#t+1] = out
      break
    end
  end

  return table.concat(t, "\n")
end

---
-- Replaces non-printable ASCII characters with hexadecimal equivalents.
function replace_nonprint(s, len)
  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format(
        ("0%s"):format((stdnse.tohex(c:byte())):upper()):sub(-2,-1))
      count = count + 4
    else
      t[#t+1] = c
      count = count + 1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)
end

---
-- Returns the number of additional output lines requested with verbosity.
function extra_output()
  return (nmap.verbosity()-nmap.debugging()>0
    and nmap.verbosity()-nmap.debugging()) or 0
end
