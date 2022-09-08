local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Check whether this port is http like service.
]]



author = "Li JieJie"

categories = {"discovery", "safe"}

portrule = function(host, port)
  return true
end

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
  local request_type = "HEAD"
  local status = false
  local result

  result = http.get(host, port, path)

  if not (result and result.status) then
    return fail("Header request failed")
  end

  table.insert(result.rawheader, "(Request type: " .. request_type .. ")")

  return stdnse.format_output(true, result.rawheader)
end
